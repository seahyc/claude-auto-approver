#!/usr/bin/env python3
"""Comprehensive tests for scoped rules in approver.py (bashlex-based)."""

import os
import tempfile
import unittest

from approver import (
    _glob_dir_prefix,
    _parse_commands,
    _strip_comments,
    _strip_quoted_contents,
    _word_is_unsafe,
    build_allowed_dirs,
    check_docker_scoped,
    check_scoped_rules,
    decide,
    extract_path_args,
    find_git_root,
    resolve_and_check_paths,
)


class TestGlobDirPrefix(unittest.TestCase):
    """Tests for extracting the directory prefix from glob paths."""

    def test_star_at_start(self):
        self.assertEqual(_glob_dir_prefix("*.txt"), ".")

    def test_star_in_subdir(self):
        self.assertEqual(_glob_dir_prefix("build/*.o"), "build")

    def test_absolute_path(self):
        self.assertEqual(_glob_dir_prefix("/tmp/*.txt"), "/tmp")

    def test_root_glob(self):
        self.assertEqual(_glob_dir_prefix("/*.txt"), "/")

    def test_nested_dirs(self):
        self.assertEqual(_glob_dir_prefix("a/b/c*.txt"), "a/b")

    def test_recursive_glob(self):
        self.assertEqual(_glob_dir_prefix("build/**/*.o"), "build")

    def test_question_mark(self):
        self.assertEqual(_glob_dir_prefix("file?.txt"), ".")

    def test_brackets(self):
        self.assertEqual(_glob_dir_prefix("file[0-9].txt"), ".")

    def test_braces(self):
        self.assertEqual(_glob_dir_prefix("{a,b}.txt"), ".")

    def test_glob_in_middle_of_filename(self):
        self.assertEqual(
            _glob_dir_prefix("transfers/transfers_*.parquet"), "transfers"
        )

    def test_no_glob_returns_path(self):
        self.assertEqual(_glob_dir_prefix("plain/file.txt"), "plain/file.txt")

    def test_deep_nested_glob(self):
        self.assertEqual(
            _glob_dir_prefix("/home/user/project/src/build/*.o"),
            "/home/user/project/src/build",
        )


class TestParseCommands(unittest.TestCase):
    """Tests for bashlex-based command parsing."""

    def test_simple_command(self):
        cmds = _parse_commands("rm file.txt")
        self.assertEqual(len(cmds), 1)
        self.assertEqual(cmds[0]["name"], "rm")
        self.assertEqual(cmds[0]["path_args"], ["file.txt"])
        self.assertFalse(cmds[0]["is_unsafe"])

    def test_command_with_flags(self):
        cmds = _parse_commands("rm -rf dir/")
        self.assertEqual(cmds[0]["name"], "rm")
        self.assertEqual(cmds[0]["path_args"], ["dir/"])
        self.assertEqual(cmds[0]["raw_words"], ["rm", "-rf", "dir/"])

    def test_and_chain(self):
        cmds = _parse_commands("rm file.txt && yarn build")
        self.assertEqual(len(cmds), 2)
        self.assertEqual(cmds[0]["name"], "rm")
        self.assertEqual(cmds[1]["name"], "yarn")

    def test_or_chain(self):
        cmds = _parse_commands("rm file.txt || echo failed")
        self.assertEqual(len(cmds), 2)
        self.assertEqual(cmds[0]["name"], "rm")

    def test_semicolon_chain(self):
        cmds = _parse_commands("rm file.txt ; echo done")
        self.assertEqual(len(cmds), 2)
        self.assertEqual(cmds[0]["name"], "rm")

    def test_pipeline(self):
        cmds = _parse_commands("yarn build 2>&1 | tail -5")
        self.assertEqual(len(cmds), 2)
        self.assertEqual(cmds[0]["name"], "yarn")
        self.assertEqual(cmds[1]["name"], "tail")

    def test_cd_tracks_target(self):
        cmds = _parse_commands("cd /tmp && rm file.txt")
        rm_cmd = [c for c in cmds if c["name"] == "rm"][0]
        self.assertEqual(rm_cmd["cd_target"], "/tmp")

    def test_cd_relative_target(self):
        cmds = _parse_commands("cd subdir && rm file.txt")
        rm_cmd = [c for c in cmds if c["name"] == "rm"][0]
        self.assertEqual(rm_cmd["cd_target"], "subdir")

    def test_no_cd_target_is_none(self):
        cmds = _parse_commands("echo hi && rm file.txt")
        rm_cmd = [c for c in cmds if c["name"] == "rm"][0]
        self.assertIsNone(rm_cmd["cd_target"])

    def test_cd_no_args_is_unknown(self):
        from approver import _UNKNOWN_CD
        cmds = _parse_commands("cd && rm file.txt")
        rm_cmd = [c for c in cmds if c["name"] == "rm"][0]
        self.assertIs(rm_cmd["cd_target"], _UNKNOWN_CD)

    def test_chained_cd_relative(self):
        """cd a && cd b → combined as a/b."""
        cmds = _parse_commands("cd a && cd b && rm file.txt")
        rm_cmd = [c for c in cmds if c["name"] == "rm"][0]
        self.assertEqual(rm_cmd["cd_target"], "a/b")

    def test_chained_cd_absolute_overrides(self):
        """cd a && cd /tmp → absolute overrides previous."""
        cmds = _parse_commands("cd a && cd /tmp && rm file.txt")
        rm_cmd = [c for c in cmds if c["name"] == "rm"][0]
        self.assertEqual(rm_cmd["cd_target"], "/tmp")

    def test_chained_cd_three_deep(self):
        cmds = _parse_commands("cd a && cd b && cd c && rm file.txt")
        rm_cmd = [c for c in cmds if c["name"] == "rm"][0]
        self.assertEqual(rm_cmd["cd_target"], "a/b/c")

    def test_chained_cd_unknown_stays_unknown(self):
        """cd $VAR && cd subdir → stays unknown."""
        from approver import _UNKNOWN_CD
        cmds = _parse_commands("cd $HOME && cd subdir && rm file.txt")
        rm_cmd = [c for c in cmds if c["name"] == "rm"][0]
        self.assertIs(rm_cmd["cd_target"], _UNKNOWN_CD)

    def test_sudo_detected(self):
        cmds = _parse_commands("sudo rm file.txt")
        self.assertEqual(len(cmds), 1)
        self.assertTrue(cmds[0]["is_privileged"])
        self.assertEqual(cmds[0]["name"], "sudo")
        self.assertIn("rm", cmds[0]["raw_words"])

    def test_doas_detected(self):
        cmds = _parse_commands("doas rm file.txt")
        self.assertTrue(cmds[0]["is_privileged"])

    def test_redirect_excluded(self):
        cmds = _parse_commands("rm file.txt 2>&1")
        self.assertEqual(cmds[0]["path_args"], ["file.txt"])
        self.assertFalse(cmds[0]["is_unsafe"])

    def test_redirect_to_devnull(self):
        cmds = _parse_commands("rm file.txt 2>/dev/null")
        self.assertEqual(cmds[0]["path_args"], ["file.txt"])

    def test_redirect_stdout(self):
        cmds = _parse_commands("rm file.txt >/dev/null")
        self.assertEqual(cmds[0]["path_args"], ["file.txt"])

    def test_command_substitution_unsafe(self):
        cmds = _parse_commands("rm $(find . -name x)")
        self.assertTrue(cmds[0]["is_unsafe"])

    def test_backtick_substitution_unsafe(self):
        cmds = _parse_commands("rm `cat list`")
        self.assertTrue(cmds[0]["is_unsafe"])

    def test_parameter_expansion_unsafe(self):
        cmds = _parse_commands("rm $FILE")
        self.assertTrue(cmds[0]["is_unsafe"])

    def test_glob_star_resolves_dir(self):
        cmds = _parse_commands("rm *.txt")
        self.assertFalse(cmds[0]["is_unsafe"])
        self.assertEqual(cmds[0]["path_args"], ["."])

    def test_glob_question_resolves_dir(self):
        cmds = _parse_commands("rm file?.txt")
        self.assertFalse(cmds[0]["is_unsafe"])
        self.assertEqual(cmds[0]["path_args"], ["."])

    def test_glob_brackets_resolves_dir(self):
        cmds = _parse_commands("rm file[0-9].txt")
        self.assertFalse(cmds[0]["is_unsafe"])
        self.assertEqual(cmds[0]["path_args"], ["."])

    def test_glob_in_subdir_resolves_dir(self):
        cmds = _parse_commands("rm build/*.o")
        self.assertFalse(cmds[0]["is_unsafe"])
        self.assertEqual(cmds[0]["path_args"], ["build"])

    def test_glob_absolute_path_resolves_dir(self):
        cmds = _parse_commands("rm /tmp/*.txt")
        self.assertEqual(cmds[0]["path_args"], ["/tmp"])

    def test_glob_nested_resolves_dir(self):
        cmds = _parse_commands("rm a/b/c*.txt")
        self.assertEqual(cmds[0]["path_args"], ["a/b"])

    def test_glob_recursive_resolves_dir(self):
        cmds = _parse_commands("rm build/**/*.o")
        self.assertEqual(cmds[0]["path_args"], ["build"])

    def test_tilde_is_safe(self):
        cmds = _parse_commands("rm ~/Desktop/file.txt")
        self.assertFalse(cmds[0]["is_unsafe"])
        self.assertEqual(cmds[0]["path_args"], ["~/Desktop/file.txt"])

    def test_quoted_path_unquoted(self):
        cmds = _parse_commands('rm "path with spaces/file.txt"')
        self.assertEqual(cmds[0]["path_args"], ["path with spaces/file.txt"])
        self.assertFalse(cmds[0]["is_unsafe"])

    def test_single_quoted_path(self):
        cmds = _parse_commands("rm 'my file.txt'")
        self.assertEqual(cmds[0]["path_args"], ["my file.txt"])

    def test_double_dash(self):
        cmds = _parse_commands("rm -- -weird-file")
        self.assertEqual(cmds[0]["path_args"], ["-weird-file"])

    def test_double_dash_with_flags_before(self):
        cmds = _parse_commands("rm -f -- -file1 -file2")
        self.assertEqual(cmds[0]["path_args"], ["-file1", "-file2"])

    def test_no_args_returns_none_paths(self):
        cmds = _parse_commands("rm ")
        # bashlex may or may not parse bare "rm " — either None or empty args
        if cmds is not None and len(cmds) > 0:
            self.assertIsNone(cmds[0]["path_args"])

    def test_only_flags_returns_none_paths(self):
        cmds = _parse_commands("rm -rf")
        self.assertIsNone(cmds[0]["path_args"])

    def test_complex_chain(self):
        cmd = "rm -f file.txt && . ~/.nvm/nvm.sh && nvm use 20 && yarn build 2>&1 | tail -5"
        cmds = _parse_commands(cmd)
        self.assertIsNotNone(cmds)
        self.assertTrue(len(cmds) >= 4)
        self.assertEqual(cmds[0]["name"], "rm")
        self.assertEqual(cmds[0]["path_args"], ["file.txt"])

    def test_parse_failure_returns_none(self):
        # Deliberately broken bash syntax
        result = _parse_commands("rm file <<<")
        self.assertIsNone(result)

    def test_mv_two_args(self):
        cmds = _parse_commands("mv old.py new.py")
        self.assertEqual(cmds[0]["path_args"], ["old.py", "new.py"])

    def test_multiple_files(self):
        cmds = _parse_commands("rm file1 file2 file3")
        self.assertEqual(cmds[0]["path_args"], ["file1", "file2", "file3"])

    def test_source_command(self):
        cmds = _parse_commands(". ~/.nvm/nvm.sh")
        self.assertEqual(cmds[0]["name"], ".")


class TestStripQuotedContents(unittest.TestCase):
    def test_double_quotes(self):
        self.assertEqual(
            _strip_quoted_contents('git commit -m "message with rm stuff"'),
            'git commit -m ""',
        )

    def test_single_quotes(self):
        self.assertEqual(
            _strip_quoted_contents("echo 'rm -rf /'"),
            "echo ''",
        )

    def test_no_quotes(self):
        self.assertEqual(
            _strip_quoted_contents("rm file.txt"),
            "rm file.txt",
        )

    def test_preserves_command_outside_quotes(self):
        self.assertEqual(
            _strip_quoted_contents('rm file && git commit -m "done"'),
            'rm file && git commit -m ""',
        )

    def test_multiple_quoted_strings(self):
        self.assertEqual(
            _strip_quoted_contents('echo "rm" && echo "mv"'),
            'echo "" && echo ""',
        )

    def test_empty_quotes_unchanged(self):
        self.assertEqual(
            _strip_quoted_contents('echo ""'),
            'echo ""',
        )


class TestStripComments(unittest.TestCase):
    def test_single_line_comment(self):
        self.assertEqual(
            _strip_comments("# The rm might have also removed the dir"),
            "",
        )

    def test_inline_comment(self):
        self.assertEqual(
            _strip_comments("ls -la  # list files with rm in comment"),
            "ls -la  ",
        )

    def test_no_comment(self):
        self.assertEqual(_strip_comments("rm file.txt"), "rm file.txt")

    def test_multiline_with_comments(self):
        text = "echo hello\n# rm is mentioned here\nls"
        self.assertEqual(_strip_comments(text), "echo hello\n\nls")

    def test_hash_after_quote_stripping(self):
        # After _strip_quoted_contents, "color #ff0000" becomes "",
        # so # inside quotes is already gone — no false strip.
        text = _strip_quoted_contents('echo "color #ff0000"')
        self.assertEqual(_strip_comments(text), 'echo ""')

    def test_shebang_stripped(self):
        # Shebangs are comments too — stripping them is fine for keyword matching
        self.assertEqual(_strip_comments("#!/bin/bash\nrm file"), "\nrm file")


class TestExtractPathArgs(unittest.TestCase):
    def test_simple_rm(self):
        self.assertEqual(extract_path_args("rm file.txt", "rm "), ["file.txt"])

    def test_rm_with_flags(self):
        self.assertEqual(extract_path_args("rm -rf dir/", "rm "), ["dir/"])

    def test_rm_multiple_files(self):
        self.assertEqual(
            extract_path_args("rm file1 file2 file3", "rm "),
            ["file1", "file2", "file3"],
        )

    def test_rm_with_multiple_flags(self):
        self.assertEqual(
            extract_path_args("rm -r -f --verbose dir/", "rm "),
            ["dir/"],
        )

    def test_double_dash_separator(self):
        self.assertEqual(
            extract_path_args("rm -- -weird-file", "rm "),
            ["-weird-file"],
        )

    def test_double_dash_with_flags_before(self):
        self.assertEqual(
            extract_path_args("rm -f -- -file1 -file2", "rm "),
            ["-file1", "-file2"],
        )

    def test_mv_two_args(self):
        self.assertEqual(
            extract_path_args("mv old.py new.py", "mv "),
            ["old.py", "new.py"],
        )

    def test_quoted_path_with_spaces(self):
        self.assertEqual(
            extract_path_args('rm "path with spaces/file.txt"', "rm "),
            ["path with spaces/file.txt"],
        )

    def test_single_quoted_path(self):
        self.assertEqual(
            extract_path_args("rm 'my file.txt'", "rm "),
            ["my file.txt"],
        )

    def test_sudo_prefix_returns_none(self):
        self.assertIsNone(extract_path_args("sudo rm file.txt", "rm "))

    def test_glob_returns_dir_prefix(self):
        self.assertEqual(extract_path_args("rm *.txt", "rm "), ["."])

    def test_dollar_returns_none(self):
        self.assertIsNone(extract_path_args("rm $(find . -name x)", "rm "))

    def test_rm_no_args(self):
        self.assertIsNone(extract_path_args("rm ", "rm "))

    def test_rm_only_flags(self):
        self.assertIsNone(extract_path_args("rm -rf", "rm "))

    def test_keyword_not_found(self):
        self.assertIsNone(extract_path_args("cp file1 file2", "rm "))

    def test_unbalanced_quotes(self):
        self.assertIsNone(extract_path_args('rm "unbalanced', "rm "))

    def test_absolute_path(self):
        self.assertEqual(
            extract_path_args("rm /tmp/file.txt", "rm "),
            ["/tmp/file.txt"],
        )

    def test_relative_dotdot_path(self):
        self.assertEqual(
            extract_path_args("rm ../other/file.txt", "rm "),
            ["../other/file.txt"],
        )

    def test_tilde_path(self):
        self.assertEqual(
            extract_path_args("rm ~/Desktop/file.txt", "rm "),
            ["~/Desktop/file.txt"],
        )

    def test_rmdir(self):
        self.assertEqual(
            extract_path_args("rmdir empty_dir", "rmdir"),
            ["empty_dir"],
        )

    def test_unlink(self):
        self.assertEqual(
            extract_path_args("unlink symlink_name", "unlink "),
            ["symlink_name"],
        )

    # --- compound command tests ---

    def test_rm_then_and_chain(self):
        self.assertEqual(
            extract_path_args("rm -f file.txt && yarn build", "rm "),
            ["file.txt"],
        )

    def test_rm_then_and_chain_with_redirects(self):
        self.assertEqual(
            extract_path_args(
                "rm -f file.txt && yarn build 2>&1 | tail -5", "rm "
            ),
            ["file.txt"],
        )

    def test_semicolon_chain_extracts_segment(self):
        self.assertEqual(
            extract_path_args("rm file.txt ; echo done", "rm "),
            ["file.txt"],
        )

    def test_pipe_chain_rm_not_in_pipe(self):
        # "rm file.txt | echo piped" — bashlex parses rm in a pipeline
        # rm is still a command with args, just piped
        self.assertEqual(
            extract_path_args("rm file.txt | echo piped", "rm "),
            ["file.txt"],
        )

    def test_cd_before_rm_returns_none(self):
        self.assertIsNone(
            extract_path_args("cd /tmp && rm file.txt", "rm ")
        )

    def test_glob_in_segment_returns_dir(self):
        self.assertEqual(
            extract_path_args("rm *.pyc && echo done", "rm "),
            ["."],
        )

    def test_glob_in_subdir_returns_dir(self):
        self.assertEqual(
            extract_path_args("rm build/*.o && echo done", "rm "),
            ["build"],
        )

    def test_dollar_in_segment_returns_none(self):
        self.assertIsNone(
            extract_path_args("rm $FILE && echo done", "rm ")
        )

    def test_real_world_rm_and_build(self):
        cmd = "rm -f /home/user/project/check.js && . ~/.nvm/nvm.sh && nvm use 20 && yarn run build 2>&1 | tail -5"
        self.assertEqual(
            extract_path_args(cmd, "rm "),
            ["/home/user/project/check.js"],
        )

    def test_doas_prefix_returns_none(self):
        self.assertIsNone(extract_path_args("doas rm file.txt", "rm "))

    def test_rm_with_2_redirect_stdout(self):
        self.assertEqual(
            extract_path_args("rm file.txt 2>&1", "rm "),
            ["file.txt"],
        )

    def test_rm_with_devnull_redirect(self):
        self.assertEqual(
            extract_path_args("rm file.txt 2>/dev/null", "rm "),
            ["file.txt"],
        )

    def test_rm_multiple_files_with_redirect(self):
        self.assertEqual(
            extract_path_args("rm file1.py file2.py file3.py 2>&1", "rm "),
            ["file1.py", "file2.py", "file3.py"],
        )

    def test_rm_redirect_then_chain(self):
        self.assertEqual(
            extract_path_args(
                "rm file.txt 2>&1 && echo done", "rm "
            ),
            ["file.txt"],
        )

    def test_real_world_whale_rm(self):
        cmd = (
            "rm /home/ubuntu/personal/WhaleWatch/ml/quick_eval.py "
            "/home/ubuntu/personal/WhaleWatch/ml/ml_evaluate.py "
            "/home/ubuntu/personal/WhaleWatch/ml/ml_scorer.py 2>&1 "
            '&& echo "Deleted files"'
        )
        result = extract_path_args(cmd, "rm ")
        self.assertEqual(result, [
            "/home/ubuntu/personal/WhaleWatch/ml/quick_eval.py",
            "/home/ubuntu/personal/WhaleWatch/ml/ml_evaluate.py",
            "/home/ubuntu/personal/WhaleWatch/ml/ml_scorer.py",
        ])

    def test_backtick_returns_none(self):
        self.assertIsNone(extract_path_args("rm `cat list`", "rm "))

    def test_parameter_expansion_returns_none(self):
        self.assertIsNone(extract_path_args("rm $FILE", "rm "))

    def test_sudo_in_chain_still_rejects(self):
        """sudo rm before a clean rm should still reject."""
        self.assertIsNone(
            extract_path_args("sudo rm secret && rm file.txt", "rm ")
        )

    def test_clean_rm_after_safe_chain(self):
        """Non-sudo chain with rm should work."""
        self.assertEqual(
            extract_path_args("echo hi && rm file.txt", "rm "),
            ["file.txt"],
        )


class TestResolveAndCheckPaths(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.project_dir = os.path.join(self.tmpdir, "project")
        os.makedirs(self.project_dir)
        self.allowed = [self.project_dir]

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_relative_path_in_project(self):
        ok, _ = resolve_and_check_paths(
            ["subdir/file.txt"], self.project_dir, self.allowed
        )
        self.assertTrue(ok)

    def test_absolute_path_in_project(self):
        inner = os.path.join(self.project_dir, "file.txt")
        ok, _ = resolve_and_check_paths([inner], self.project_dir, self.allowed)
        self.assertTrue(ok)

    def test_absolute_path_outside(self):
        ok, _ = resolve_and_check_paths(["/etc/passwd"], self.project_dir, self.allowed)
        self.assertFalse(ok)

    def test_dotdot_traversal_escaping(self):
        ok, _ = resolve_and_check_paths(
            ["../../etc/passwd"], self.project_dir, self.allowed
        )
        self.assertFalse(ok)

    def test_dotdot_staying_inside(self):
        subdir = os.path.join(self.project_dir, "subdir")
        os.makedirs(subdir)
        ok, _ = resolve_and_check_paths(
            ["subdir/../file.txt"], self.project_dir, self.allowed
        )
        self.assertTrue(ok)

    def test_symlink_escaping(self):
        outside_dir = os.path.join(self.tmpdir, "outside")
        os.makedirs(outside_dir)
        link_path = os.path.join(self.project_dir, "sneaky_link")
        os.symlink(outside_dir, link_path)

        ok, _ = resolve_and_check_paths(
            ["sneaky_link/secret.txt"], self.project_dir, self.allowed
        )
        self.assertFalse(ok)

    def test_symlink_staying_inside(self):
        sub1 = os.path.join(self.project_dir, "sub1")
        sub2 = os.path.join(self.project_dir, "sub2")
        os.makedirs(sub1)
        os.makedirs(sub2)
        link_path = os.path.join(sub1, "link_to_sub2")
        os.symlink(sub2, link_path)

        ok, _ = resolve_and_check_paths(
            ["sub1/link_to_sub2/file.txt"], self.project_dir, self.allowed
        )
        self.assertTrue(ok)

    def test_project_root_itself_rejected(self):
        ok, _ = resolve_and_check_paths(
            [self.project_dir], self.project_dir, self.allowed
        )
        self.assertFalse(ok)

    def test_tilde_expansion(self):
        ok, _ = resolve_and_check_paths(["~/file.txt"], self.project_dir, self.allowed)
        self.assertFalse(ok)

    def test_multiple_paths_all_inside(self):
        ok, _ = resolve_and_check_paths(
            ["a.txt", "b.txt", "sub/c.txt"], self.project_dir, self.allowed
        )
        self.assertTrue(ok)

    def test_multiple_paths_one_outside(self):
        ok, _ = resolve_and_check_paths(
            ["a.txt", "/etc/passwd", "b.txt"], self.project_dir, self.allowed
        )
        self.assertFalse(ok)

    def test_empty_allowed_dirs(self):
        ok, _ = resolve_and_check_paths(["file.txt"], self.project_dir, [])
        self.assertFalse(ok)

    def test_prefix_dir_not_confused(self):
        evil_dir = self.project_dir + "-evil"
        os.makedirs(evil_dir)
        evil_file = os.path.join(evil_dir, "payload.txt")
        ok, _ = resolve_and_check_paths(
            [evil_file], self.project_dir, self.allowed
        )
        self.assertFalse(ok)

    def test_multiple_allowed_dirs(self):
        extra = os.path.join(self.tmpdir, "extra")
        os.makedirs(extra)
        ok, _ = resolve_and_check_paths(
            [os.path.join(extra, "file.txt")],
            self.project_dir,
            [self.project_dir, extra],
        )
        self.assertTrue(ok)


class TestFindGitRoot(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_finds_git_root(self):
        git_dir = os.path.join(self.tmpdir, ".git")
        os.makedirs(git_dir)
        sub = os.path.join(self.tmpdir, "a", "b", "c")
        os.makedirs(sub)

        result = find_git_root(sub)
        self.assertEqual(result, os.path.realpath(self.tmpdir))

    def test_at_git_root(self):
        git_dir = os.path.join(self.tmpdir, ".git")
        os.makedirs(git_dir)

        result = find_git_root(self.tmpdir)
        self.assertEqual(result, os.path.realpath(self.tmpdir))

    def test_no_git_root(self):
        deep = os.path.join(self.tmpdir, "a", "b")
        os.makedirs(deep)
        result = find_git_root(deep)
        self.assertTrue(result is None or isinstance(result, str))

    def test_git_worktree_file(self):
        git_file = os.path.join(self.tmpdir, ".git")
        with open(git_file, "w") as f:
            f.write("gitdir: /some/other/path\n")
        sub = os.path.join(self.tmpdir, "src")
        os.makedirs(sub)

        result = find_git_root(sub)
        self.assertEqual(result, os.path.realpath(self.tmpdir))


class TestBuildAllowedDirs(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.project = os.path.join(self.tmpdir, "project")
        os.makedirs(self.project)
        os.makedirs(os.path.join(self.project, ".git"))

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_project_dir_detection(self):
        cwd = os.path.join(self.project, "src")
        os.makedirs(cwd)
        dirs = build_allowed_dirs(cwd, {"allow_project_dir": True})
        self.assertIn(os.path.realpath(self.project), dirs)

    def test_static_dirs(self):
        extra = os.path.join(self.tmpdir, "extra")
        os.makedirs(extra)
        dirs = build_allowed_dirs(
            self.project,
            {"allow_project_dir": False, "allowed_dirs": [extra]},
        )
        self.assertIn(os.path.realpath(extra), dirs)
        self.assertEqual(len(dirs), 1)

    def test_nonexistent_static_dir_skipped(self):
        dirs = build_allowed_dirs(
            self.project,
            {"allow_project_dir": False, "allowed_dirs": ["/nonexistent/dir"]},
        )
        self.assertEqual(dirs, [])

    def test_both_static_and_project(self):
        extra = os.path.join(self.tmpdir, "extra")
        os.makedirs(extra)
        dirs = build_allowed_dirs(
            self.project,
            {"allow_project_dir": True, "allowed_dirs": [extra]},
        )
        self.assertEqual(len(dirs), 2)


class TestCheckScopedRules(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.project = os.path.join(self.tmpdir, "project")
        os.makedirs(self.project)
        os.makedirs(os.path.join(self.project, ".git"))
        self.config = {
            "rules": {
                "safe_substrings": ["--rm"],
                "scoped": {
                    "keywords": ["rm ", "mv ", "rmdir", "unlink "],
                    "allow_project_dir": True,
                    "allowed_dirs": [],
                },
            }
        }

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_rm_in_project_approved(self):
        result = check_scoped_rules("rm build/temp.o", self.project, self.config)
        self.assertIsNotNone(result)
        self.assertEqual(result[0], "allow")
        self.assertIn("Scoped approve", result[1])

    def test_rm_absolute_outside_returns_none(self):
        result = check_scoped_rules("rm /etc/passwd", self.project, self.config)
        self.assertIsNone(result)

    def test_rm_dotdot_escape_returns_none(self):
        result = check_scoped_rules("rm ../../etc/passwd", self.project, self.config)
        self.assertIsNone(result)

    def test_metacharacter_returns_none(self):
        result = check_scoped_rules("rm *.pyc", self.project, self.config)
        self.assertIsNone(result)

    def test_command_substitution_returns_none(self):
        result = check_scoped_rules("rm $(cat list)", self.project, self.config)
        self.assertIsNone(result)

    def test_sudo_prefix_returns_none(self):
        result = check_scoped_rules("sudo rm file.txt", self.project, self.config)
        self.assertIsNone(result)

    def test_doas_prefix_returns_none(self):
        result = check_scoped_rules("doas rm file.txt", self.project, self.config)
        self.assertIsNone(result)

    def test_no_scoped_keywords_returns_none(self):
        config = {"rules": {"scoped": {"keywords": []}}}
        result = check_scoped_rules("rm file.txt", self.project, config)
        self.assertIsNone(result)

    def test_no_scoped_section_returns_none(self):
        config = {"rules": {}}
        result = check_scoped_rules("rm file.txt", self.project, config)
        self.assertIsNone(result)

    def test_unmatched_keyword_returns_none(self):
        result = check_scoped_rules("cp file1 file2", self.project, self.config)
        self.assertIsNone(result)

    def test_mv_both_in_project(self):
        result = check_scoped_rules("mv old.py new.py", self.project, self.config)
        self.assertIsNotNone(result)
        self.assertEqual(result[0], "allow")

    def test_mv_destination_outside(self):
        result = check_scoped_rules("mv old.py /tmp/new.py", self.project, self.config)
        self.assertIsNone(result)

    def test_rm_no_args_returns_none(self):
        result = check_scoped_rules("rm ", self.project, self.config)
        self.assertIsNone(result)

    def test_rm_only_flags_returns_none(self):
        result = check_scoped_rules("rm -rf", self.project, self.config)
        self.assertIsNone(result)

    def test_safe_substring_stripping(self):
        result = check_scoped_rules("docker run --rm image", self.project, self.config)
        self.assertIsNone(result)

    def test_symlink_escape(self):
        outside = os.path.join(self.tmpdir, "outside")
        os.makedirs(outside)
        link = os.path.join(self.project, "escape_link")
        os.symlink(outside, link)

        result = check_scoped_rules(
            "rm escape_link/secret.txt", self.project, self.config
        )
        self.assertIsNone(result)

    def test_rm_with_flags_in_project(self):
        result = check_scoped_rules("rm -rf build/", self.project, self.config)
        self.assertIsNotNone(result)
        self.assertEqual(result[0], "allow")

    def test_double_dash_in_project(self):
        result = check_scoped_rules("rm -- -weird-file", self.project, self.config)
        self.assertIsNotNone(result)
        self.assertEqual(result[0], "allow")

    def test_quoted_path_in_project(self):
        result = check_scoped_rules(
            'rm "path with spaces/file.txt"', self.project, self.config
        )
        self.assertIsNotNone(result)
        self.assertEqual(result[0], "allow")

    def test_multiple_files_all_in_project(self):
        result = check_scoped_rules(
            "rm a.txt b.txt sub/c.txt", self.project, self.config
        )
        self.assertIsNotNone(result)
        self.assertEqual(result[0], "allow")

    def test_multiple_files_one_outside(self):
        result = check_scoped_rules(
            "rm a.txt /etc/passwd b.txt", self.project, self.config
        )
        self.assertIsNone(result)

    # --- compound command tests ---

    def test_rm_and_chain_in_project(self):
        result = check_scoped_rules(
            "rm -f build/temp.o && yarn build", self.project, self.config
        )
        self.assertIsNotNone(result)
        self.assertEqual(result[0], "allow")

    def test_rm_and_chain_with_redirects(self):
        result = check_scoped_rules(
            "rm -f build/temp.o && yarn build 2>&1 | tail -5",
            self.project,
            self.config,
        )
        self.assertIsNotNone(result)
        self.assertEqual(result[0], "allow")

    def test_cd_outside_project_returns_none(self):
        result = check_scoped_rules(
            "cd /tmp && rm file.txt", self.project, self.config
        )
        self.assertIsNone(result)

    def test_cd_inside_project_then_rm_approved(self):
        """cd to subdir in project + rm relative path → approved."""
        subdir = os.path.join(self.project, "src")
        os.makedirs(subdir, exist_ok=True)
        result = check_scoped_rules(
            f"cd {subdir} && rm old.o", self.project, self.config
        )
        self.assertIsNotNone(result)
        self.assertEqual(result[0], "allow")

    def test_cd_relative_inside_project_then_rm_approved(self):
        """cd to relative subdir + rm → approved."""
        os.makedirs(os.path.join(self.project, "build"), exist_ok=True)
        result = check_scoped_rules(
            "cd build && rm old.o", self.project, self.config
        )
        self.assertIsNotNone(result)
        self.assertEqual(result[0], "allow")

    def test_chained_cd_relative_inside_project(self):
        """cd a && cd b && rm file → resolves a/b relative to cwd."""
        os.makedirs(os.path.join(self.project, "a", "b"), exist_ok=True)
        result = check_scoped_rules(
            "cd a && cd b && rm file.txt", self.project, self.config
        )
        self.assertIsNotNone(result)
        self.assertEqual(result[0], "allow")

    def test_chained_cd_escapes_returns_none(self):
        """cd subdir && cd /tmp → absolute outside overrides, should ask."""
        os.makedirs(os.path.join(self.project, "subdir"), exist_ok=True)
        result = check_scoped_rules(
            "cd subdir && cd /tmp && rm file.txt", self.project, self.config
        )
        self.assertIsNone(result)

    def test_real_world_rm_and_nvm_build(self):
        cmd = (
            "rm -f /home/ubuntu/glints/api/check-associations.js "
            "&& . ~/.nvm/nvm.sh && nvm use 20 && yarn run build 2>&1 | tail -5"
        )
        # The rm path is outside our test project, so it should return None
        result = check_scoped_rules(cmd, self.project, self.config)
        self.assertIsNone(result)

    def test_real_world_rm_in_project_and_build(self):
        inner_file = os.path.join(self.project, "check.js")
        cmd = f"rm -f {inner_file} && . ~/.nvm/nvm.sh && nvm use 20 && yarn run build 2>&1 | tail -5"
        result = check_scoped_rules(cmd, self.project, self.config)
        self.assertIsNotNone(result)
        self.assertEqual(result[0], "allow")

    def test_cd_outside_before_mv_returns_none(self):
        cmd = "cd /some/dir && mv file1 file2 2>&1 && echo done"
        result = check_scoped_rules(cmd, self.project, self.config)
        self.assertIsNone(result)

    def test_glob_in_segment_returns_none(self):
        result = check_scoped_rules(
            "rm *.pyc && echo done", self.project, self.config
        )
        self.assertIsNone(result)

    def test_rm_with_redirect_in_project(self):
        result = check_scoped_rules(
            "rm build/temp.o 2>&1", self.project, self.config
        )
        self.assertIsNotNone(result)
        self.assertEqual(result[0], "allow")

    def test_rm_multiple_files_redirect_and_chain(self):
        f1 = os.path.join(self.project, "a.py")
        f2 = os.path.join(self.project, "b.py")
        cmd = f'rm {f1} {f2} 2>&1 && echo "Deleted"'
        result = check_scoped_rules(cmd, self.project, self.config)
        self.assertIsNotNone(result)
        self.assertEqual(result[0], "allow")

    # --- User-submitted real-world edge cases ---

    def test_user_edge_case_glints_rm_and_build(self):
        """rm -f <project-file> && . ~/.nvm/nvm.sh && nvm use 20 && yarn build 2>&1 | tail -5"""
        inner = os.path.join(self.project, "api", "check-associations.js")
        cmd = (
            f"rm -f {inner} "
            "&& . ~/.nvm/nvm.sh && nvm use 20 && yarn run build 2>&1 | tail -5"
        )
        result = check_scoped_rules(cmd, self.project, self.config)
        self.assertIsNotNone(result)
        self.assertEqual(result[0], "allow")

    def test_user_edge_case_cd_mv_glob_outside(self):
        """cd to outside-project dir && mv glob → should ask."""
        cmd = (
            "cd /home/ubuntu/personal/WhaleWatch/ml/data/polymarket "
            "&& mv transfers/transfers_*.parquet staging/transfers/ 2>&1 "
            '&& echo "Moved" && ls staging/transfers/ | wc -l'
        )
        # cd target is outside this test project → should return None
        result = check_scoped_rules(cmd, self.project, self.config)
        self.assertIsNone(result)

    def test_user_edge_case_cd_mv_glob_inside_project(self):
        """cd to subdir in project && mv glob → should approve."""
        subdir = os.path.join(self.project, "data", "polymarket")
        os.makedirs(os.path.join(subdir, "transfers"), exist_ok=True)
        os.makedirs(os.path.join(subdir, "staging"), exist_ok=True)
        cmd = (
            f"cd {subdir} "
            "&& mv transfers/transfers_*.parquet staging/transfers/ 2>&1 "
            '&& echo "Moved"'
        )
        result = check_scoped_rules(cmd, self.project, self.config)
        self.assertIsNotNone(result)
        self.assertEqual(result[0], "allow")

    def test_user_edge_case_whale_rm_multiple_files(self):
        """rm <file1> <file2> <file3> 2>&1 && echo 'Deleted'"""
        f1 = os.path.join(self.project, "ml", "quick_eval.py")
        f2 = os.path.join(self.project, "ml", "ml_evaluate.py")
        f3 = os.path.join(self.project, "ml", "ml_scorer.py")
        cmd = f'rm {f1} {f2} {f3} 2>&1 && echo "Deleted 6 Python files"'
        result = check_scoped_rules(cmd, self.project, self.config)
        self.assertIsNotNone(result)
        self.assertEqual(result[0], "allow")

    def test_glob_in_subdir_approved(self):
        """rm build/*.o — glob in subdirectory of project should be approved."""
        os.makedirs(os.path.join(self.project, "build"), exist_ok=True)
        result = check_scoped_rules(
            "rm build/*.o", self.project, self.config
        )
        self.assertIsNotNone(result)
        self.assertEqual(result[0], "allow")

    def test_glob_at_project_root_returns_none(self):
        """rm *.pyc at project root — '.' resolves to root, which is not strictly inside."""
        result = check_scoped_rules("rm *.pyc", self.project, self.config)
        self.assertIsNone(result)

    def test_glob_outside_project_returns_none(self):
        """rm /tmp/*.txt — glob directory is outside project."""
        result = check_scoped_rules("rm /tmp/*.txt", self.project, self.config)
        self.assertIsNone(result)

    def test_mv_glob_both_in_project(self):
        """mv subdir/*.parquet dest/ — both glob dir and dest inside project."""
        result = check_scoped_rules(
            "mv transfers/*.parquet staging/", self.project, self.config
        )
        self.assertIsNotNone(result)
        self.assertEqual(result[0], "allow")

    def test_mv_glob_absolute_in_project(self):
        """mv with absolute glob path inside project."""
        transfers = os.path.join(self.project, "transfers")
        staging = os.path.join(self.project, "staging")
        cmd = f"mv {transfers}/*.parquet {staging}/"
        result = check_scoped_rules(cmd, self.project, self.config)
        self.assertIsNotNone(result)
        self.assertEqual(result[0], "allow")

    def test_user_edge_case_rm_slash_and_commit(self):
        """rm / && git commit . — rm / should NOT be approved."""
        result = check_scoped_rules(
            "rm / && git commit .", self.project, self.config
        )
        # / is not inside project
        self.assertIsNone(result)


class TestDecideWithScopedRules(unittest.TestCase):
    """Integration tests: full decide() priority chain with scoped rules."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.project = os.path.join(self.tmpdir, "project")
        os.makedirs(self.project)
        os.makedirs(os.path.join(self.project, ".git"))
        self.config = {
            "rules": {
                "default_action": "approve",
                "safe_substrings": ["--rm", "git rm"],
                "deny": {"keywords": ["rm -rf /"]},
                "scoped": {
                    "keywords": ["rm ", "mv "],
                    "allow_project_dir": True,
                    "allowed_dirs": [],
                },
                "ask": {"keywords": ["rm ", "mv "]},
                "allow": {"keywords": []},
            },
            "tools": {},
        }

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_deny_overrides_scoped(self):
        action, reason = decide("Bash", "rm -rf /", self.config, cwd=self.project)
        self.assertEqual(action, "deny")
        self.assertIn("deny keyword", reason)

    def test_scoped_approve_before_ask(self):
        action, reason = decide(
            "Bash", "rm build/temp.o", self.config, cwd=self.project
        )
        self.assertEqual(action, "allow")
        self.assertIn("Scoped approve", reason)

    def test_failed_scope_falls_through_to_ask(self):
        action, reason = decide(
            "Bash", "rm /etc/passwd", self.config, cwd=self.project
        )
        self.assertEqual(action, "ask")
        self.assertIn("ask keyword", reason)

    def test_metachar_falls_through_to_ask(self):
        action, reason = decide(
            "Bash", "rm *.pyc", self.config, cwd=self.project
        )
        self.assertEqual(action, "ask")
        self.assertIn("ask keyword", reason)

    def test_sudo_falls_through_to_ask(self):
        action, reason = decide(
            "Bash", "sudo rm file.txt", self.config, cwd=self.project
        )
        self.assertEqual(action, "ask")
        self.assertIn("ask keyword", reason)

    def test_no_cwd_skips_scoped_falls_to_ask(self):
        action, reason = decide("Bash", "rm file.txt", self.config, cwd="")
        self.assertEqual(action, "ask")

    def test_non_matching_command_uses_default(self):
        action, reason = decide(
            "Bash", "echo hello", self.config, cwd=self.project
        )
        self.assertEqual(action, "allow")
        self.assertIn("Global default", reason)

    def test_safe_substring_no_false_positive(self):
        action, reason = decide(
            "Bash", "docker run --rm img", self.config, cwd=self.project
        )
        self.assertEqual(action, "allow")

    def test_skip_keyword_check_tools(self):
        action, reason = decide(
            "EnterPlanMode", "{}", self.config, cwd=self.project
        )
        self.assertEqual(action, "allow")
        self.assertIn("Skipped", reason)

    def test_mv_both_in_project_approved(self):
        action, reason = decide(
            "Bash", "mv old.py new.py", self.config, cwd=self.project
        )
        self.assertEqual(action, "allow")
        self.assertIn("Scoped approve", reason)

    def test_mv_destination_outside_asks(self):
        action, reason = decide(
            "Bash", "mv old.py /tmp/new.py", self.config, cwd=self.project
        )
        self.assertEqual(action, "ask")

    def test_chained_cd_outside_then_rm_falls_to_ask(self):
        action, reason = decide(
            "Bash", "cd /tmp && rm file", self.config, cwd=self.project
        )
        self.assertEqual(action, "ask")

    def test_chained_cd_inside_then_rm_approved(self):
        os.makedirs(os.path.join(self.project, "src"), exist_ok=True)
        action, reason = decide(
            "Bash",
            f"cd {os.path.join(self.project, 'src')} && rm old.o",
            self.config,
            cwd=self.project,
        )
        self.assertEqual(action, "allow")
        self.assertIn("Scoped approve", reason)

    # --- compound command integration tests ---

    def test_rm_and_build_chain_approved(self):
        action, reason = decide(
            "Bash",
            "rm -f build/out.js && yarn build 2>&1 | tail -5",
            self.config,
            cwd=self.project,
        )
        self.assertEqual(action, "allow")
        self.assertIn("Scoped approve", reason)

    def test_rm_outside_in_chain_asks(self):
        action, reason = decide(
            "Bash",
            "rm -f /etc/important && echo done",
            self.config,
            cwd=self.project,
        )
        self.assertEqual(action, "ask")

    def test_rm_glob_at_root_asks(self):
        """rm *.pyc at project root still asks (root not strictly inside)."""
        action, reason = decide(
            "Bash",
            "rm *.pyc && echo cleaned",
            self.config,
            cwd=self.project,
        )
        self.assertEqual(action, "ask")

    def test_rm_glob_in_subdir_approved(self):
        """rm build/*.o — glob in project subdir is approved."""
        action, reason = decide(
            "Bash",
            "rm build/*.o && echo cleaned",
            self.config,
            cwd=self.project,
        )
        self.assertEqual(action, "allow")
        self.assertIn("Scoped approve", reason)

    # --- quoted string content tests ---

    def test_commit_message_with_rm_does_not_trigger(self):
        action, reason = decide(
            "Bash",
            'git commit -m "Add scoped rules for rm/mv within project"',
            self.config,
            cwd=self.project,
        )
        self.assertEqual(action, "allow")
        self.assertIn("Global default", reason)

    def test_echo_with_rm_does_not_trigger(self):
        action, reason = decide(
            "Bash",
            'echo "use rm to delete files"',
            self.config,
            cwd=self.project,
        )
        self.assertEqual(action, "allow")

    def test_real_rm_before_commit_still_caught(self):
        action, reason = decide(
            "Bash",
            'rm /etc/passwd && git commit -m "oops"',
            self.config,
            cwd=self.project,
        )
        self.assertEqual(action, "ask")

    def test_real_rm_in_project_before_commit_approved(self):
        action, reason = decide(
            "Bash",
            'rm build/out.js && git commit -m "clean build"',
            self.config,
            cwd=self.project,
        )
        self.assertEqual(action, "allow")
        self.assertIn("Scoped approve", reason)

    # --- git rm safe substring ---

    def test_git_rm_cached_does_not_trigger(self):
        """git rm should be stripped by safe_substrings so 'rm ' doesn't match."""
        action, reason = decide(
            "Bash",
            "git rm --cached .claude/settings.local.json 2>&1",
            self.config,
            cwd=self.project,
        )
        self.assertEqual(action, "allow")
        self.assertIn("Global default", reason)

    # --- User-submitted real-world edge cases for decide() ---

    def test_user_edge_case_rm_slash_and_commit_asks(self):
        """rm / && git commit . — should ask (/ is not in project)."""
        action, reason = decide(
            "Bash",
            "rm / && git commit .",
            self.config,
            cwd=self.project,
        )
        self.assertEqual(action, "ask")

    def test_user_edge_case_full_rm_build_chain(self):
        """Full real-world command: rm <in-project> && . nvm.sh && nvm use && yarn build 2>&1 | tail"""
        inner = os.path.join(self.project, "check.js")
        cmd = (
            f"rm -f {inner} "
            "&& . ~/.nvm/nvm.sh && nvm use 20 && yarn run build 2>&1 | tail -5"
        )
        action, reason = decide("Bash", cmd, self.config, cwd=self.project)
        self.assertEqual(action, "allow")
        self.assertIn("Scoped approve", reason)

    def test_user_edge_case_cd_outside_then_mv_glob_asks(self):
        """cd to outside dir && mv glob — should ask."""
        cmd = (
            "cd /home/ubuntu/personal/WhaleWatch/ml/data/polymarket "
            "&& mv transfers/transfers_*.parquet staging/transfers/ 2>&1"
        )
        action, reason = decide("Bash", cmd, self.config, cwd=self.project)
        self.assertEqual(action, "ask")

    def test_user_edge_case_cd_inside_then_mv_glob_approved(self):
        """cd to project subdir && mv glob — should approve."""
        subdir = os.path.join(self.project, "data")
        os.makedirs(os.path.join(subdir, "transfers"), exist_ok=True)
        os.makedirs(os.path.join(subdir, "staging"), exist_ok=True)
        cmd = (
            f"cd {subdir} "
            "&& mv transfers/*.parquet staging/ 2>&1"
        )
        action, reason = decide("Bash", cmd, self.config, cwd=self.project)
        self.assertEqual(action, "allow")
        self.assertIn("Scoped approve", reason)

    def test_user_edge_case_whale_rm_multiple_approved(self):
        """rm <in-project-file1> <file2> <file3> 2>&1 && echo 'Deleted'"""
        f1 = os.path.join(self.project, "ml", "quick_eval.py")
        f2 = os.path.join(self.project, "ml", "ml_evaluate.py")
        f3 = os.path.join(self.project, "ml", "ml_scorer.py")
        cmd = f'rm {f1} {f2} {f3} 2>&1 && echo "Deleted 6 Python files"'
        action, reason = decide("Bash", cmd, self.config, cwd=self.project)
        self.assertEqual(action, "allow")
        self.assertIn("Scoped approve", reason)

    def test_user_edge_case_mv_glob_absolute_approved(self):
        """mv /project/transfers/*.parquet /project/staging/ — glob with absolute paths in project."""
        transfers = os.path.join(self.project, "transfers")
        staging = os.path.join(self.project, "staging")
        cmd = f"mv {transfers}/*.parquet {staging}/transfers/"
        action, reason = decide("Bash", cmd, self.config, cwd=self.project)
        self.assertEqual(action, "allow")
        self.assertIn("Scoped approve", reason)

    # --- Multi-keyword chain safety ---

    def test_rm_ok_but_mv_escapes_asks(self):
        """rm in-project + mv escaping → must ask (both scoped keywords checked)."""
        action, reason = decide(
            "Bash",
            "rm build/old.o && mv secrets.txt /tmp/",
            self.config,
            cwd=self.project,
        )
        self.assertEqual(action, "ask")

    def test_rm_ok_mv_ok_both_approved(self):
        """rm + mv both in project → approved."""
        action, reason = decide(
            "Bash",
            "rm build/a.o && mv build/b.o build/c.o",
            self.config,
            cwd=self.project,
        )
        self.assertEqual(action, "allow")
        self.assertIn("Scoped approve", reason)

    def test_scoped_ok_but_ask_only_keyword_asks(self):
        """rm in-project + kubectl (ask-only) → must ask."""
        config = dict(self.config)
        config["rules"] = dict(config["rules"])
        config["rules"]["ask"] = {"keywords": ["rm ", "mv ", "kubectl"]}
        action, reason = decide(
            "Bash",
            "rm build/old.o && kubectl delete pod mypod",
            config,
            cwd=self.project,
        )
        self.assertEqual(action, "ask")

    def test_pushd_outside_project_asks(self):
        """pushd /tmp && rm file → should ask."""
        action, reason = decide(
            "Bash",
            "pushd /tmp && rm file.txt",
            self.config,
            cwd=self.project,
        )
        self.assertEqual(action, "ask")

    def test_pushd_inside_project_approved(self):
        """pushd <project-subdir> && rm file → approved."""
        src = os.path.join(self.project, "src")
        os.makedirs(src, exist_ok=True)
        action, reason = decide(
            "Bash",
            f"pushd {src} && rm old.o",
            self.config,
            cwd=self.project,
        )
        self.assertEqual(action, "allow")
        self.assertIn("Scoped approve", reason)

    def test_popd_then_rm_asks(self):
        """popd && rm file → unknown directory, should ask."""
        action, reason = decide(
            "Bash",
            "popd && rm file.txt",
            self.config,
            cwd=self.project,
        )
        self.assertEqual(action, "ask")

    def test_user_edge_case_commit_message_with_rm_text(self):
        """git add && git commit -m 'Add scoped rules for rm/mv...' — rm in message shouldn't trigger."""
        cmd = (
            'git add approver.py config.toml && '
            'git commit -m "Add scoped rules: path-aware auto-approve for rm/mv within project dir"'
        )
        action, reason = decide("Bash", cmd, self.config, cwd=self.project)
        self.assertEqual(action, "allow")
        self.assertIn("Global default", reason)

    def test_comment_with_rm_keyword_does_not_trigger_ask(self):
        """Regression: bash comment containing 'rm' should not trigger ask."""
        cmd = "ls -la\n# The rm might have also removed the directory? Let's check"
        action, reason = decide("Bash", cmd, self.config, cwd=self.project)
        self.assertEqual(action, "allow")
        self.assertIn("Global default", reason)

    def test_inline_comment_with_keyword_does_not_trigger_ask(self):
        """Inline comment containing ask keyword should be stripped."""
        cmd = "ls -la  # check if rm deleted it"
        action, reason = decide("Bash", cmd, self.config, cwd=self.project)
        self.assertEqual(action, "allow")
        self.assertIn("Global default", reason)

    def test_real_rm_not_hidden_by_comment_stripping(self):
        """Actual rm command on a line should still trigger ask."""
        cmd = "rm /etc/passwd  # dangerous"
        action, reason = decide("Bash", cmd, self.config, cwd=self.project)
        self.assertEqual(action, "ask")
        self.assertIn("rm ", reason)


class TestCheckDockerScoped(unittest.TestCase):
    """Tests for docker scoped rules: literal targets vs shell expansion."""

    def setUp(self):
        self.config = {
            "rules": {
                "safe_substrings": ["--rm"],
                "docker_scoped": {
                    "keywords": ["docker rm", "docker rmi", "docker container rm"],
                },
                "scoped": {
                    "keywords": ["rm ", "mv "],
                },
                "ask": {
                    "keywords": [
                        "rm ", "mv ", "docker rm", "docker rmi",
                        "docker container rm", "docker system prune",
                    ],
                },
            },
        }

    def test_literal_container_name_approved(self):
        result = check_docker_scoped("docker rm my-container", self.config)
        self.assertIsNotNone(result)
        self.assertEqual(result[0], "allow")

    def test_literal_multiple_containers_approved(self):
        result = check_docker_scoped("docker rm container1 container2", self.config)
        self.assertIsNotNone(result)
        self.assertEqual(result[0], "allow")

    def test_literal_with_force_flag_approved(self):
        result = check_docker_scoped("docker rm -f my-container", self.config)
        self.assertIsNotNone(result)
        self.assertEqual(result[0], "allow")

    def test_command_substitution_returns_none(self):
        """docker rm $(docker ps -aq) — the shotgun pattern."""
        result = check_docker_scoped("docker rm $(docker ps -aq)", self.config)
        self.assertIsNone(result)

    def test_backtick_substitution_returns_none(self):
        result = check_docker_scoped("docker rm `docker ps -aq`", self.config)
        self.assertIsNone(result)

    def test_variable_returns_none(self):
        result = check_docker_scoped("docker rm $CONTAINER", self.config)
        self.assertIsNone(result)

    def test_rmi_literal_approved(self):
        result = check_docker_scoped("docker rmi my-image:latest", self.config)
        self.assertIsNotNone(result)
        self.assertEqual(result[0], "allow")

    def test_rmi_expansion_returns_none(self):
        result = check_docker_scoped("docker rmi $(docker images -q)", self.config)
        self.assertIsNone(result)

    def test_container_rm_literal_approved(self):
        result = check_docker_scoped("docker container rm my-container", self.config)
        self.assertIsNotNone(result)
        self.assertEqual(result[0], "allow")

    def test_sudo_docker_rm_returns_none(self):
        result = check_docker_scoped("sudo docker rm my-container", self.config)
        self.assertIsNone(result)

    def test_chain_stop_then_rm_literal_approved(self):
        result = check_docker_scoped(
            "docker stop my-container; docker rm my-container", self.config
        )
        self.assertIsNotNone(result)
        self.assertEqual(result[0], "allow")

    def test_chain_stop_expansion_then_rm_expansion_returns_none(self):
        """The real-world shotgun pattern from logs."""
        result = check_docker_scoped(
            "docker stop $(docker ps -q) 2>/dev/null; docker rm $(docker ps -aq) 2>/dev/null",
            self.config,
        )
        self.assertIsNone(result)

    def test_docker_rm_with_other_ask_keyword_returns_none(self):
        """docker rm + docker system prune in same chain → ask."""
        result = check_docker_scoped(
            "docker rm my-container && docker system prune", self.config
        )
        self.assertIsNone(result)

    def test_docker_run_rm_flag_no_match(self):
        """docker run --rm should not trigger (--rm is safe_substring)."""
        result = check_docker_scoped("docker run --rm my-image", self.config)
        self.assertIsNone(result)

    def test_no_docker_scoped_config_returns_none(self):
        config = {"rules": {}}
        result = check_docker_scoped("docker rm my-container", config)
        self.assertIsNone(result)

    def test_unrelated_command_returns_none(self):
        result = check_docker_scoped("echo hello", self.config)
        self.assertIsNone(result)

    def test_unparseable_command_returns_none(self):
        result = check_docker_scoped("docker rm <<<", self.config)
        self.assertIsNone(result)


class TestDecideWithDockerScoped(unittest.TestCase):
    """Integration tests: decide() with docker scoped rules."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.project = os.path.join(self.tmpdir, "project")
        os.makedirs(self.project)
        os.makedirs(os.path.join(self.project, ".git"))
        self.config = {
            "rules": {
                "default_action": "approve",
                "safe_substrings": ["--rm", "git rm"],
                "deny": {"keywords": []},
                "scoped": {
                    "keywords": ["rm ", "mv "],
                    "allow_project_dir": True,
                    "allowed_dirs": [],
                },
                "docker_scoped": {
                    "keywords": ["docker rm", "docker rmi"],
                },
                "ask": {
                    "keywords": [
                        "rm ", "mv ", "docker rm", "docker rmi",
                        "docker system prune", "docker volume rm",
                    ],
                },
                "allow": {"keywords": []},
            },
            "tools": {},
        }

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_docker_rm_literal_approved(self):
        action, reason = decide(
            "Bash", "docker rm my-container", self.config, cwd=self.project
        )
        self.assertEqual(action, "allow")
        self.assertIn("Docker scoped approve", reason)

    def test_docker_rm_expansion_asks(self):
        action, reason = decide(
            "Bash", "docker rm $(docker ps -aq)", self.config, cwd=self.project
        )
        self.assertEqual(action, "ask")

    def test_docker_rmi_literal_approved(self):
        action, reason = decide(
            "Bash", "docker rmi my-image:v1", self.config, cwd=self.project
        )
        self.assertEqual(action, "allow")
        self.assertIn("Docker scoped approve", reason)

    def test_docker_rmi_expansion_asks(self):
        action, reason = decide(
            "Bash", "docker rmi $(docker images -q)", self.config, cwd=self.project
        )
        self.assertEqual(action, "ask")

    def test_docker_system_prune_still_asks(self):
        """docker system prune is not in docker_scoped, should still ask."""
        action, reason = decide(
            "Bash", "docker system prune", self.config, cwd=self.project
        )
        self.assertEqual(action, "ask")

    def test_docker_volume_rm_still_asks(self):
        action, reason = decide(
            "Bash", "docker volume rm myvolume", self.config, cwd=self.project
        )
        self.assertEqual(action, "ask")

    def test_real_world_shotgun_asks(self):
        """The exact pattern from today's logs."""
        cmd = 'docker stop $(docker ps -q) 2>/dev/null; docker rm $(docker ps -aq) 2>/dev/null; echo "done"'
        action, reason = decide("Bash", cmd, self.config, cwd=self.project)
        self.assertEqual(action, "ask")

    def test_real_world_cleanup_literal_approved(self):
        """Targeted cleanup of known containers."""
        cmd = "docker stop myapp-db myapp-redis; docker rm myapp-db myapp-redis"
        action, reason = decide("Bash", cmd, self.config, cwd=self.project)
        self.assertEqual(action, "allow")
        self.assertIn("Docker scoped approve", reason)

    def test_docker_rm_plus_file_rm_in_project(self):
        """docker rm + rm in-project — falls through since both ask keywords present."""
        cmd = "docker rm my-container && rm build/temp.o"
        action, reason = decide("Bash", cmd, self.config, cwd=self.project)
        # docker_scoped sees "rm " (ask keyword not in docker_scoped) → returns None
        # scoped sees "docker rm" (ask keyword not in scoped) → returns None
        # Falls through to ask
        self.assertEqual(action, "ask")

    def test_docker_run_rm_flag_approved(self):
        """docker run --rm should not trigger docker_scoped or ask."""
        action, reason = decide(
            "Bash", "docker run --rm my-image", self.config, cwd=self.project
        )
        self.assertEqual(action, "allow")
        self.assertIn("Global default", reason)


if __name__ == "__main__":
    unittest.main()
