#!/usr/bin/env python3
"""Comprehensive tests for scoped rules in approver.py."""

import os
import tempfile
import unittest

from approver import (
    _find_keyword_segment,
    _strip_redirections,
    build_allowed_dirs,
    check_scoped_rules,
    decide,
    extract_path_args,
    find_git_root,
    resolve_and_check_paths,
)


class TestFindKeywordSegment(unittest.TestCase):
    """Tests for compound command splitting."""

    def test_simple_command_returns_whole(self):
        self.assertEqual(
            _find_keyword_segment("rm file.txt", "rm "),
            "rm file.txt",
        )

    def test_rm_before_and_chain(self):
        seg = _find_keyword_segment(
            "rm -f file.txt && yarn build", "rm "
        )
        self.assertEqual(seg, "rm -f file.txt")

    def test_rm_after_safe_chain(self):
        seg = _find_keyword_segment(
            "echo hello && rm file.txt", "rm "
        )
        self.assertEqual(seg, "rm file.txt")

    def test_cd_before_rm_returns_none(self):
        self.assertIsNone(
            _find_keyword_segment("cd /tmp && rm file.txt", "rm ")
        )

    def test_or_chain(self):
        seg = _find_keyword_segment(
            "rm file.txt || echo failed", "rm "
        )
        self.assertEqual(seg, "rm file.txt")

    def test_semicolon_chain(self):
        seg = _find_keyword_segment(
            "rm file.txt ; echo done", "rm "
        )
        self.assertEqual(seg, "rm file.txt")

    def test_pipe_chain(self):
        seg = _find_keyword_segment(
            "rm file.txt | echo piped", "rm "
        )
        self.assertEqual(seg, "rm file.txt")

    def test_keyword_not_found(self):
        self.assertIsNone(
            _find_keyword_segment("echo hello && ls", "rm ")
        )

    def test_multiple_chains(self):
        seg = _find_keyword_segment(
            "rm -f build/out && echo cleaned && ls", "rm "
        )
        self.assertEqual(seg, "rm -f build/out")

    def test_real_world_rm_and_build(self):
        cmd = "rm -f /home/user/project/check.js && . ~/.nvm/nvm.sh && nvm use 20 && yarn run build 2>&1 | tail -5"
        seg = _find_keyword_segment(cmd, "rm ")
        self.assertEqual(seg, "rm -f /home/user/project/check.js")

    def test_cd_in_compound_mv(self):
        cmd = "cd /some/dir && mv file1 file2 2>&1 && echo done"
        self.assertIsNone(_find_keyword_segment(cmd, "mv "))


class TestStripRedirections(unittest.TestCase):
    """Tests for redirection stripping."""

    def test_stderr_to_stdout(self):
        self.assertEqual(_strip_redirections("rm file 2>&1"), "rm file")

    def test_stderr_to_devnull(self):
        self.assertEqual(_strip_redirections("rm file 2>/dev/null"), "rm file")

    def test_stdout_to_devnull(self):
        self.assertEqual(_strip_redirections("rm file >/dev/null"), "rm file")

    def test_stdout_to_file(self):
        self.assertEqual(_strip_redirections("rm file >output.log"), "rm file")

    def test_append_redirect(self):
        self.assertEqual(_strip_redirections("rm file >>output.log"), "rm file")

    def test_input_redirect(self):
        self.assertEqual(_strip_redirections("cmd < input.txt"), "cmd")

    def test_no_redirect(self):
        self.assertEqual(_strip_redirections("rm file1 file2"), "rm file1 file2")

    def test_multiple_redirects(self):
        self.assertEqual(
            _strip_redirections("rm file 2>&1 >/dev/null"), "rm file"
        )

    def test_preserves_paths(self):
        self.assertEqual(
            _strip_redirections("rm /home/user/file.txt 2>&1"),
            "rm /home/user/file.txt",
        )


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
        # sudo is now caught as an unsafe prefix within the segment
        self.assertIsNone(extract_path_args("sudo rm file.txt", "rm "))

    def test_metacharacters_return_none(self):
        self.assertIsNone(extract_path_args("rm *.txt", "rm "))

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
        """rm in first segment of '&&' chain should extract paths from that segment."""
        self.assertEqual(
            extract_path_args("rm -f file.txt && yarn build", "rm "),
            ["file.txt"],
        )

    def test_rm_then_and_chain_with_redirects(self):
        """Segments after the rm segment can have >, |, etc. without affecting parsing."""
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

    def test_pipe_chain_extracts_segment(self):
        self.assertEqual(
            extract_path_args("rm file.txt | echo piped", "rm "),
            ["file.txt"],
        )

    def test_cd_before_rm_returns_none(self):
        """If cd appears before rm in a chain, cwd may have changed — bail out."""
        self.assertIsNone(
            extract_path_args("cd /tmp && rm file.txt", "rm ")
        )

    def test_glob_in_segment_returns_none(self):
        """Globs in the rm segment itself should still be rejected."""
        self.assertIsNone(
            extract_path_args("rm *.pyc && echo done", "rm ")
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
        """2>&1 in the rm segment should be stripped, not rejected."""
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

    def test_cd_before_rm_returns_none(self):
        result = check_scoped_rules(
            "cd /tmp && rm file.txt", self.project, self.config
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

    def test_cd_before_mv_returns_none(self):
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
                "safe_substrings": ["--rm"],
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

    def test_chained_cd_then_rm_falls_to_ask(self):
        action, reason = decide(
            "Bash", "cd /tmp && rm file", self.config, cwd=self.project
        )
        self.assertEqual(action, "ask")

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

    def test_rm_chain_with_glob_asks(self):
        action, reason = decide(
            "Bash",
            "rm *.pyc && echo cleaned",
            self.config,
            cwd=self.project,
        )
        self.assertEqual(action, "ask")


if __name__ == "__main__":
    unittest.main()
