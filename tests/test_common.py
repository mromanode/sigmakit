import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent))

from common import run, baseline_sha, changed_rule_paths


class TestRun:
    def test_run_success(self):
        result = run(["cmd", "/c", "echo", "hello"])
        assert result.returncode == 0
        assert result.stdout.strip() == "hello"

    def test_run_failure(self):
        result = run(["cmd", "/c", "exit", "1"])
        assert result.returncode != 0


class TestBaselineSha:
    @patch("common.run")
    def test_explicit_base_sha_valid(self, mock_run):
        mock_run.side_effect = [
            MagicMock(returncode=0),  # cat-file check
        ]
        os.environ["SIGMAKIT_BASE_SHA"] = "abc123"
        assert baseline_sha() == "abc123"
        del os.environ["SIGMAKIT_BASE_SHA"]

    @patch("common.run")
    def test_explicit_base_sha_fetch(self, mock_run):
        mock_run.side_effect = [
            MagicMock(returncode=1),  # cat-file fails
            MagicMock(returncode=0),  # fetch succeeds
        ]
        os.environ["SIGMAKIT_BASE_SHA"] = "abc123"
        assert baseline_sha() == "abc123"
        del os.environ["SIGMAKIT_BASE_SHA"]

    @patch("common.run")
    def test_merge_base(self, mock_run):
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout="merge123\n"),  # merge-base
        ]
        assert baseline_sha() == "merge123"

    @patch("common.run")
    def test_fallback_to_head_parent(self, mock_run):
        mock_run.side_effect = [
            MagicMock(returncode=1, stdout=""),  # merge-base fails
            MagicMock(returncode=0, stdout="parent123\n"),  # HEAD^
        ]
        assert baseline_sha() == "parent123"


class TestChangedRulePaths:
    @patch("common.run")
    def test_changed_rule_paths_added(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="A\trules/sigma/linux/process_creation/new_rule.yml\n"
        )
        rules_root = Path("rules/sigma")
        changes = list(changed_rule_paths("base", rules_root))
        assert len(changes) == 1
        status, rel = changes[0]
        assert status == "A"
        assert rel == Path("linux/process_creation/new_rule.yml")

    @patch("common.run")
    def test_changed_rule_paths_modified(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="M\trules/sigma/web/proxy_generic/existing.yml\n"
        )
        rules_root = Path("rules/sigma")
        changes = list(changed_rule_paths("base", rules_root))
        assert len(changes) == 1
        status, rel = changes[0]
        assert status == "M"

    @patch("common.run")
    def test_changed_rule_paths_deleted(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="D\trules/sigma/linux/process_creation/old.yml\n"
        )
        rules_root = Path("rules/sigma")
        changes = list(changed_rule_paths("base", rules_root))
        assert len(changes) == 1
        status, rel = changes[0]
        assert status == "D"

    @patch("common.run")
    def test_changed_rule_paths_renamed(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="R100\trules/sigma/old.yml\trules/sigma/new.yml\n"
        )
        rules_root = Path("rules/sigma")
        changes = list(changed_rule_paths("base", rules_root))
        assert len(changes) == 1
        status, rel = changes[0]
        assert status.startswith("R")
        assert str(rel) == "new.yml"