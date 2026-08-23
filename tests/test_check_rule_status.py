import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent))

from check_rule_status import status_of_source, main


class TestStatusOfSource:
    def test_valid_experimental(self):
        yaml_content = """
title: Test
id: 12345678-1234-1234-1234-123456789012
status: experimental
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
"""
        assert status_of_source(yaml_content) == "experimental"

    def test_valid_test(self):
        yaml_content = """
title: Test
id: 12345678-1234-1234-1234-123456789012
status: test
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
"""
        assert status_of_source(yaml_content) == "test"

    def test_valid_stable(self):
        yaml_content = """
title: Test
id: 12345678-1234-1234-1234-123456789012
status: stable
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
"""
        assert status_of_source(yaml_content) == "stable"

    def test_missing_status(self):
        yaml_content = """
title: Test
id: 12345678-1234-1234-1234-123456789012
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
"""
        assert status_of_source(yaml_content) is None

    def test_invalid_yaml(self):
        yaml_content = "not: valid: yaml: ["
        assert status_of_source(yaml_content) is None


class TestMain:
    @patch("check_rule_status.baseline_sha")
    @patch("check_rule_status.changed_rule_paths")
    def test_workflow_dispatch_skips(self, mock_changed, mock_baseline):
        os.environ["GITHUB_EVENT_NAME"] = "workflow_dispatch"
        assert main() == 0
        mock_baseline.assert_not_called()
        mock_changed.assert_not_called()
        del os.environ["GITHUB_EVENT_NAME"]

    @patch("check_rule_status.baseline_sha")
    @patch("check_rule_status.changed_rule_paths")
    def test_push_non_main_skips(self, mock_changed, mock_baseline):
        os.environ["GITHUB_EVENT_NAME"] = "push"
        os.environ["GITHUB_REF_NAME"] = "feature-branch"
        assert main() == 0
        mock_baseline.assert_not_called()
        mock_changed.assert_not_called()
        del os.environ["GITHUB_EVENT_NAME"]
        del os.environ["GITHUB_REF_NAME"]

    @patch("check_rule_status.baseline_sha")
    def test_no_baseline_skips(self, mock_baseline):
        os.environ["GITHUB_EVENT_NAME"] = "pull_request"
        mock_baseline.return_value = ""
        assert main() == 0
        del os.environ["GITHUB_EVENT_NAME"]

    @patch("check_rule_status.baseline_sha")
    @patch("check_rule_status.changed_rule_paths")
    def test_new_rule_experimental_passes(self, mock_changed, mock_baseline):
        os.environ["GITHUB_EVENT_NAME"] = "pull_request"
        mock_baseline.return_value = "base123"
        
        with tempfile.TemporaryDirectory() as tmpdir:
            rules_root = Path(tmpdir) / "rules" / "sigma"
            rules_root.mkdir(parents=True)
            rule_file = rules_root / "linux" / "process_creation" / "new_rule.yml"
            rule_file.parent.mkdir(parents=True)
            rule_file.write_text("""
title: Test
id: 12345678-1234-1234-1234-123456789012
status: experimental
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        field: value
    condition: selection
""")
            
            mock_changed.return_value = [("A", Path("linux/process_creation/new_rule.yml"))]
            
            with patch("check_rule_status.RULES", rules_root):
                assert main() == 0
        
        del os.environ["GITHUB_EVENT_NAME"]

    @patch("check_rule_status.baseline_sha")
    @patch("check_rule_status.changed_rule_paths")
    def test_new_rule_non_experimental_fails(self, mock_changed, mock_baseline):
        os.environ["GITHUB_EVENT_NAME"] = "pull_request"
        mock_baseline.return_value = "base123"
        
        with tempfile.TemporaryDirectory() as tmpdir:
            rules_root = Path(tmpdir) / "rules" / "sigma"
            rules_root.mkdir(parents=True)
            rule_file = rules_root / "linux" / "process_creation" / "new_rule.yml"
            rule_file.parent.mkdir(parents=True)
            rule_file.write_text("""
title: Test
id: 12345678-1234-1234-1234-123456789012
status: test
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        field: value
    condition: selection
""")
            
            mock_changed.return_value = [("A", Path("linux/process_creation/new_rule.yml"))]
            
            with patch("check_rule_status.RULES", rules_root):
                assert main() == 1
        
        del os.environ["GITHUB_EVENT_NAME"]

    @patch("check_rule_status.baseline_sha")
    @patch("check_rule_status.changed_rule_paths")
    def test_modified_rule_any_status_passes(self, mock_changed, mock_baseline):
        os.environ["GITHUB_EVENT_NAME"] = "pull_request"
        mock_baseline.return_value = "base123"
        
        with tempfile.TemporaryDirectory() as tmpdir:
            rules_root = Path(tmpdir) / "rules" / "sigma"
            rules_root.mkdir(parents=True)
            rule_file = rules_root / "linux" / "process_creation" / "existing.yml"
            rule_file.parent.mkdir(parents=True)
            rule_file.write_text("""
title: Test
id: 12345678-1234-1234-1234-123456789012
status: stable
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        field: value
    condition: selection
""")
            
            mock_changed.return_value = [("M", Path("linux/process_creation/existing.yml"))]
            
            with patch("check_rule_status.RULES", rules_root):
                assert main() == 0
        
        del os.environ["GITHUB_EVENT_NAME"]