import sys
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent))

from convert_rules import parenthesize_or_groups, conversion_fingerprint, main


class TestParenthesizeOrGroups:
    def test_no_atoms(self):
        query = "simple query without atoms"
        assert parenthesize_or_groups(query) == query

    def test_single_atom(self):
        query = 'field=/"pattern"/i'
        assert parenthesize_or_groups(query) == query

    def test_multiple_or_atoms_same_depth(self):
        query = 'field=/"a"/i or field=/"b"/i or field=/"c"/i'
        result = parenthesize_or_groups(query)
        assert result == '(field=/"a"/i or field=/"b"/i or field=/"c"/i)'

    def test_mixed_operators(self):
        query = 'field=/"a"/i and field=/"b"/i or field=/"c"/i'
        result = parenthesize_or_groups(query)
        assert 'or' in result

    def test_nested_parens(self):
        query = '(field=/"a"/i or field=/"b"/i) and field=/"c"/i'
        result = parenthesize_or_groups(query)
        assert result == query

    def test_case_insensitive_or(self):
        query = 'field=/"a"/i OR field=/"b"/i'
        result = parenthesize_or_groups(query)
        assert result == '(field=/"a"/i OR field=/"b"/i)'

    def test_or_with_whitespace(self):
        query = 'field=/"a"/i   or   field=/"b"/i'
        result = parenthesize_or_groups(query)
        assert result == '(field=/"a"/i   or   field=/"b"/i)'


class TestConversionFingerprint:
    @patch("convert_rules.version")
    def test_fingerprint_with_pipeline_file(self, mock_version):
        def version_side_effect(dist):
            versions = {"sigma-cli": "1.0", "pySigma": "2.0", "pySigma-validators-sigmahq": "1.0", "pysigma-backend-splunk": "1.0", "pysigma-backend-crowdstrike": "1.0"}
            return versions.get(dist)
        mock_version.side_effect = version_side_effect
        
        with tempfile.TemporaryDirectory() as tmpdir:
            pipeline = Path(tmpdir) / "pipeline.yml"
            pipeline.write_text("test: config")
            
            fp1 = conversion_fingerprint(pipeline)
            fp2 = conversion_fingerprint(pipeline)
            assert fp1 == fp2
            assert len(fp1) == 64

    @patch("convert_rules.version")
    def test_fingerprint_builtin_pipeline(self, mock_version):
        def version_side_effect(dist):
            versions = {"sigma-cli": "1.0", "pySigma": "2.0", "pySigma-validators-sigmahq": "1.0", "pysigma-backend-splunk": "1.0", "pysigma-backend-crowdstrike": "1.0"}
            return versions.get(dist)
        mock_version.side_effect = version_side_effect
        
        fp1 = conversion_fingerprint(Path("crowdstrike_falcon"))
        fp2 = conversion_fingerprint(Path("crowdstrike_falcon"))
        assert fp1 == fp2
        assert len(fp1) == 64  # SHA256 hex digest


class TestMain:
    def _create_mock_run(self, output_content=""):
        def mock_run(cmd, **kwargs):
            # Create the output file that sigma convert would create
            out_idx = cmd.index("-o") if "-o" in cmd else -1
            if out_idx >= 0 and out_idx + 1 < len(cmd):
                out_path = Path(cmd[out_idx + 1])
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_text(output_content)
            return MagicMock(returncode=0, stdout="", stderr="")
        return mock_run

    @patch("convert_rules.subprocess.run")
    @patch("convert_rules.baseline_sha")
    def test_convert_all_rules_no_base(self, mock_baseline, mock_run):
        mock_baseline.return_value = ""
        mock_run.side_effect = self._create_mock_run()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            rules_root = Path(tmpdir) / "rules"
            rules_root.mkdir()
            (rules_root / "rule1.yml").write_text("title: Test\nid: 1\nstatus: experimental\nlogsource:\n  category: test\ndetection:\n  sel:\n    f: v\n  condition: sel")
            (rules_root / "rule2.yml").write_text("title: Test2\nid: 2\nstatus: experimental\nlogsource:\n  category: test\ndetection:\n  sel:\n    f: v\n  condition: sel")
            
            out_root = Path(tmpdir) / "out"
            pipeline = Path(tmpdir) / "pipeline.yml"
            pipeline.write_text("test: config")
            
            sys.argv = ["convert_rules.py", "--rules", str(rules_root), "--out", str(out_root),
                        "--target", "splunk", "--pipeline", str(pipeline), "--suffix", ".spl"]
            
            assert main() == 0
            assert mock_run.call_count == 2

    @patch("convert_rules.subprocess.run")
    @patch("convert_rules.baseline_sha")
    def test_convert_changed_only(self, mock_baseline, mock_run):
        mock_baseline.return_value = "base123"
        mock_run.side_effect = self._create_mock_run()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            rules_root = Path(tmpdir) / "rules"
            rules_root.mkdir()
            (rules_root / "rule1.yml").write_text("title: Test\nid: 1\nstatus: experimental\nlogsource:\n  category: test\ndetection:\n  sel:\n    f: v\n  condition: sel")
            (rules_root / "rule2.yml").write_text("title: Test2\nid: 2\nstatus: experimental\nlogsource:\n  category: test\ndetection:\n  sel:\n    f: v\n  condition: sel")
            
            out_root = Path(tmpdir) / "out"
            out_root.mkdir()
            stamp = out_root / ".conversion-stamp"
            stamp.write_text("same_fingerprint\n")
            
            pipeline = Path(tmpdir) / "pipeline.yml"
            pipeline.write_text("test: config")
            
            with patch("convert_rules.conversion_fingerprint", return_value="same_fingerprint"):
                with patch("convert_rules.changed_rule_paths") as mock_changed:
                    mock_changed.return_value = [("M", Path("rule1.yml"))]
                    
                    sys.argv = ["convert_rules.py", "--rules", str(rules_root), "--out", str(out_root),
                                "--target", "splunk", "--pipeline", str(pipeline), "--suffix", ".spl"]
                    
                    assert main() == 0
                    assert mock_run.call_count == 1

    @patch("convert_rules.subprocess.run")
    @patch("convert_rules.baseline_sha")
    def test_convert_all_on_fingerprint_change(self, mock_baseline, mock_run):
        mock_baseline.return_value = "base123"
        mock_run.side_effect = self._create_mock_run()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            rules_root = Path(tmpdir) / "rules"
            rules_root.mkdir()
            (rules_root / "rule1.yml").write_text("title: Test\nid: 1\nstatus: experimental\nlogsource:\n  category: test\ndetection:\n  sel:\n    f: v\n  condition: sel")
            
            out_root = Path(tmpdir) / "out"
            out_root.mkdir()
            stamp = out_root / ".conversion-stamp"
            stamp.write_text("old_fingerprint\n")
            
            pipeline = Path(tmpdir) / "pipeline.yml"
            pipeline.write_text("test: config")
            
            with patch("convert_rules.conversion_fingerprint", return_value="new_fingerprint"):
                sys.argv = ["convert_rules.py", "--rules", str(rules_root), "--out", str(out_root),
                            "--target", "splunk", "--pipeline", str(pipeline), "--suffix", ".spl"]
                
                assert main() == 0
                assert mock_run.call_count == 1

    @patch("convert_rules.subprocess.run")
    @patch("convert_rules.baseline_sha")
    def test_removes_stale_outputs(self, mock_baseline, mock_run):
        mock_baseline.return_value = ""
        mock_run.side_effect = self._create_mock_run()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            rules_root = Path(tmpdir) / "rules"
            rules_root.mkdir()
            (rules_root / "rule1.yml").write_text("title: Test\nid: 1\nstatus: experimental\nlogsource:\n  category: test\ndetection:\n  sel:\n    f: v\n  condition: sel")
            
            out_root = Path(tmpdir) / "out"
            out_root.mkdir()
            (out_root / "stale.spl").write_text("stale")
            
            pipeline = Path(tmpdir) / "pipeline.yml"
            pipeline.write_text("test: config")
            
            sys.argv = ["convert_rules.py", "--rules", str(rules_root), "--out", str(out_root),
                        "--target", "splunk", "--pipeline", str(pipeline), "--suffix", ".spl"]
            
            assert main() == 0
            assert not (out_root / "stale.spl").exists()
            assert (out_root / "rule1.spl").exists()

    @patch("convert_rules.subprocess.run")
    @patch("convert_rules.baseline_sha")
    def test_log_scale_postprocess(self, mock_baseline, mock_run):
        mock_baseline.return_value = ""
        mock_run.side_effect = self._create_mock_run('field=/"a"/i or field=/"b"/i')
        
        with tempfile.TemporaryDirectory() as tmpdir:
            rules_root = Path(tmpdir) / "rules"
            rules_root.mkdir()
            (rules_root / "rule1.yml").write_text("title: Test\nid: 1\nstatus: experimental\nlogsource:\n  category: test\ndetection:\n  sel:\n    f: v\n  condition: sel")
            
            out_root = Path(tmpdir) / "out"
            pipeline = Path(tmpdir) / "pipeline.yml"
            pipeline.write_text("test: config")
            
            sys.argv = ["convert_rules.py", "--rules", str(rules_root), "--out", str(out_root),
                        "--target", "log_scale", "--pipeline", str(pipeline), "--suffix", ".cql"]
            
            assert main() == 0
            output = (out_root / "rule1.cql").read_text()
            assert output.startswith("(") and output.endswith(")")