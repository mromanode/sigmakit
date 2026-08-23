import sys
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent))

from validate_queries import check_cql_regex_literals, check_spl_index_sourcetype, main


class TestCheckCqlRegexLiterals:
    def test_valid_regex(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.cql', delete=False) as f:
            f.write('field=/pattern/i\nother=/another/ims')
            path = Path(f.name)
        try:
            assert check_cql_regex_literals(path) is True
        finally:
            path.unlink()

    def test_valid_regex_with_escapes(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.cql', delete=False) as f:
            f.write(r'field=/path\/to\/file/i')
            path = Path(f.name)
        try:
            assert check_cql_regex_literals(path) is True
        finally:
            path.unlink()

    def test_unterminated_regex(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.cql', delete=False) as f:
            f.write('field=/unterminated')
            path = Path(f.name)
        try:
            assert check_cql_regex_literals(path) is False
        finally:
            path.unlink()

    def test_empty_regex(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.cql', delete=False) as f:
            f.write('field=//i')
            path = Path(f.name)
        try:
            assert check_cql_regex_literals(path) is False
        finally:
            path.unlink()

    def test_regex_in_quotes_ignored(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.cql', delete=False) as f:
            f.write('field="/not/a/regex/"')
            path = Path(f.name)
        try:
            assert check_cql_regex_literals(path) is True
        finally:
            path.unlink()

    def test_mixed_quotes_and_regex(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.cql', delete=False) as f:
            f.write('field="/quoted/" and other=/regex/i')
            path = Path(f.name)
        try:
            assert check_cql_regex_literals(path) is True
        finally:
            path.unlink()


class TestCheckSplIndexSourcetype:
    def test_valid_spl(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.spl', delete=False) as f:
            f.write('index="main" sourcetype="test" field=value')
            path = Path(f.name)
        try:
            assert check_spl_index_sourcetype(path) is True
        finally:
            path.unlink()

    def test_missing_index(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.spl', delete=False) as f:
            f.write('sourcetype="test" field=value')
            path = Path(f.name)
        try:
            assert check_spl_index_sourcetype(path) is False
        finally:
            path.unlink()

    def test_missing_sourcetype(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.spl', delete=False) as f:
            f.write('index="main" field=value')
            path = Path(f.name)
        try:
            assert check_spl_index_sourcetype(path) is False
        finally:
            path.unlink()

    def test_multiple_blocks_all_valid(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.spl', delete=False) as f:
            f.write('index="main" sourcetype="test" field=value\n\nindex="other" sourcetype="test2" field=value2')
            path = Path(f.name)
        try:
            assert check_spl_index_sourcetype(path) is True
        finally:
            path.unlink()

    def test_multiple_blocks_one_invalid(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.spl', delete=False) as f:
            f.write('index="main" sourcetype="test" field=value\n\nfield=value2')
            path = Path(f.name)
        try:
            assert check_spl_index_sourcetype(path) is False
        finally:
            path.unlink()

    def test_empty_blocks_ignored(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.spl', delete=False) as f:
            f.write('index="main" sourcetype="test" field=value\n\n\n\nindex="other" sourcetype="test2" field=value2')
            path = Path(f.name)
        try:
            assert check_spl_index_sourcetype(path) is True
        finally:
            path.unlink()


class TestMain:
    @patch("validate_queries.fail")
    def test_no_sigma_rules(self, mock_fail):
        with tempfile.TemporaryDirectory() as tmpdir:
            trans_root = Path(tmpdir) / "platform-translations"
            trans_root.mkdir()
            (trans_root / "splunk-spl").mkdir()
            (trans_root / "crowdstrike-logscale").mkdir()
            
            rules_root = Path(tmpdir) / "rules" / "sigma"
            rules_root.mkdir(parents=True)
            
            sys.argv = ["validate_queries.py", str(trans_root), str(rules_root)]
            assert main() == 1
            mock_fail.assert_called()

    def test_valid_setup(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            trans_root = Path(tmpdir) / "platform-translations"
            trans_root.mkdir()
            (trans_root / "splunk-spl").mkdir()
            (trans_root / "crowdstrike-logscale").mkdir()
            
            rules_root = Path(tmpdir) / "rules" / "sigma"
            rules_root.mkdir(parents=True)
            
            rule_file = rules_root / "test.yml"
            rule_file.write_text("title: Test\nid: 1\nstatus: experimental\nlogsource:\n  category: test\ndetection:\n  sel:\n    f: v\n  condition: sel")
            
            (trans_root / "splunk-spl" / "test.spl").write_text('index="main" sourcetype="test" field=value')
            (trans_root / "crowdstrike-logscale" / "test.cql").write_text('field=/value/i')
            
            sys.argv = ["validate_queries.py", str(trans_root), str(rules_root)]
            assert main() == 0

    def test_missing_spl(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            trans_root = Path(tmpdir) / "platform-translations"
            trans_root.mkdir()
            (trans_root / "splunk-spl").mkdir()
            (trans_root / "crowdstrike-logscale").mkdir()
            
            rules_root = Path(tmpdir) / "rules" / "sigma"
            rules_root.mkdir(parents=True)
            
            rule_file = rules_root / "test.yml"
            rule_file.write_text("title: Test\nid: 1\nstatus: experimental\nlogsource:\n  category: test\ndetection:\n  sel:\n    f: v\n  condition: sel")
            
            (trans_root / "crowdstrike-logscale" / "test.cql").write_text('field=/value/i')
            
            sys.argv = ["validate_queries.py", str(trans_root), str(rules_root)]
            assert main() == 1

    def test_missing_cql(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            trans_root = Path(tmpdir) / "platform-translations"
            trans_root.mkdir()
            (trans_root / "splunk-spl").mkdir()
            (trans_root / "crowdstrike-logscale").mkdir()
            
            rules_root = Path(tmpdir) / "rules" / "sigma"
            rules_root.mkdir(parents=True)
            
            rule_file = rules_root / "test.yml"
            rule_file.write_text("title: Test\nid: 1\nstatus: experimental\nlogsource:\n  category: test\ndetection:\n  sel:\n    f: v\n  condition: sel")
            
            (trans_root / "splunk-spl" / "test.spl").write_text('index="main" sourcetype="test" field=value')
            
            sys.argv = ["validate_queries.py", str(trans_root), str(rules_root)]
            assert main() == 1

    def test_orphaned_spl(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            trans_root = Path(tmpdir) / "platform-translations"
            trans_root.mkdir()
            (trans_root / "splunk-spl").mkdir()
            (trans_root / "crowdstrike-logscale").mkdir()
            
            rules_root = Path(tmpdir) / "rules" / "sigma"
            rules_root.mkdir(parents=True)
            
            rule_file = rules_root / "test.yml"
            rule_file.write_text("title: Test\nid: 1\nstatus: experimental\nlogsource:\n  category: test\ndetection:\n  sel:\n    f: v\n  condition: sel")
            
            (trans_root / "splunk-spl" / "test.spl").write_text('index="main" sourcetype="test" field=value')
            (trans_root / "crowdstrike-logscale" / "test.cql").write_text('field=/value/i')
            (trans_root / "splunk-spl" / "orphan.spl").write_text('index="main" sourcetype="test" field=value')
            
            sys.argv = ["validate_queries.py", str(trans_root), str(rules_root)]
            assert main() == 1

    def test_orphaned_cql(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            trans_root = Path(tmpdir) / "platform-translations"
            trans_root.mkdir()
            (trans_root / "splunk-spl").mkdir()
            (trans_root / "crowdstrike-logscale").mkdir()
            
            rules_root = Path(tmpdir) / "rules" / "sigma"
            rules_root.mkdir(parents=True)
            
            rule_file = rules_root / "test.yml"
            rule_file.write_text("title: Test\nid: 1\nstatus: experimental\nlogsource:\n  category: test\ndetection:\n  sel:\n    f: v\n  condition: sel")
            
            (trans_root / "splunk-spl" / "test.spl").write_text('index="main" sourcetype="test" field=value')
            (trans_root / "crowdstrike-logscale" / "test.cql").write_text('field=/value/i')
            (trans_root / "crowdstrike-logscale" / "orphan.cql").write_text('field=/value/i')
            
            sys.argv = ["validate_queries.py", str(trans_root), str(rules_root)]
            assert main() == 1

    def test_empty_output_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            trans_root = Path(tmpdir) / "platform-translations"
            trans_root.mkdir()
            (trans_root / "splunk-spl").mkdir()
            (trans_root / "crowdstrike-logscale").mkdir()
            
            rules_root = Path(tmpdir) / "rules" / "sigma"
            rules_root.mkdir(parents=True)
            
            rule_file = rules_root / "test.yml"
            rule_file.write_text("title: Test\nid: 1\nstatus: experimental\nlogsource:\n  category: test\ndetection:\n  sel:\n    f: v\n  condition: sel")
            
            (trans_root / "splunk-spl" / "test.spl").write_text('')
            (trans_root / "crowdstrike-logscale" / "test.cql").write_text('field=/value/i')
            
            sys.argv = ["validate_queries.py", str(trans_root), str(rules_root)]
            assert main() == 1

    def test_invalid_cql_regex(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            trans_root = Path(tmpdir) / "platform-translations"
            trans_root.mkdir()
            (trans_root / "splunk-spl").mkdir()
            (trans_root / "crowdstrike-logscale").mkdir()
            
            rules_root = Path(tmpdir) / "rules" / "sigma"
            rules_root.mkdir(parents=True)
            
            rule_file = rules_root / "test.yml"
            rule_file.write_text("title: Test\nid: 1\nstatus: experimental\nlogsource:\n  category: test\ndetection:\n  sel:\n    f: v\n  condition: sel")
            
            (trans_root / "splunk-spl" / "test.spl").write_text('index="main" sourcetype="test" field=value')
            (trans_root / "crowdstrike-logscale" / "test.cql").write_text('field=/unterminated')
            
            sys.argv = ["validate_queries.py", str(trans_root), str(rules_root)]
            assert main() == 1

    def test_invalid_spl_missing_index(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            trans_root = Path(tmpdir) / "platform-translations"
            trans_root.mkdir()
            (trans_root / "splunk-spl").mkdir()
            (trans_root / "crowdstrike-logscale").mkdir()
            
            rules_root = Path(tmpdir) / "rules" / "sigma"
            rules_root.mkdir(parents=True)
            
            rule_file = rules_root / "test.yml"
            rule_file.write_text("title: Test\nid: 1\nstatus: experimental\nlogsource:\n  category: test\ndetection:\n  sel:\n    f: v\n  condition: sel")
            
            (trans_root / "splunk-spl" / "test.spl").write_text('sourcetype="test" field=value')
            (trans_root / "crowdstrike-logscale" / "test.cql").write_text('field=/value/i')
            
            sys.argv = ["validate_queries.py", str(trans_root), str(rules_root)]
            assert main() == 1