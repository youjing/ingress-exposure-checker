import pytest
from pathlib import Path
from iec.input import parse_targets
from iec.models import Target

def _write(tmp_path, name, content):
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p

class TestTxtInput:
    def test_parse_one_url_per_line(self, tmp_path):
        p = _write(tmp_path, "t.txt", "http://a.com\nhttp://b.com\n")
        targets = parse_targets(p)
        assert len(targets) == 2 and targets[0].url == "http://a.com" and targets[1].url == "http://b.com"
    def test_strips_blank_lines_and_whitespace(self, tmp_path):
        p = _write(tmp_path, "t.txt", "\n  http://a.com  \n\n")
        targets = parse_targets(p)
        assert len(targets) == 1 and targets[0].url == "http://a.com"
    def test_deduplicates(self, tmp_path):
        p = _write(tmp_path, "t.txt", "http://a.com\nhttp://a.com\n")
        assert len(parse_targets(p)) == 1
    def test_rejects_non_http_scheme(self, tmp_path):
        p = _write(tmp_path, "t.txt", "ftp://a.com\n")
        with pytest.raises(ValueError, match="http/https"):
            parse_targets(p)

class TestCsvInput:
    def test_csv_with_url_column(self, tmp_path):
        p = _write(tmp_path, "t.csv", "name,url\nfoo,http://a.com\nbar,http://b.com\n")
        ts = parse_targets(p)
        assert ts[0] == Target(url="http://a.com", name="foo") and ts[1].url == "http://b.com"
    def test_csv_url_only(self, tmp_path):
        p = _write(tmp_path, "t.csv", "url\nhttp://a.com\n")
        assert parse_targets(p)[0] == Target(url="http://a.com")

class TestSchemeNormalization:
    def test_adds_http_scheme_when_missing(self, tmp_path):
        p = _write(tmp_path, "t.txt", "example.com\n")
        assert parse_targets(p)[0].url == "http://example.com"
    def test_preserves_https(self, tmp_path):
        p = _write(tmp_path, "t.txt", "https://secure.com\n")
        assert parse_targets(p)[0].url == "https://secure.com"
