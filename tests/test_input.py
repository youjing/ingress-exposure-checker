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

class TestIngressTableInput:
    @staticmethod
    def _row(ns, name, host, path, ports):
        return f"{ns:<25} {name:<40} {host:<30} {path:<60} {ports:<10}\n"

    INGRESS_TABLE = (
        _row.__func__("NAMESPACE", "NAME", "HOSTS", "PATHS", "PORTS")
        + _row.__func__("ns-demo", "nacos-test", "chart-example.local", "/nacos", "80")
        + _row.__func__("team-a", "audit-backend", "api.example.com", "/api/v1/audit", "80, 443")
        + _row.__func__("team-a", "platform-ui", "admin.platform.example.internal", "/", "80")
        + _row.__func__("ns-observ", "grafana-ingress", "demo.example.com", "/grafana(/|$)(.*)", "80, 443")
    )

    def test_ingress_table_parses_targets(self, tmp_path):
        p = _write(tmp_path, "ingress.txt", self.INGRESS_TABLE)
        targets = parse_targets(p)
        assert len(targets) == 4

    def test_ingress_table_extracts_namespace(self, tmp_path):
        p = _write(tmp_path, "ingress.txt", self.INGRESS_TABLE)
        targets = parse_targets(p)
        assert targets[0].namespace == "ns-demo"
        assert targets[1].namespace == "team-a"

    def test_ingress_table_https_on_443(self, tmp_path):
        p = _write(tmp_path, "ingress.txt", self.INGRESS_TABLE)
        targets = parse_targets(p)
        assert targets[1].url.startswith("https://")  # has 443
        assert targets[1].url == "https://api.example.com/api/v1/audit"

    def test_ingress_table_http_without_443(self, tmp_path):
        p = _write(tmp_path, "ingress.txt", self.INGRESS_TABLE)
        targets = parse_targets(p)
        assert targets[0].url.startswith("http://")  # only 80
        assert targets[0].url == "http://chart-example.local/nacos"

    def test_ingress_table_empty_path_becomes_root(self, tmp_path):
        p = _write(tmp_path, "ingress.txt", self.INGRESS_TABLE)
        targets = parse_targets(p)
        assert targets[2].url == "http://admin.platform.example.internal/"

    def test_ingress_table_preserves_name(self, tmp_path):
        p = _write(tmp_path, "ingress.txt", self.INGRESS_TABLE)
        targets = parse_targets(p)
        assert targets[0].name == "nacos-test"
        assert targets[3].name == "grafana-ingress"

    def test_ingress_table_not_matched_as_plain_txt(self, tmp_path):
        # A plain URL file should still parse as TXT, not ingress table
        p = _write(tmp_path, "t.txt", "http://a.com\nhttp://b.com\n")
        targets = parse_targets(p)
        assert len(targets) == 2
