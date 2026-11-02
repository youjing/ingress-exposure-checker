import pytest
from unittest.mock import patch
from iec.models import AuthStatus
from iec.cli import main, build_parser


def test_cli_refuses_without_authorized():
    with patch("sys.argv", ["iec", "targets.txt"]):
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code != 0


def test_cli_help_shows_authorized_flag(capsys):
    with patch("sys.argv", ["iec", "--help"]):
        with pytest.raises(SystemExit):
            main()
    out = capsys.readouterr().out
    assert "--authorized" in out


def test_cli_missing_file_friendly_error(capsys):
    with patch("sys.argv", ["iec", "nonexistent-file.txt", "--authorized"]):
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 3
        err = capsys.readouterr().err
        assert "输入文件不存在" in err
        assert "Traceback" not in err


def _patch_scan(monkeypatch, status):
    from iec.models import Target, ScanResult, AuthStatus
    async def fake_scan_all(targets, **kwargs):
        return [ScanResult(target=targets[0], auth_status=status, evidence=["x"])]
    monkeypatch.setattr("iec.cli.scan_all", fake_scan_all)


def test_cli_exit_zero_ignores_findings(monkeypatch, capsys, tmp_path):
    _patch_scan(monkeypatch, AuthStatus.EXPOSED_DEFAULT_CREDS)
    argv = ["iec", "--url", "http://x.example.com", "--authorized", "--exit-zero",
            "--no-report", "--output-html", str(tmp_path / "h"), "--output-md", str(tmp_path / "m")]
    with patch("sys.argv", argv):
        with pytest.raises(SystemExit) as exc:
            main()
    assert exc.value.code == 0
    assert "--exit-zero" in capsys.readouterr().out


def test_cli_without_exit_zero_exits_high(monkeypatch, tmp_path):
    _patch_scan(monkeypatch, AuthStatus.EXPOSED_DEFAULT_CREDS)
    argv = ["iec", "--url", "http://x.example.com", "--authorized",
            "--no-report", "--output-html", str(tmp_path / "h"), "--output-md", str(tmp_path / "m")]
    with patch("sys.argv", argv):
        with pytest.raises(SystemExit) as exc:
            main()
    assert exc.value.code == 1
