import pytest
from unittest.mock import patch
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
