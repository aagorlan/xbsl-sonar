"""Встроенный перечень ключевых слов: запуск без выгрузки справки."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from xbsl_sonar import cli, data
from xbsl_sonar.keywords import KEYWORDS

HELP = Path(__file__).parent / "help"

CODE = """
    @ВПроекте
    @НаСервере @ДоступноСКлиента
    статический метод ЗафиксироватьДоступ(Участник: Участники.Ссылка)
        знч НоваяЗапись = новый Журнал.Запись()
        НоваяЗапись.Участник = Участник
        исп КонтекстДоступа.Привилегированный()
        Журнал.Записать(НоваяЗапись)
    ;
"""


def run(tmp_path, monkeypatch, *source: str) -> list[tuple[str, int]]:
    module = tmp_path / "IT" / "Проект" / "Основное" / "Модуль.xbsl"
    module.parent.mkdir(parents=True, exist_ok=True)
    module.write_text(textwrap.dedent(CODE).lstrip(), encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    cli.main(["check", "IT", *source, "--rules", "ПР-01", "--json", "находки.json"])
    found = json.loads((tmp_path / "находки.json").read_text(encoding="utf-8"))["findings"]
    return [(f["rule"], f["line"]) for f in found]


def test_builtin_list_matches_help_table():
    assert list(KEYWORDS) == data.pairs_from_help(HELP / "topics" / "keywords" / "index.md")


def test_check_without_help_finds_the_same(tmp_path, monkeypatch):
    without = run(tmp_path / "без", monkeypatch)
    with_help = run(tmp_path / "со", monkeypatch, "--help-dir", str(HELP))
    assert without == with_help == [("ПР-01", 3)]


def test_data_without_help_builds_language(tmp_path):
    out = data.build(None, tmp_path)
    language = json.loads((out / data.VERSION / "language.json").read_text(encoding="utf-8"))
    assert language["meta"]["generated_from"] == "xbsl-sonar: встроенный перечень"
    assert language["keywords"]["METHOD"]["forms"] == ["метод", "method"]


def test_help_dir_without_table_is_an_error(tmp_path):
    with pytest.raises(SystemExit) as stop:
        data.build(tmp_path, tmp_path / "данные")
    assert "Нет таблицы ключевых слов справки" in str(stop.value)
