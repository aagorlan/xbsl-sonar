"""ПР-14: результат запроса не через `исп`. Положительные и отрицательные примеры."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from xbsl_sonar import cli, data

HELP = Path(__file__).parent / "help"


@pytest.fixture(scope="session")
def data_dir(tmp_path_factory) -> Path:
    return data.build(HELP, tmp_path_factory.mktemp("data"))


def check(tmp_path, monkeypatch, data_dir, code: str) -> tuple[int, list[dict]]:
    module = tmp_path / "IT" / "Проект" / "Основное" / "Модуль.xbsl"
    module.parent.mkdir(parents=True)
    module.write_text(textwrap.dedent(code).lstrip(), encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    rc = cli.main(["check", "IT", "--data-dir", str(data_dir), "--json", "находки.json",
                   "--rules", "ПР-14"])
    found = json.loads((tmp_path / "находки.json").read_text(encoding="utf-8"))["findings"]
    return rc, found


def lines(found: list[dict]) -> list[tuple[str, int]]:
    return [(f["rule"], f["line"]) for f in found]


def test_empty_check_on_result_is_a_finding(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        @НаСервере
        метод ЕстьПубликации(Участник: Участники.Ссылка): Булево
            возврат не Запрос{ВЫБРАТЬ ПЕРВЫЕ 1
                Публикация.Ссылка КАК Ссылка
            ИЗ
                Публикация КАК Публикация
            ГДЕ
                Публикация.Участник == %Участник}.Выполнить().Пусто()
        ;
    """)
    assert rc == 1
    assert lines(found) == [("ПР-14", 8)]


def test_disposed_result_is_not_a_finding(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        @НаСервере
        метод ЕстьПубликации(Участник: Участники.Ссылка): Булево
            исп Записи = Запрос{ВЫБРАТЬ ПЕРВЫЕ 1
                Публикация.Ссылка КАК Ссылка
            ИЗ
                Публикация КАК Публикация
            ГДЕ
                Публикация.Участник == %Участник}.Выполнить()
            возврат не Записи.Пусто()
        ;
    """)
    assert rc == 0
    assert found == []


def test_commented_out_line_is_not_a_finding(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        @НаСервере
        метод Проверить()
            //если Запрос{ВЫБРАТЬ 1}.Выполнить().Пусто()
        ;
    """)
    assert found == []
