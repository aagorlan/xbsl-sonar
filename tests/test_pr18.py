"""ПР-18: ПОДОБНО с шаблоном от начала строки. Положительные и отрицательные примеры.

Данные о языке строятся из `tests/help` — таблицы пар ключевых слов в том виде, в каком
её отдаёт выгрузка справки (только сами слова, без текста справки).
"""

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


def check(tmp_path, monkeypatch, data_dir, code: str, name: str = "Модуль.xbsl") -> tuple[int, list[dict]]:
    module = tmp_path / "IT" / "Проект" / "Основное" / name
    module.parent.mkdir(parents=True)
    module.write_text(textwrap.dedent(code).lstrip(), encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    rc = cli.main(["check", "IT", "--data-dir", str(data_dir), "--json", "находки.json",
                   "--rules", "ПР-18"])
    found = json.loads((tmp_path / "находки.json").read_text(encoding="utf-8"))["findings"]
    return rc, found


def test_literal_with_leading_percent_is_a_finding(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        @НаСервере
        метод Найти(): Массив<Публикация.Ссылка>
            возврат Запрос{
                ВЫБРАТЬ Публикация.Ссылка КАК Ссылка
                ИЗ Публикация КАК Публикация
                ГДЕ Публикация.Заголовок ПОДОБНО "%релиз%"
            }.Выполнить().Преобразовать(Стр -> Стр.Ссылка)
        ;
    """)
    assert rc == 1
    assert [(f["rule"], f["line"]) for f in found] == [("ПР-18", 6)]


def test_leading_underscore_and_not_like_are_findings(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        @НаСервере
        метод Найти()
            знч Р = Запрос{
                ВЫБРАТЬ Т.Ссылка КАК Ссылка
                ИЗ Товары КАК Т
                ГДЕ Т.Код ПОДОБНО "_12"
                    И НЕ Т.Наименование ПОДОБНО "%старый"
            }.Выполнить()
        ;
    """)
    assert rc == 1
    assert [f["line"] for f in found] == [6, 7]


def test_parameter_assigned_with_leading_percent_is_a_finding(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        @НаСервере
        метод Найти(Текст: Строка)
            знч Шаблон = "%" + Текст + "%"
            знч Р = Запрос{
                ВЫБРАТЬ Т.Ссылка КАК Ссылка
                ИЗ Товары КАК Т
                ГДЕ Т.Наименование ПОДОБНО %Шаблон
            }.Выполнить()
        ;
    """)
    assert rc == 1
    assert [(f["line"], "Шаблон" in f["message"]) for f in found] == [(7, True)]


def test_inline_expression_with_leading_percent_is_a_finding(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        @НаСервере
        метод Найти(Текст: Строка)
            знч Р = Запрос{
                ВЫБРАТЬ Т.Ссылка КАК Ссылка
                ИЗ Товары КАК Т
                ГДЕ Т.Наименование ПОДОБНО %{"%" + Текст}
            }.Выполнить()
        ;
    """)
    assert rc == 1
    assert [f["line"] for f in found] == [6]


def test_query_file_is_checked(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        ВЫБРАТЬ Т.Ссылка КАК Ссылка
        ИЗ Товары КАК Т
        ГДЕ Т.Наименование ПОДОБНО "%а"
    """, name="Поиск.xbql")
    assert rc == 1
    assert [f["line"] for f in found] == [3]


def test_known_prefix_is_not_a_finding(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        @НаСервере
        метод Найти(Текст: Строка)
            знч Шаблон = Текст + "%"
            знч Р = Запрос{
                ВЫБРАТЬ Т.Ссылка КАК Ссылка
                ИЗ Товары КАК Т
                ГДЕ Т.Наименование ПОДОБНО "Версия%"
                    ИЛИ Т.Код ПОДОБНО %Шаблон
            }.Выполнить()
        ;
    """)
    assert rc == 0
    assert found == []


def test_unknown_parameter_and_text_outside_query_are_not_findings(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        //Поиск ПОДОБНО "%…" медленный — здесь Содержит() вне запроса
        @НаСервере
        метод Найти(Шаблон: Строка, Текст: Строка): Булево
            знч Р = Запрос{
                ВЫБРАТЬ Т.Ссылка КАК Ссылка
                ИЗ Товары КАК Т
                ГДЕ Т.Наименование ПОДОБНО %Шаблон
                // раньше было ПОДОБНО "%а"
            }.Выполнить()
            возврат Текст.Содержит("а")
        ;
    """)
    assert rc == 0
    assert found == []
