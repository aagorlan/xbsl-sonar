"""ПР-15: обращение к данным в цикле. Положительные и отрицательные примеры.

Данные о языке строятся из `tests/help` — таблицы пар ключевых слов в том виде, в каком
её отдаёт выгрузка справки (только сами слова, без текста справки).
"""

from __future__ import annotations

import json
import re
import textwrap
from pathlib import Path

import pytest

from xbsl_sonar import cli, data, report

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
                   "--bsl-report", "отчёт.json"])
    found = json.loads((tmp_path / "находки.json").read_text(encoding="utf-8"))["findings"]
    return rc, found


def test_query_in_for_body(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        @НаСервере
        метод Проверить(Участники: Массив<Строка>)
            для Участник из Участники
                знч Настройки = Запрос{ВЫБРАТЬ ПЕРВЫЕ 1
                    Т.Ссылка КАК Ссылка
                ИЗ
                    Т КАК Т
                ГДЕ
                    Т.Имя == %Участник}.Выполнить()
            ;
        ;
    """)
    assert rc == 1
    assert [(f["rule"], f["line"]) for f in found] == [("ПР-15", 4)]


def test_query_in_loop_header_is_not_a_finding(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        @НаСервере
        метод Описания(): Массив<Строка>
            знч Результат = новый Массив<Строка>()
            для Стр из Запрос{
                ВЫБРАТЬ
                    Т.Наименование КАК Наименование
                ИЗ
                    Т КАК Т
            }.Выполнить()
                Результат.Добавить(Стр.Наименование)
            ;
            возврат Результат
        ;
    """)
    assert (rc, found) == (0, [])


def test_query_in_while_loop_is_not_a_finding(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        @НаСервере
        метод Очистить()
            пока Истина
                знч Порция = Запрос{ВЫБРАТЬ ПЕРВЫЕ 200 Т.Ссылка КАК Ссылка ИЗ Т КАК Т}.Выполнить()
                если Порция.Пусто()
                    прервать
                ;
            ;
        ;
    """)
    assert (rc, found) == (0, [])


def test_write_in_loop_is_not_a_finding(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        @НаСервере
        метод Записать(Ссылки: Массив<Т.Ссылка>)
            для Ссылка из Ссылки
                Ссылка.ЗагрузитьОбъект().Записать()
            ;
        ;
    """)
    assert (rc, found) == (0, [])


def test_query_after_else_if_inside_loop_keeps_block_balance(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        @НаСервере
        метод Разобрать(Объекты: Массив<Строка>)
            для Объект из Объекты
                если Объект == "а"
                    возврат
                иначе если Объект == "б"
                    возврат
                ;
            ;
            знч Итог = Запрос{ВЫБРАТЬ Т.Ссылка КАК Ссылка ИЗ Т КАК Т}.Выполнить()
        ;
    """)
    assert (rc, found) == (0, [])


def test_server_call_in_client_loop(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        @НаКлиенте
        метод Показать(Строки: Массив<Строка>)
            для Стр из Строки
                знч Описание = ОписаниеНаСервере(Стр)
            ;
        ;

        @НаСервере @ДоступноСКлиента
        метод ОписаниеНаСервере(Стр: Строка): Строка
            возврат Стр
        ;
    """)
    assert rc == 1
    assert [(f["rule"], f["line"]) for f in found] == [("ПР-15", 4)]


def test_server_call_in_client_loop_header_is_not_a_finding(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        @НаКлиенте
        метод Показать()
            для Событие из СобытияНаСервере()
                Сообщить(Событие)
            ;
        ;

        @НаСервере @ДоступноСКлиента
        метод СобытияНаСервере(): Массив<Строка>
            возврат новый Массив<Строка>()
        ;
    """)
    assert (rc, found) == (0, [])


def test_exception_mark_above_the_line(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        @НаСервере
        метод Проверить(Участники: Массив<Строка>)
            для Участник из Участники
                // анализ:исключение ПР-15 ТД-7 — разовая обработка десятка записей
                знч Настройки = Запрос{ВЫБРАТЬ Т.Ссылка КАК Ссылка ИЗ Т КАК Т ГДЕ Т.Имя == %Участник}.Выполнить()
            ;
        ;
    """)
    assert rc == 0
    assert [(f["debt"], f["reason"]) for f in found] == [("ТД-7", "разовая обработка десятка записей")]
    bsl = json.loads((tmp_path / "отчёт.json").read_text(encoding="utf-8"))
    diag = bsl["fileinfos"][0]["diagnostics"][0]
    assert diag["severity"] == "Hint" and diag["code"] == "PR-15" and diag["source"] == "universal-rules"
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", bsl["date"])


def test_mark_for_another_rule_does_not_apply(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        @НаСервере
        метод Проверить(Участники: Массив<Строка>)
            для Участник из Участники
                // анализ:исключение ПР-01 ТД-7 — другое правило
                знч Настройки = Запрос{ВЫБРАТЬ Т.Ссылка КАК Ссылка ИЗ Т КАК Т ГДЕ Т.Имя == %Участник}.Выполнить()
            ;
        ;
    """)
    assert rc == 1 and found[0]["debt"] is None


def test_rules_file_matches_plugin_format():
    rules = report.rules_file()["rules"]
    assert [r["code"] for r in rules] == ["PR-01", "PR-15"]
    assert set(rules[0]) == {"code", "name", "description", "type", "severity", "active",
                             "needForCertificate", "effortMinutes", "internalCode"}
