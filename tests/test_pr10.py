"""ПР-10: ошибка поймана и отпущена молча. Положительные и отрицательные примеры.

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


def test_bare_return_is_a_finding(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        @НаСервере
        метод Отправить(Чат: Число)
            попытка
                Телеграм.Отправить("код", Чат)
            поймать Исключение: ИсключениеНедопустимоеСостояние
                возврат
            ;
        ;
    """)
    assert rc == 1
    assert [(f["rule"], f["line"]) for f in found] == [('ПР-10', 5)]


def test_continue_in_loop_is_a_finding(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        @НаСервере
        метод Удалить(Номера: Массив<Число>)
            для Номер из Номера
                попытка
                    Телеграм.Удалить(Номер)
                поймать Исключение: Исключение
                    продолжить
                ;
            ;
        ;
    """)
    assert rc == 1
    assert [(f["rule"], f["line"]) for f in found] == [('ПР-10', 6)]


def test_empty_body_is_a_finding(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        метод Проверить()
            попытка
                Сделать()
            поймать Искл: Исключение
            ;
        ;
    """)
    assert rc == 1
    assert [(f["rule"], f["line"]) for f in found] == [('ПР-10', 4)]


def test_comment_explains(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        метод Проверить()
            попытка
                Сделать()
            поймать Исключение: Исключение
                //испорченный идентификатор пропускается
            ;
        ;
    """)
    assert (rc, found) == (0, [])


def test_fallback_value_is_not_a_finding(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        метод Ид(Строка: Строка): Ууид?
            попытка
                возврат новый Ууид(Строка)
            поймать Исключение: Исключение
                возврат Неопределено
            ;
        ;
    """)
    assert (rc, found) == (0, [])


def test_rethrow_and_log_are_not_findings(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        метод Проверить()
            попытка
                Сделать()
            поймать Исключение: ИсключениеHttp
                ЖурналСобытий.Записать(Исключение.Описание)
            поймать Исключение: Исключение
                выбросить Исключение
            ;
        ;
    """)
    assert (rc, found) == (0, [])


def test_each_catch_is_checked(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        метод Проверить()
            попытка
                Сделать()
            поймать Исключение: ИсключениеHttp
                ЖурналСобытий.Записать(Исключение.Описание)
            поймать Исключение: Исключение
                возврат
            ;
        ;
    """)
    assert rc == 1
    assert [(f["rule"], f["line"]) for f in found] == [('ПР-10', 6)]


def test_finally_ends_catch_body(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        метод Проверить()
            попытка
                Сделать()
            поймать Исключение: Исключение
                возврат
            вконце
                Закрыть()
            ;
        ;
    """)
    assert rc == 1
    assert [(f["rule"], f["line"]) for f in found] == [('ПР-10', 4)]


def test_nested_try_in_catch(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        метод Проверить()
            попытка
                Сделать()
            поймать Исключение: Исключение
                попытка
                    Записать(Исключение)
                поймать Вложенное: Исключение
                    возврат
                ;
            ;
        ;
    """)
    assert rc == 1
    assert [(f["rule"], f["line"]) for f in found] == [('ПР-10', 7)]
