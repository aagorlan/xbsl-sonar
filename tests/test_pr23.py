"""ПР-23: секрет уходит на клиент. Положительные и отрицательные примеры."""

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
    module = tmp_path / "IT" / "Проект" / "Основное" / "Настройка.xbsl"
    module.parent.mkdir(parents=True)
    module.write_text(textwrap.dedent(code).lstrip(), encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    rc = cli.main(["check", "IT", "--data-dir", str(data_dir), "--json", "находки.json",
                   "--rules", "ПР-23"])
    found = json.loads((tmp_path / "находки.json").read_text(encoding="utf-8"))["findings"]
    return rc, found


def lines(found: list[dict]) -> list[tuple[str, int]]:
    return [(f["rule"], f["line"]) for f in found]


def test_returns_secret_setting(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        @НаСервере @ДоступноСКлиента
        статический метод ТокенНаСервере(): Строка
            ПроверитьПрава()
            возврат ПараметрыСистемы.ТокенСтатистики()
        ;
    """)
    assert rc == 1
    assert lines(found) == [("ПР-23", 4)]
    assert "ТокенНаСервере" in found[0]["message"]


def test_structure_field_gets_secret(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        @НаСервере @ДоступноСКлиента
        статический метод Прочитать(): Генерация.НастройкиОформления
            знч Настройки = Генерация.Настройки()
            возврат новый Генерация.НастройкиОформления(
                Адрес = Настройки.Адрес,
                Токен = Настройки.Токен)
        ;
    """)
    assert rc == 1
    assert lines(found) == [("ПР-23", 4)]
    assert "Токен" in found[0]["message"]


def test_variable_holding_secret(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        @НаСервере @ДоступноСКлиента
        статический метод Значение(): Строка
            знч Т = НастройкиПрограммы.ЗначениеНастройки(ВидНастройки.ТокенБота)
            возврат Т
        ;
    """)
    assert lines(found) == [("ПР-23", 4)]


def test_secret_in_branch_of_condition(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        @НаСервере @ДоступноСКлиента
        статический метод Значение(): Строка
            знч Н = Генерация.Настройки()
            возврат Н.Включена
                ? Н.Пароль
                : ""
        ;
    """)
    assert lines(found) == [("ПР-23", 4)]


def test_literal_branches_are_not_secret(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        @НаСервере @ДоступноСКлиента
        статический метод Прочитать(): Генерация.НастройкиОформления
            знч Настройки = Генерация.Настройки()
            возврат новый Генерация.НастройкиОформления(
                Адрес = Настройки.Адрес,
                Токен = Настройки.Токен.Пусто() ? "" : "задан")
        ;
    """)
    assert rc == 0
    assert found == []


def test_variable_named_secret_but_returns_other(tmp_path, monkeypatch, data_dir):
    _, found = check(tmp_path, monkeypatch, data_dir, """
        @НаСервере @ДоступноСКлиента
        статический метод СлепойТокен(): Строка
            знч Токен = НастройкиПрограммы.ЗначениеНастройки(ВидНастройки.ТокенБота)
            если Токен.Пусто()
                возврат ""
            ;
            возврат новый Ууид().ВСтроку()
        ;
    """)
    assert found == []


def test_boolean_and_application_secret_are_not_findings(tmp_path, monkeypatch, data_dir):
    _, found = check(tmp_path, monkeypatch, data_dir, """
        @НаСервере @ДоступноСКлиента
        статический метод ТокенЗадан(): Булево
            возврат не ПараметрыСистемы.ТокенСтатистики().Пусто()
        ;

        @НаСервере @ДоступноСКлиента
        статический метод Ключ(): СекретПриложения?
            возврат новый НастройкиПриложения.КлючЗаписи().ЗагрузитьЗапись()?.ПарольОтправителя
        ;

        @НаСервере @ДоступноСКлиента
        статический метод Запись(): НастройкиПочты.Запись
            возврат новый НастройкиПочты.Запись(Пароль = новый СекретПриложения(Ввод.Пароль))
        ;
    """)
    assert found == []


def test_method_not_available_from_client(tmp_path, monkeypatch, data_dir):
    _, found = check(tmp_path, monkeypatch, data_dir, """
        @НаСервере
        метод Токен(): Строка
            возврат ПараметрыСистемы.ТокенСтатистики()
        ;
    """)
    assert found == []


def test_parameter_from_client_is_not_secret_source(tmp_path, monkeypatch, data_dir):
    _, found = check(tmp_path, monkeypatch, data_dir, """
        @НаСервере @ДоступноСКлиента
        статический метод Записать(Токен: Строка): Строка
            ПараметрыСистемы.ЗаписатьТокен(Токен)
            возврат Токен
        ;
    """)
    assert found == []


def test_exception_mark(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        @НаСервере @ДоступноСКлиента
        статический метод ТокенНаСервере(): Строка
            // анализ:исключение ПР-23 ТД-1 — администратор копирует токен в буфер обмена
            возврат ПараметрыСистемы.ТокенСтатистики()
        ;
    """)
    assert rc == 0
    assert [f.get("debt") for f in found] == ["ТД-1"]
