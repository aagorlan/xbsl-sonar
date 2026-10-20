"""ПР-06: секрет строкой в коде. Положительные и отрицательные примеры."""

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


def check(tmp_path, monkeypatch, data_dir, files: dict[str, str]) -> tuple[int, list[dict]]:
    for name, code in files.items():
        path = tmp_path / "IT" / "Проект" / "Основное" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(code).lstrip(), encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    rc = cli.main(["check", "IT", "--data-dir", str(data_dir), "--rules", "ПР-06",
                   "--json", "находки.json"])
    found = json.loads((tmp_path / "находки.json").read_text(encoding="utf-8"))["findings"]
    return rc, found


def module(body: str) -> dict[str, str]:
    return {"Модуль.xbsl": "метод А()\n" + textwrap.indent(textwrap.dedent(body).strip(), "    ")
            + "\n;\n"}


def test_token_in_variable(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, module('''
        знч ТокенБота = "a8Fk2LmQ9zXw"
    '''))
    assert rc == 1
    assert [f["rule"] for f in found] == ["ПР-06"]
    assert "ТокенБота" in found[0]["message"]


def test_password_named_argument(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, module('''
        знч Вход = новый АутентификацияHttp(Пользователь = "bot", Пароль = "qwerty123")
    '''))
    assert rc == 1
    assert len(found) == 1 and "Пароль" in found[0]["message"]


def test_property_and_latin_name(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, module('''
        Настройки.ApiKey = "sk_live_51HxYzAbCdEf"
        Настройки.ПарольОтправителя = "Zx9-Pq7-Lm3"
    '''))
    assert rc == 1
    assert len(found) == 2


def test_map_key_with_literal_value(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, module('''
        Данные.Вставить("password", "Hunter2024!")
    '''))
    assert rc == 1
    assert len(found) == 1


def test_secret_shaped_literal_anywhere(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, module('''
        знч Адрес = "7012345678:AAHabcdefghijklmnopqrstuvwxyz012345"
        Заголовки.Вставить("Authorization", "Bearer eyJhbGciOiJIUzI1NiJ9abc")
    '''))
    assert rc == 1
    assert len(found) == 2


def test_yaml_default_of_secret_attribute(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, {"Настройки.yaml": """
        ВидЭлемента: Константа
        Имя: Настройки
        Реквизиты:
            -
                Имя: ТокенБота
                Тип: Строка
                ЗначениеПоУмолчанию: a8Fk2LmQ9zXwT
            -
                Имя: Подключение
                Тип: СекретПриложения?
                ЗначениеПоУмолчанию: "Zx9Pq7Lm3Wd"
            -
                Имя: Заголовок
                Тип: Строка
                ЗначениеПоУмолчанию: a8Fk2LmQ9zXwT
    """})
    assert rc == 1
    assert len(found) == 2
    assert {f["line"] for f in found} == {7, 11}


def test_not_secrets(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, module('''
        знч Вход = новый АутентификацияHttp(Пользователь = "AUTH_TOKEN", Пароль = Тикет())
        Данные.Вставить("secret_token", ТокенВходящегоВызова)
        знч Адрес = "/bot%{Токен()}/sendPhoto"
        ПолеПароль.СообщениеОшибка = "Обязательно для заполнения"
        знч ПодсказкаПароля = "Введите пароль"
        знч Пароль = ""
        знч ТокенЗаглушка = "abc"
        знч Токен = Префикс + "a8Fk2LmQ9zXw"
        знч СекретКлючей = Настройки.СекретКлючей
        если Пароль == "a8Fk2LmQ9zXw"
            возврат
        ;
    '''))
    assert rc == 0
    assert found == []


def test_yaml_expression_and_plain_attribute(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, {"Форма.yaml": """
        ВидЭлемента: КомпонентИнтерфейса
        Имя: Форма
        Свойства:
            -
                Имя: Пароль
                Тип: Строка
                ЗначениеПоУмолчанию: =Настройки.Пароль()
            -
                Имя: Адрес
                Тип: Строка
                ЗначениеПоУмолчанию: https-example-org
    """})
    assert rc == 0
    assert found == []
