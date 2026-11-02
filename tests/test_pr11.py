"""ПР-11: адрес HTTP-запроса из данных пользователя. Положительные и отрицательные примеры.

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
                   "--rules", "ПР-11"])
    found = json.loads((tmp_path / "находки.json").read_text(encoding="utf-8"))["findings"]
    return rc, found


def lines(found: list[dict]) -> list[tuple[str, int]]:
    return [(f["rule"], f["line"]) for f in found]


def test_client_parameter_as_url_is_a_finding(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        @НаСервере @ДоступноСКлиента
        метод ПроверитьСсылку(Адрес: Строка): Булево
            возврат КлиентHttp.ЗапросGet(Адрес).Выполнить().КодСостояния == 200
        ;
    """)
    assert rc == 1
    assert lines(found) == [("ПР-11", 3)]
    assert "Адрес" in found[0]["message"]


def test_client_parameter_through_local_variable_and_url_object(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        @НаСервере @ДоступноСКлиента
        метод Получить(Хост: Строка)
            знч Ссылка = новый Url("https://" + Хост)
            знч Ответ = КлиентHttp.ЗапросPost(Ссылка).Выполнить()
        ;
    """)
    assert rc == 1
    assert lines(found) == [("ПР-11", 4)]


def test_http_service_request_is_a_finding(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        @НаСервере
        метод ПриЗапросе(Запрос: HttpСервисЗапрос)
            знч Адрес = Запрос.Параметры.Получить("url")
            КлиентHttp.СБазовымUrl(Адрес).ЗапросGet("/").Выполнить()
        ;
    """)
    assert lines(found) == [("ПР-11", 4)]


def test_stored_field_is_a_finding(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        @НаСервере
        метод ПроверитьТрансляцию(Доклад: Доклад.Ссылка)
            знч ДокладОбъект = Доклад.ЗагрузитьОбъект()
            КлиентHttp.ЗапросHead(ДокладОбъект.СсылкаНаТрансляцию).Выполнить()
        ;
    """)
    assert lines(found) == [("ПР-11", 4)]


def test_create_request_second_argument(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        @НаСервере @ДоступноСКлиента
        метод Отправить(Метод: Строка, Адрес: Строка)
            КлиентHttp.СоздатьЗапрос("GET", Адрес).Выполнить()
            КлиентHttp.СоздатьЗапрос(Метод, "https://example.org").Выполнить()
        ;
    """)
    assert lines(found) == [("ПР-11", 3)]


def test_literal_and_method_without_parameters_are_not_findings(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        @НаСервере @ДоступноСКлиента
        метод Отправить(Токен: Строка, Текст: Строка)
            КлиентHttp.СБазовымUrl("https://api.telegram.org")
                .ЗапросPost("/bot%Токен/sendMessage")
                .УстановитьТело(Текст)
                .Выполнить()
            КлиентHttp.СБазовымUrl(АдресСервера()).ЗапросGet("/getMe").Выполнить()
        ;

        @НаСервере
        метод АдресСервера(): Строка
            возврат "https://api.telegram.org"
        ;
    """)
    assert rc == 0
    assert found == []


def test_server_parameter_without_client_access_is_not_a_finding(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        @НаСервере
        метод Загрузить(Адрес: Строка)
            знч Ссылка = новый Url(Адрес).СПутем("/путь")
            КлиентHttp.ЗапросGet(Ссылка).Выполнить()
        ;
    """)
    assert rc == 0
    assert found == []


def test_reference_method_call_is_not_a_stored_field(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        @НаСервере
        метод Получить()
            знч Ссылка = новый Url("http://адрес")
            КлиентHttp.ЗапросGet(Ссылка.СПутем("/путь/к/ресурсу")).Выполнить()
        ;
    """)
    assert found == []


def test_commented_call_is_not_a_finding(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        @НаСервере @ДоступноСКлиента
        метод Проверить(Адрес: Строка)
            // КлиентHttp.ЗапросGet(Адрес).Выполнить()
            возврат
        ;
    """)
    assert found == []



def test_fixed_host_with_user_path_is_not_a_finding(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        @НаСервере @ДоступноСКлиента
        метод Получить(Путь: Строка)
            КлиентHttp.ЗапросGet("https://example.org/" + Путь).Выполнить() // хост задан
        ;
    """)
    assert found == []


def test_user_url_after_fixed_base_is_a_finding(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        @НаСервере @ДоступноСКлиента
        метод Получить(Адрес: Строка)
            КлиентHttp.СБазовымUrl("https://example.org").ЗапросGet(Адрес).Выполнить()
        ;
    """)
    assert lines(found) == [("ПР-11", 3)]
