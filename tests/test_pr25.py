"""ПР-25: внешний HTTP-запрос без предела ожидания. Положительные и отрицательные примеры.

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
                   "--rules", "ПР-25"])
    found = json.loads((tmp_path / "находки.json").read_text(encoding="utf-8"))["findings"]
    return rc, found


def lines(found: list[dict]) -> list[tuple[str, int]]:
    return [(f["rule"], f["line"]) for f in found]


def test_chain_without_timeout_is_a_finding(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        метод Отправить(Токен: Строка): ОтветHttp?
            попытка
                возврат КлиентHttp.СБазовымUrl("https://api.example.org")
                    .ЗапросPost("/bot%Токен/sendMessage")
                    .УстановитьТело("{}")
                    .Выполнить()
            поймать Исключение: ИсключениеHttp
                возврат Неопределено
            ;
        ;
    """)
    assert rc == 1
    assert lines(found) == [("ПР-25", 3)]
    assert "предела ожидания" in found[0]["message"]


def test_request_in_variable_without_timeout_is_a_finding(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        метод Спросить(Адрес: Строка): Строка
            пер Запрос = КлиентHttp.ЗапросPost(Адрес)
                .УстановитьЗаголовок("Content-Type", "application/json")
            Запрос = Запрос.УстановитьЗаголовок("X-Id", "1")
            исп Ответ = Запрос.Выполнить()
            возврат Ответ.Тело.ПрочитатьКакСтроку()
        ;
    """)
    assert lines(found) == [("ПР-25", 5)]


def test_connection_timeout_alone_is_a_finding(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        метод Проверить()
            знч Ответ = КлиентHttp.СТаймаутомСоединения(5с).ЗапросGet("https://example.org").Выполнить()
        ;
    """)
    assert lines(found) == [("ПР-25", 2)]


def test_timeouts_on_client_or_request_are_not_findings(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        метод НаКлиенте(): ОтветHttp
            возврат КлиентHttp.СТаймаутомЗапроса(15с).ЗапросGet("https://example.org").Выполнить()
        ;

        метод НаЗапросе(Адрес: Строка, Таймаут: Длительность): Строка
            пер Запрос = КлиентHttp.ЗапросPost(Адрес)
                .УстановитьТаймаутЗапроса(Таймаут)
                .УстановитьТело("{}")
            Запрос = Запрос.УстановитьЗаголовок("X-Id", "1")
            исп Ответ = Запрос.Выполнить()
            возврат Ответ.Тело.ПрочитатьКакСтроку()
        ;

        метод КлиентВПеременной(): ОтветHttp
            знч Клиент = КлиентHttp.СБазовымUrl("https://example.org").СТаймаутомЗапроса(10с)
            возврат Клиент.ЗапросGet("/x").Выполнить()
        ;
    """)
    assert rc == 0
    assert found == []


def test_query_execute_is_not_a_finding(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        метод Посчитать(): Число
            знч Запрос = новый Запрос("ВЫБРАТЬ 1 КАК Один")
            исп Итог = Запрос.Выполнить()
            исп Строки = Запрос{
                ВЫБРАТЬ 1 КАК Один
            }.Выполнить()
            возврат 1
        ;
    """)
    assert found == []


def test_variable_reused_for_query_is_not_a_finding(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        метод Дважды()
            пер Запрос = КлиентHttp.СТаймаутомЗапроса(5с).ЗапросGet("https://example.org")
            Запрос.Выполнить()
            Запрос = новый ПостроительЗапроса()
            Запрос.Выполнить()
        ;
    """)
    assert found == []
