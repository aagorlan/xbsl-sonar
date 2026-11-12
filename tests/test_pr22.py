"""ПР-22: HTTP-сервис открыт всем, а обработчик не проверяет допуск. Положительные и отрицательные примеры."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from xbsl_sonar import cli, data

HELP = Path(__file__).parent / "help"

OPEN_YAML = """\
ВидЭлемента: HttpСервис
Ид: 00000000-0000-4000-8000-000000000001
Имя: Сервис
КонтрольДоступа:
    Разрешения:
        Вызов: РазрешеноВсем
КорневойUrl: svc
ШаблоныUrl:
    -
        Имя: send
        Шаблон: /send
        ЛюбойМетод: Принять
"""


@pytest.fixture(scope="session")
def data_dir(tmp_path_factory) -> Path:
    return data.build(HELP, tmp_path_factory.mktemp("data"))


def check(tmp_path, monkeypatch, data_dir, code: str, yaml: str = OPEN_YAML) -> tuple[int, list[dict]]:
    module = tmp_path / "IT" / "Проект" / "Основное" / "Сервис.xbsl"
    module.parent.mkdir(parents=True)
    module.write_text(textwrap.dedent(code).lstrip(), encoding="utf-8")
    module.with_suffix(".yaml").write_text(yaml, encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    rc = cli.main(["check", "IT", "--data-dir", str(data_dir), "--json", "находки.json",
                   "--rules", "ПР-22"])
    found = json.loads((tmp_path / "находки.json").read_text(encoding="utf-8"))["findings"]
    return rc, found


def lines(found: list[dict]) -> list[tuple[str, int]]:
    return [(f["rule"], f["line"]) for f in found]


def test_open_handler_without_check(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        метод Принять(Запрос: HttpСервисЗапрос)
            если Запрос.Метод != "POST"
                Запрос.Ответ.КодСтатуса = 405
                возврат
            ;
            исп КонтекстДоступа.Привилегированный()
            Обработка.Выполнить(Запрос)
        ;
    """)
    assert rc == 1
    assert lines(found) == [("ПР-22", 1)]
    assert "Принять" in found[0]["message"]


def test_check_in_called_method(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        метод Принять(Запрос: HttpСервисЗапрос)
            если не Допущен(Запрос)
                Запрос.Ответ.КодСтатуса = 401
                возврат
            ;
            исп КонтекстДоступа.Привилегированный()
            Обработка.Выполнить(Запрос)
        ;

        @Локально
        метод Допущен(Запрос: HttpСервисЗапрос): Булево
            знч Полученный = Запрос.Заголовки.ПолучитьПервый("X-Token") ?? ""
            возврат Полученный == Настройки.Токен()
        ;
    """)
    assert (rc, found) == (0, [])


def test_check_and_denial_deep_in_module(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        метод Принять(Запрос: HttpСервисЗапрос)
            Обработать(Запрос)
        ;

        @Локально
        метод Обработать(Запрос: HttpСервисЗапрос)
            знч Ключ = Запрос.Заголовки.ПолучитьПервый("Authorization") ?? ""
            если Ключ == ""
                Отказать(Запрос, 401)
                возврат
            ;
            Обработка.Выполнить(Запрос)
        ;

        @Локально
        метод Отказать(Запрос: HttpСервисЗапрос, Код: Число)
            Запрос.Ответ.КодСтатуса = Код
        ;
    """)
    assert (rc, found) == (0, [])


def test_response_headers_are_not_a_check(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        метод Принять(Запрос: HttpСервисЗапрос)
            Запрос.Ответ.Заголовки.Установить("Content-Type", "application/json")
            Запрос.Ответ.УстановитьТело(СериализацияJson.ЗаписатьОбъект(Данные.Все()))
        ;
    """)
    assert rc == 1
    assert lines(found) == [("ПР-22", 1)]


def test_static_resource_is_not_a_finding(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        метод Принять(Запрос: HttpСервисЗапрос)
            знч Ответ = Запрос.Ответ
            Ответ.Заголовки.Добавить("Content-Type", "text/css")
            Ответ.УстановитьТело(Ресурс{стиль.css}.Ссылка)
        ;
    """)
    assert (rc, found) == (0, [])


def test_authenticated_template_is_not_checked(tmp_path, monkeypatch, data_dir):
    yaml = OPEN_YAML + """\
        КонтрольДоступа:
            Разрешения:
                Вызов: РазрешеноАутентифицированным
"""
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        метод Принять(Запрос: HttpСервисЗапрос)
            исп КонтекстДоступа.Привилегированный()
            Обработка.Выполнить(Запрос)
        ;
    """, yaml=yaml)
    assert (rc, found) == (0, [])


def test_method_rights_are_nearest(tmp_path, monkeypatch, data_dir):
    yaml = """\
ВидЭлемента: HttpСервис
Ид: 00000000-0000-4000-8000-000000000002
Имя: Сервис
КонтрольДоступа:
    Разрешения:
        Вызов: РазрешеноАутентифицированным
КорневойUrl: svc
ШаблоныUrl:
    -
        Имя: items
        Шаблон: /items
        Методы:
            -
                Метод: GET
                Обработчик: Список
            -
                Метод: POST
                Обработчик: Добавить
                КонтрольДоступа:
                    Разрешения:
                        Вызов: РазрешеноВсем
"""
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        метод Список(Запрос: HttpСервисЗапрос)
            Запрос.Ответ.УстановитьТело(Данные.Все())
        ;

        метод Добавить(Запрос: HttpСервисЗапрос)
            Данные.Добавить(Запрос.Тело.ПрочитатьКакСтроку())
        ;
    """, yaml=yaml)
    assert rc == 1
    assert lines(found) == [("ПР-22", 5)]


def test_exception_mark(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        // анализ:исключение ПР-22 ТД-1 — открыт намеренно
        метод Принять(Запрос: HttpСервисЗапрос)
            Данные.Добавить(Запрос.Тело.ПрочитатьКакСтроку())
        ;
    """)
    assert rc == 0
    assert [f.get("debt") for f in found] == ["ТД-1"]


def test_not_http_service(tmp_path, monkeypatch, data_dir):
    yaml = "ВидЭлемента: ОбщийМодуль\nИд: 00000000-0000-4000-8000-000000000003\nИмя: Сервис\n"
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        метод Принять(Запрос: HttpСервисЗапрос)
            исп КонтекстДоступа.Привилегированный()
        ;
    """, yaml=yaml)
    assert (rc, found) == (0, [])
