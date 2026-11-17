"""ПР-26: ответ HTTP-сервиса с данными без Cache-Control: no-store. Положительные и отрицательные примеры."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from xbsl_sonar import cli, data

HELP = Path(__file__).parent / "help"

SERVICE_YAML = """\
ВидЭлемента: HttpСервис
Ид: 00000000-0000-4000-8000-000000000001
Имя: Сервис
КорневойUrl: svc
ШаблоныUrl:
    -
        Имя: data
        Шаблон: /data
        ЛюбойМетод: Данные
"""

MODULE_YAML = """\
ВидЭлемента: ОбщийМодуль
Ид: 00000000-0000-4000-8000-000000000002
Имя: Сервис
"""


@pytest.fixture(scope="session")
def data_dir(tmp_path_factory) -> Path:
    return data.build(HELP, tmp_path_factory.mktemp("data"))


def check(tmp_path, monkeypatch, data_dir, code: str, yaml: str = SERVICE_YAML) -> tuple[int, list[dict]]:
    module = tmp_path / "IT" / "Проект" / "Основное" / "Сервис.xbsl"
    module.parent.mkdir(parents=True)
    module.write_text(textwrap.dedent(code).lstrip(), encoding="utf-8")
    module.with_suffix(".yaml").write_text(yaml, encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    rc = cli.main(["check", "IT", "--data-dir", str(data_dir), "--json", "находки.json",
                   "--rules", "ПР-26"])
    found = json.loads((tmp_path / "находки.json").read_text(encoding="utf-8"))["findings"]
    return rc, found


def lines(found: list[dict]) -> list[tuple[str, int]]:
    return [(f["rule"], f["line"]) for f in found]


def test_json_body_without_no_store_is_a_finding(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        метод Данные(Запрос: HttpСервисЗапрос)
            пер Ответ = Запрос.Ответ
            пер ДанныеСообщения = новый Соответствие<Строка, Строка>()
            ДанныеСообщения.Вставить("result", "Ok")
            Ответ.УстановитьТело(СериализацияJson.ЗаписатьОбъект(ДанныеСообщения))
        ;
    """)
    assert rc == 1
    assert lines(found) == [("ПР-26", 5)]
    assert "no-store" in found[0]["message"]


def test_string_body_and_data_variable_are_findings(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        метод Данные(Запрос: HttpСервисЗапрос)
            Запрос.Ответ.УстановитьТело("Пользователь: %{Запрос.Параметры.ПолучитьПервый("id")}")
        ;

        метод Отдать(Запрос: HttpСервисЗапрос, Данные: Объект)
            знч Тело = СериализацияJson.ЗаписатьОбъект(Данные)
            Запрос.Ответ.Заголовки.Установить("Content-Type", "application/json")
            Запрос.Ответ.УстановитьТело(Тело)
        ;
    """)
    assert lines(found) == [("ПР-26", 2), ("ПР-26", 8)]


def test_no_store_in_the_same_method_is_not_a_finding(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        метод ОтветитьJson(Запрос: HttpСервисЗапрос, Данные: Объект?)
            Запрос.Ответ.Заголовки.Установить("Content-Type", "application/json; charset=utf-8")
            Запрос.Ответ.Заголовки.Установить("Cache-Control", "no-store")
            Запрос.Ответ.УстановитьТело(СериализацияJson.ЗаписатьОбъект(Данные))
        ;

        метод Позже(Запрос: HttpСервисЗапрос)
            Запрос.Ответ.УстановитьТело("{}")
            Запрос.Ответ.Заголовки.Установить("Cache-Control", "private, no-store, max-age=0")
        ;
    """)
    assert rc == 0
    assert found == []


def test_file_body_is_not_a_finding(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        метод Картинка(Запрос: HttpСервисЗапрос)
            знч Файл = Хранилище.Файл(Запрос.Параметры.ПолучитьПервый("id"))
            Запрос.Ответ.Заголовки.Установить("Content-Type", "image/png")
            Запрос.Ответ.УстановитьТело(Файл!)
        ;
    """)
    assert found == []


def test_http_client_request_body_is_not_a_finding(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        метод Данные(Запрос: HttpСервисЗапрос)
            знч Ответ = КлиентHttp.СТаймаутомЗапроса(15с).ЗапросPost("https://example.org").УстановитьТело("{}").Выполнить()
        ;
    """)
    assert found == []


def test_module_of_other_kind_is_not_checked(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        метод УстановитьОтветJSON(Запрос: HttpСервисЗапрос, ДанныеОтвета: Соответствие<Строка, Объект?>)
            Запрос.Ответ.УстановитьТело(СериализацияJson.ЗаписатьОбъект(ДанныеОтвета))
        ;
    """, yaml=MODULE_YAML)
    assert found == []
