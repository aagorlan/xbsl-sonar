"""ПР-27: секрет сравнивается не за постоянное время. Положительные и отрицательные примеры."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from xbsl_sonar import cli, data

HELP = Path(__file__).parent / "help"

MODULE_YAML = """\
ВидЭлемента: ОбщийМодуль
Ид: 00000000-0000-4000-8000-000000000002
Имя: Сервис
"""


@pytest.fixture(scope="session")
def data_dir(tmp_path_factory) -> Path:
    return data.build(HELP, tmp_path_factory.mktemp("data"))


def check(tmp_path, monkeypatch, data_dir, code: str) -> tuple[int, list[dict]]:
    module = tmp_path / "IT" / "Проект" / "Основное" / "Сервис.xbsl"
    module.parent.mkdir(parents=True)
    module.write_text(textwrap.dedent(code).lstrip(), encoding="utf-8")
    module.with_suffix(".yaml").write_text(MODULE_YAML, encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    rc = cli.main(["check", "IT", "--data-dir", str(data_dir), "--json", "находки.json",
                   "--rules", "ПР-27"])
    found = json.loads((tmp_path / "находки.json").read_text(encoding="utf-8"))["findings"]
    return rc, found


def lines(found: list[dict]) -> list[tuple[str, int]]:
    return [(f["rule"], f["line"]) for f in found]


def test_header_compared_with_setting_through_variables(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        метод Допущен(Запрос: HttpСервисЗапрос): Булево
            знч Эталон = ПараметрыСистемы.ТокенСтатистики()
            знч Полученный = Запрос.Заголовки.ПолучитьПервый("X-Token") ?? ""
            возврат не Эталон.Пусто() и Полученный == Эталон
        ;
    """)
    assert rc == 1
    assert lines(found) == [("ПР-27", 4)]
    assert "заголовка" in found[0]["message"]


def test_secret_named_variable_with_not_equal(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        метод Ping(Запрос: HttpСервисЗапрос)
            знч ПолученныйТокен = Запрос.Заголовки.ПолучитьПервый("X-Secret")
            знч ЭталонныйТокен = Настройки.Значение(ВидНастройки.Токен)
            если ПолученныйТокен != ЭталонныйТокен
                Запрос.Ответ.КодСтатуса = 401
            ;
        ;
    """)
    assert lines(found) == [("ПР-27", 4)]


def test_computed_signature_is_a_finding(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        метод Проверить(Ключ: Строка): Булево
            знч Части = Ключ.Разделить(".")
            если Части.Размер() != 2 или Подпись(Части[0]) != Части[1]
                возврат Ложь
            ;
            возврат Истина
        ;
    """)
    assert lines(found) == [("ПР-27", 3)]


def test_literals_length_and_emptiness_are_not_findings(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        метод Проверить(Запрос: HttpСервисЗапрос, Настройки: Объект)
            знч Ключ = Запрос.Заголовки.ПолучитьПервый("X-Key") ?? ""
            если Ключ == ""
                возврат
            ;
            знч ТокенЗадан = Настройки.Токен == "задан"
            если Настройки.ПарольОтправителя == Неопределено или Настройки.Токен.Длина() == 0
                возврат
            ;
        ;
    """)
    assert rc == 0
    assert found == []


def test_enum_value_and_interface_caption_are_not_findings(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        метод Выделить(Выбранная: Надпись, Вид: ВидНастройки)
            для Подпись из [Компоненты.НадписьОдин, Компоненты.НадписьДва]
                Подпись.Шрифт = Подпись == Выбранная ? СтилевыеШрифты.Крупный : СтилевыеШрифты.Мелкий
            ;
            если Вид == ВидНастройки.ТокенВходящихВызовов
                возврат
            ;
        ;
    """)
    assert found == []


def test_ordinary_comparisons_are_not_findings(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        метод Сравнить(Запрос: HttpСервисЗапрос, Беседа: Объект)
            знч Части = Запрос.Параметры.ПолучитьПервый("id").Разделить(".")
            если Части[1] != Беседа.Ид.ВСтроку()
                возврат
            ;
        ;
    """)
    assert found == []


def test_mark_suppresses_finding(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        метод Допущен(Запрос: HttpСервисЗапрос, Эталон: Строка): Булево
            знч Полученный = Запрос.Заголовки.ПолучитьПервый("X-Token") ?? ""
            // анализ:исключение ПР-27 ТД-1 — до перехода на сравнение HMAC
            возврат Полученный == Эталон
        ;
    """)
    assert rc == 0
