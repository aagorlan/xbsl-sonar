"""ПР-12: внешний JSON без проверки структуры. Положительные и отрицательные примеры.

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
                   "--rules", "ПР-12"])
    found = json.loads((tmp_path / "находки.json").read_text(encoding="utf-8"))["findings"]
    return rc, found


def lines(found: list[dict]) -> list[tuple[str, int]]:
    return [(f["rule"], f["line"]) for f in found]


def test_http_response_into_map_with_cast_is_a_finding(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        @НаСервере
        метод ОтправитьСообщение(Запрос: HttpЗапрос): Число
            знч Ответ = Запрос.Выполнить()
            знч ДанныеОтвета = СериализацияJson.ПрочитатьОбъект(Ответ.Тело, Тип<Соответствие<Строка, Объект?>>)
            знч Результат = ДанныеОтвета.Получить("result") как Соответствие<Строка, Объект?>
            возврат Результат.Получить("message_id") как Число
        ;
    """)
    assert rc == 1
    assert lines(found) == [("ПР-12", 4)]
    assert "ДанныеОтвета" in found[0]["message"]


def test_stored_body_split_over_lines_is_a_finding(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        @НаСервере
        метод Обработать(ВызовВебХука: ВызовыВебХука.Объект)
            знч ДанныеЗапроса =
                СериализацияJson.ПрочитатьОбъект(ВызовВебХука.ТелоЗапроса, Тип<Соответствие<Строка, неизвестно>>)
            если ДанныеЗапроса.СодержитКлюч("message")
                знч Сообщение = ДанныеЗапроса.Получить("message") как Соответствие<Строка, неизвестно>
            ;
        ;
    """)
    assert lines(found) == [("ПР-12", 4)]


def test_blind_get_without_contains_key_is_a_finding(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        @НаСервере
        метод ПриЗапросе(Запрос: HttpСервисЗапрос)
            знч Тело = Запрос.Тело.ПрочитатьКакСтроку()
            знч Данные = СериализацияJson.ПрочитатьОбъект(Тело, Тип<Соответствие<Строка, Объект>>)
            Записать(Данные.Получить("id"))
        ;
    """)
    assert lines(found) == [("ПР-12", 4)]


def test_typed_structure_is_not_a_finding(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        @НаСервере
        метод ПриЗапросе(Запрос: HttpСервисЗапрос)
            знч Черновик = СериализацияJson.ПрочитатьОбъект(Запрос.Тело.ПрочитатьКакСтроку(),
                Тип<ПерепискаВебЧата.ЧерновикСообщения>)
            Отправить(Черновик)
        ;
    """)
    assert rc == 0
    assert found == []


def test_own_data_is_not_a_finding(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        @ВПроекте
        метод ИзФайла(Json: Строка)
            знч Части = СериализацияJson.ПрочитатьОбъект(Json, Тип<Соответствие<Строка, Объект>>)
            знч Час = Части.Получить("час") как Число
        ;
    """)
    assert found == []


def test_result_written_back_is_not_a_finding(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        @ВПроекте
        метод НачатьЗаписьЛога(ТелоЗапроса: Строка)
            Запись.ТелоЗапроса =
                СериализацияJson.ЗаписатьОбъект(СериализацияJson.ПрочитатьОбъект(ТелоЗапроса, Тип<Соответствие<Строка, Объект>>))
        ;
    """)
    assert found == []


def test_read_inside_try_is_not_a_finding(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        @НаСервере
        метод Разобрать(Ответ: HttpОтвет): Число?
            попытка
                знч Данные = СериализацияJson.ПрочитатьОбъект(Ответ.Тело, Тип<Соответствие<Строка, Объект>>)
                возврат Данные.Получить("id") как Число
            поймать Ошибка: Исключение
                возврат Неопределено
            ;
        ;
    """)
    assert found == []
