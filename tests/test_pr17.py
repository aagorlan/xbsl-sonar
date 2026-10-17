"""ПР-17: обращение к серверу при каждой перерисовке формы. Положительные и отрицательные примеры."""

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


def check(tmp_path, monkeypatch, data_dir, files: dict[str, str],
          *extra: str) -> tuple[int, list[dict]]:
    for name, code in files.items():
        path = tmp_path / "IT" / "Проект" / "Основное" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(code).lstrip(), encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    rc = cli.main(["check", "IT", "--data-dir", str(data_dir), "--rules", "ПР-17",
                   "--json", "находки.json", *extra])
    found = json.loads((tmp_path / "находки.json").read_text(encoding="utf-8"))["findings"]
    return rc, found


ROW_YAML = """
    ВидЭлемента: КомпонентИнтерфейса
    Имя: Строка
    Наследует:
        Тип: ПроизвольнаяСтрокаСписка<СтрокаДинамическогоСписка<Форма.Данные>>
        Содержимое:
            Тип: Группа
            ЦветФона: =ЦветСостояния()
            Содержимое:
                -
                    Тип: Надпись
                    Значение: =ДанныеСтроки.Данные.Текст
                -
                    Тип: Надпись
                    Ширина: =Отступ()
    Свойства:
        -
            Имя: Профиль
            ЗначениеПоУмолчанию: =ЦветСостояния()
"""

ROW_XBSL = """
    метод ЦветСостояния(): Цвет
        возврат Состояния.Цвет(ДанныеСтроки.Данные.Состояние)
    ;

    метод Отступ(): Число
        возврат ДанныеСтроки.Данные.Уровень * 50
    ;
"""

SERVER_STATES = """
    @ВПроекте
    @НаСервере @ДоступноСКлиента
    статический метод Цвет(Состояние: Строка): Цвет
        возврат Цвета.Зеленый
    ;
"""

CLIENT_STATES = """
    @ВПроекте
    статический метод Цвет(Состояние: Строка): Цвет
        возврат Цвета.Зеленый
    ;
"""


def test_expression_in_list_row_reaching_server(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, {
        "Строка.yaml": ROW_YAML, "Строка.xbsl": ROW_XBSL, "Состояния.xbsl": SERVER_STATES})
    assert rc == 1
    assert [(f["rule"], f["line"]) for f in found] == [("ПР-17", 7)]
    assert found[0]["message"].startswith("Выражение ЦветФона =ЦветСостояния(): строка списка")
    assert "'Строка.ЦветСостояния'" in found[0]["message"]


def test_client_computation_is_not_a_finding(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, {
        "Строка.yaml": ROW_YAML, "Строка.xbsl": ROW_XBSL, "Состояния.xbsl": CLIENT_STATES})
    assert (rc, found) == (0, [])


def test_query_in_method_of_form_expression(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, {
        "Форма.yaml": """
            ВидЭлемента: КомпонентИнтерфейса
            Имя: Форма
            Наследует:
                Тип: ФормаОбъекта<Документ.Объект>
                Содержимое:
                    Тип: Надпись
                    Значение: '=НаименованиеОбласти(Объект.Область)'
        """,
        "Форма.xbsl": """
            @Локально
            статический метод НаименованиеОбласти(Область: Строка): Строка
                возврат Запрос{ВЫБРАТЬ Области.Наименование ИЗ Области}.Выполнить().Первый().Наименование
            ;
        """,
    })
    assert rc == 1
    assert found[0]["message"].startswith("Выражение Значение =НаименованиеОбласти(): форма считает")


def test_not_a_component_yaml(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, {
        "Документ.yaml": """
            ВидЭлемента: Документ
            Имя: Документ
            Реквизиты:
                -
                    Имя: Цвет
                    ЗначениеПоУмолчанию: =ЦветСостояния()
        """,
        "Документ.xbsl": ROW_XBSL, "Состояния.xbsl": SERVER_STATES})
    assert (rc, found) == (0, [])


HANDLER = """
    @Обработчик
    метод ПослеСоздания()
        Надпись = Данные()
        Профиль = Данные()
        Права = Данные()
        {четвёртый}
        если Признак
            Счётчик = Запрос{{ВЫБРАТЬ 1}}.Выполнить().Размер()
        ;
    ;

    @НаСервере @ДоступноСКлиента
    статический метод Данные(): Строка
        возврат ""
    ;
"""

COMPONENT_YAML = """
    ВидЭлемента: КомпонентИнтерфейса
    Имя: Форма
"""


def test_handler_over_threshold(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, {
        "Форма.yaml": COMPONENT_YAML, "Форма.xbsl": HANDLER.format(четвёртый="Ещё = Данные()")})
    assert rc == 1
    assert [(f["rule"], f["line"]) for f in found] == [("ПР-17", 2)]
    assert found[0]["message"].startswith("Обработчик ПослеСоздания: 5 обращений")


def test_handler_within_threshold_and_parameter(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, {
        "Форма.yaml": COMPONENT_YAML, "Форма.xbsl": HANDLER.format(четвёртый="")},
        "--max-accesses", "4")
    assert (rc, found) == (0, [])


def test_handler_outside_component_is_not_a_finding(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, {
        "Форма.yaml": "ВидЭлемента: Справочник\nИмя: Форма\n",
        "Форма.xbsl": HANDLER.format(четвёртый="Ещё = Данные()")})
    assert (rc, found) == (0, [])


def test_agreed_finding(tmp_path, monkeypatch, data_dir):
    (tmp_path / "согласовано.txt").write_text(
        "IT/Проект/Основное/Строка.yaml: ПР-17 Выражение ЦветФона =ЦветСостояния() — пункт долга ТД-1\n",
        encoding="utf-8")
    rc, found = check(tmp_path, monkeypatch, data_dir, {
        "Строка.yaml": ROW_YAML, "Строка.xbsl": ROW_XBSL, "Состояния.xbsl": SERVER_STATES},
        "--agreed", "согласовано.txt")
    assert rc == 0
    assert [f["debt"] for f in found] == ["согласовано"]
