"""ПР-20: лишний индекс в YAML. Положительные и отрицательные примеры."""

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


def check(tmp_path, monkeypatch, data_dir, yaml: str, module: str = "") -> tuple[int, list[dict]]:
    folder = tmp_path / "IT" / "Проект" / "Основное"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "Элемент.yaml").write_text(textwrap.dedent(yaml).lstrip(), encoding="utf-8")
    if module:
        (folder / "Модуль.xbsl").write_text(textwrap.dedent(module).lstrip(), encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    rc = cli.main(["check", "IT", "--data-dir", str(data_dir), "--json", "находки.json",
                   "--rules", "ПР-20"])
    found = json.loads((tmp_path / "находки.json").read_text(encoding="utf-8"))["findings"]
    return rc, found


def lines(found: list[dict]) -> list[tuple[str, int]]:
    return [(f["rule"], f["line"]) for f in found]


REGISTER = """
    ВидЭлемента: РегистрСведений
    Имя: Слушатели
    Измерения:
        -
            Имя: Доклад
            Тип: Доклад.Ссылка?
        -
            Имя: Участник
            Тип: Участники.Ссылка?
    Индексы:
        -
            Имя: ПоДокладу
            Поля:
                - Доклад
    Ресурсы:
        -
            Имя: Записан
            Тип: Булево
"""

QUERY_BY_DOCUMENT = """
    метод Записавшиеся(Ссылка: Доклад.Ссылка): Число
        возврат Запрос{
            ВЫБРАТЬ КОЛИЧЕСТВО(Слушатели.Участник) КАК Число
            ИЗ Слушатели КАК Слушатели
            ГДЕ Слушатели.Доклад == %Ссылка И Слушатели.Записан
        }.Выполнить().Единственный().Число
    ;
"""


def test_index_on_leading_dimension_is_a_finding(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, REGISTER, QUERY_BY_DOCUMENT)
    assert rc == 1
    assert lines(found) == [("ПР-20", 12)]
    assert "индекс платформы по измерениям" in found[0]["message"]


def test_duplicate_and_prefix_of_another_index_are_findings(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        ВидЭлемента: Документ
        Имя: Комментарий
        Индексы:
            -
                Имя: ПубликацияДата
                Поля:
                    - Публикация
                    - Дата
            -
                Имя: Публикация
                Поля:
                    - Публикация
            -
                Имя: ЕщёПубликацияДата
                Поля:
                    - Публикация
                    - Дата
    """, """
        метод Свежие(П: Публикация.Ссылка)
            знч Р = Запрос{ВЫБРАТЬ Комментарий.Ссылка ИЗ Комментарий ГДЕ Комментарий.Публикация == %П
                УПОРЯДОЧИТЬ ПО Комментарий.Дата}.Выполнить()
        ;
    """)
    assert rc == 1
    assert lines(found) == [("ПР-20", 10), ("ПР-20", 14)]


def test_catalog_index_on_name_is_a_finding(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        ВидЭлемента: Справочник
        Имя: Области
        Индексы:
            -
                Имя: ПоНаименованию
                Поля:
                    - Наименование
    """, """
        метод Найти(Имя: Строка)
            знч Р = Запрос{ВЫБРАТЬ Области.Ссылка ИЗ Области ГДЕ Области.Наименование == %Имя}.Выполнить()
        ;
    """)
    assert rc == 1
    assert lines(found) == [("ПР-20", 5)]


def test_index_on_field_nobody_queries_is_a_finding(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        ВидЭлемента: Документ
        Имя: Заявка
        Индексы:
            -
                Имя: ПоДатеОтправки
                Поля:
                    - ДатаОтправки
    """, """
        метод Все()
            знч Р = Запрос{ВЫБРАТЬ Заявка.Ссылка ИЗ Заявка}.Выполнить()
        ;
    """)
    assert rc == 1
    assert lines(found) == [("ПР-20", 5)]
    assert "ДатаОтправки" in found[0]["message"]


def test_index_on_queried_field_is_not_a_finding(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        ВидЭлемента: Документ
        Имя: Комментарий
        Индексы:
            -
                Имя: Публикация
                Поля:
                    - Публикация
    """, """
        метод Комментарии(П: Публикация.Ссылка)
            знч Р = Запрос{ВЫБРАТЬ Комментарий.Ссылка ИЗ Комментарий ГДЕ Комментарий.Публикация == %П}.Выполнить()
        ;
    """)
    assert rc == 0
    assert found == []


def test_index_used_by_list_filter_is_not_a_finding(tmp_path, monkeypatch, data_dir):
    folder = tmp_path / "IT" / "Проект" / "Основное"
    folder.mkdir(parents=True)
    (folder / "Список.yaml").write_text(textwrap.dedent("""
        ВидЭлемента: КомпонентИнтерфейса
        Имя: Список
        Свойства:
            -
                Имя: Строки
                ЗначениеПоУмолчанию:
                    Фильтр:
                        Элементы:
                            -
                                Тип: ЭлементФильтраВыражение
                                Выражение: ВнутренниеЧаты.Владелец == &Участник
    """).lstrip(), encoding="utf-8")
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        ВидЭлемента: РегистрСведений
        Имя: ВнутренниеЧаты
        Измерения:
            -
                Имя: Чат
                Тип: Чаты.Ссылка?
        Индексы:
            -
                Имя: Владелец
                Поля:
                    - Владелец
    """)
    assert rc == 0
    assert found == []


def test_periodic_register_dimensions_are_not_taken_as_platform_index(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        ВидЭлемента: РегистрСведений
        Имя: Курсы
        Периодичность: Секунда
        Измерения:
            -
                Имя: Валюта
                Тип: Валюты.Ссылка?
        Индексы:
            -
                Имя: ПоВалюте
                Поля:
                    - Валюта
    """, """
        метод Курс(В: Валюты.Ссылка)
            знч Р = Запрос{ВЫБРАТЬ Курсы.Курс ИЗ Курсы ГДЕ Курсы.Валюта == %В}.Выполнить()
        ;
    """)
    assert rc == 0
    assert found == []
