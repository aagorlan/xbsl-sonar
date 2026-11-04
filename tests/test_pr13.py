"""ПР-13: текст запроса из строк. Положительные и отрицательные примеры.

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
                   "--rules", "ПР-13"])
    found = json.loads((tmp_path / "находки.json").read_text(encoding="utf-8"))["findings"]
    return rc, found


def lines(found: list[dict]) -> list[tuple[str, int]]:
    return [(f["rule"], f["line"]) for f in found]


def test_concatenated_text_is_a_finding(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        @НаСервере
        метод Найти(Строка: Строка): Массив<Публикация.Ссылка>
            знч Текст = "ВЫБРАТЬ Ссылка ИЗ Публикация ГДЕ Заголовок ПОДОБНО \\"" + Строка + "\\""
            знч Результат = новый Запрос(Текст).Выполнить()
            возврат Результат.ВМассив()
        ;
    """)
    assert rc == 1
    assert lines(found) == [("ПР-13", 4)]


def test_interpolated_plain_string_is_a_finding(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        @НаСервере
        метод Найти(Таблица: Строка)
            знч Результат = новый Запрос("ВЫБРАТЬ Ссылка ИЗ %Таблица").Выполнить()
        ;
    """)
    assert lines(found) == [("ПР-13", 3)]


def test_text_assigned_from_variable_is_a_finding(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        @НаСервере
        метод Найти(Условие: Строка)
            знч ТекстЗапроса = новый Запрос("ВЫБРАТЬ 1")
            ТекстЗапроса.Текст = "ВЫБРАТЬ Ссылка ИЗ Публикация ГДЕ " + Условие
            ТекстЗапроса.Выполнить()
        ;
    """)
    assert lines(found) == [("ПР-13", 4)]


def test_query_literal_with_parameters_is_not_a_finding(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        @НаСервере
        метод Найти(Шаблон: Строка): Массив<Публикация.Ссылка>
            возврат Запрос{
                ВЫБРАТЬ Ссылка ИЗ Публикация ГДЕ Заголовок ПОДОБНО %Шаблон И Автор == %{Текущий()}
            }.Выполнить().ВМассив()
        ;
    """)
    assert rc == 0
    assert found == []


def test_single_literal_is_not_a_finding(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        @НаСервере
        метод Посчитать(): Число
            знч Результат = новый Запрос("ВЫБРАТЬ
                КОЛИЧЕСТВО(Ссылка) КАК Всего
            ИЗ
                Публикация").Выполнить()
            возврат Результат.Единственный().Всего
        ;
    """)
    assert found == []


def test_text_of_other_object_is_not_a_finding(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        метод Подписать(Подпись: Надпись, Имя: Строка)
            Подпись.Текст = "Здравствуйте, " + Имя
        ;
    """)
    assert found == []
