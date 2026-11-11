"""ПР-21: обращение к данным из модуля формы. Положительные и отрицательные примеры."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from xbsl_sonar import cli, data

HELP = Path(__file__).parent / "help"

FORM_YAML = """\
ВидЭлемента: КомпонентИнтерфейса
Ид: 00000000-0000-4000-8000-000000000001
Имя: Модуль
Наследует:
    Тип: Форма
"""

MANAGER_YAML = """\
ВидЭлемента: РегистрСведений
Ид: 00000000-0000-4000-8000-000000000002
Имя: Модуль
"""


@pytest.fixture(scope="session")
def data_dir(tmp_path_factory) -> Path:
    return data.build(HELP, tmp_path_factory.mktemp("data"))


def check(tmp_path, monkeypatch, data_dir, code: str, yaml: str = FORM_YAML) -> tuple[int, list[dict]]:
    module = tmp_path / "IT" / "Проект" / "Основное" / "Модуль.xbsl"
    module.parent.mkdir(parents=True)
    module.write_text(textwrap.dedent(code).lstrip(), encoding="utf-8")
    module.with_suffix(".yaml").write_text(yaml, encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    rc = cli.main(["check", "IT", "--data-dir", str(data_dir), "--json", "находки.json",
                   "--rules", "ПР-21"])
    found = json.loads((tmp_path / "находки.json").read_text(encoding="utf-8"))["findings"]
    return rc, found


def lines(found: list[dict]) -> list[tuple[str, int]]:
    return [(f["rule"], f["line"]) for f in found]


def test_query_in_form_is_a_hint(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        @Локально
        @НаСервере @ДоступноСКлиента
        статический метод Опубликованные(): Массив<Строка>
            исп Выборка = Запрос{ВЫБРАТЬ
                Публикации.Заголовок КАК Заголовок
            ИЗ
                Публикации КАК Публикации}.Выполнить()
            возврат новый Массив<Строка>()
        ;
    """)
    assert rc == 0, "подсказка анализ не роняет"
    assert lines(found) == [("ПР-21", 4)]
    assert found[0]["message"].startswith("Метод 'Опубликованные':")


def test_load_record_and_record_set_in_form_are_hints(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        @Локально
        @НаСервере @ДоступноСКлиента
        статический метод Прочитать(): Строка
            знч Запись = новый Параметры.КлючЗаписи().ЗагрузитьЗапись()
            знч Набор = новый Параметры.НаборЗаписей()
            знч Объект = Ссылка.ЗагрузитьОбъект()
            возврат ""
        ;
    """)
    assert rc == 0
    assert lines(found) == [("ПР-21", 4), ("ПР-21", 5), ("ПР-21", 6)]


def test_call_to_manager_is_not_a_finding(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        @Локально
        @НаСервере @ДоступноСКлиента
        статический метод Прочитать(): Строка
            //Запрос{ — в комментарии, «Запрос{» — в строке
            знч Текст = "Запрос{ВЫБРАТЬ}"
            возврат ПараметрыСистемы.АдресЛендинга()
        ;
    """)
    assert rc == 0
    assert found == []


def test_query_in_manager_module_is_not_a_finding(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        @ВПроекте
        @НаСервере
        метод Опубликованные(): Число
            исп Выборка = Запрос{ВЫБРАТЬ 1 КАК Один}.Выполнить()
            возврат 1
        ;
    """, yaml=MANAGER_YAML)
    assert rc == 0
    assert found == []


def test_hint_does_not_hide_blocking_findings(tmp_path, monkeypatch, data_dir):
    module = tmp_path / "IT" / "Проект" / "Основное" / "Модуль.xbsl"
    module.parent.mkdir(parents=True)
    module.write_text(textwrap.dedent("""
        метод Список(Слова: Массив<Строка>): Строка
            пер Итог = ""
            для Слово из Слова
                Итог += Слово
            ;
            исп Выборка = Запрос{ВЫБРАТЬ 1 КАК Один}.Выполнить()
            возврат Итог
        ;
    """).lstrip(), encoding="utf-8")
    module.with_suffix(".yaml").write_text(FORM_YAML, encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    rc = cli.main(["check", "IT", "--data-dir", str(data_dir), "--json", "находки.json",
                   "--rules", "ПР-19,ПР-21"])
    found = json.loads((tmp_path / "находки.json").read_text(encoding="utf-8"))["findings"]
    assert rc == 1
    assert sorted(lines(found)) == [("ПР-19", 4), ("ПР-21", 6)]
