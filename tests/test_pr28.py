"""ПР-28: решение о правах по признаку из параметра клиента. Положительные и отрицательные примеры."""

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
                   "--rules", "ПР-28"])
    found = json.loads((tmp_path / "находки.json").read_text(encoding="utf-8"))["findings"]
    return rc, found


def lines(found: list[dict]) -> list[tuple[str, int]]:
    return [(f["rule"], f["line"]) for f in found]


def test_admin_flag_guards_exception(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        @ВПроекте
        @НаСервере @ДоступноСКлиента
        метод ЗаменитьОбласть(Пост: Публикация.Ссылка, ЭтоАдминистратор: Булево)
            если не ЭтоАдминистратор
                выбросить новый ИсключениеНедопустимоеСостояние("Нет прав")
            ;
            Записать(Пост)
        ;
    """)
    assert rc == 1
    assert lines(found) == [("ПР-28", 4)]
    assert "ЭтоАдминистратор" in found[0]["message"]


def test_flag_opens_privileged_context_in_else(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        @НаСервере @ДоступноСКлиента
        метод Прочитать(Ссылка: Публикация.Ссылка,
            БезПроверкиПрав: Булево = Ложь): Строка
            если не БезПроверкиПрав
                и не ЕстьДоступ(Ссылка)
                возврат ""
            иначе
                исп КонтекстДоступа.Привилегированный()
                возврат Ссылка.Заголовок
            ;
        ;
    """)
    assert rc == 1
    assert lines(found) == [("ПР-28", 4)]


def test_server_side_flag_is_not_a_finding(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        @НаСервере @ДоступноСКлиента
        метод ЗаменитьОбласть(Пост: Публикация.Ссылка)
            знч Администратор = ОбщийМодуль.ЭтоАдминистратор()
            если не Администратор
                выбросить новый ИсключениеНедопустимоеСостояние("Нет прав")
            ;
        ;
    """)
    assert rc == 0
    assert found == []


def test_method_not_available_from_client_is_not_a_finding(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        @Локально
        метод Записать(Пост: Публикация.Ссылка, БезПроверки: Булево)
            если не БезПроверки
                выбросить новый ИсключениеНедопустимоеСостояние("Нет прав")
            ;
        ;
    """)
    assert rc == 0
    assert found == []


def test_flag_without_refusal_is_not_a_finding(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        @НаСервере @ДоступноСКлиента
        метод Заголовок(Пост: Публикация.Ссылка, ДляАдминистратора: Булево): Строка
            если ДляАдминистратора
                возврат Пост.Заголовок + " (служебная)"
            ;
            возврат Пост.Заголовок
        ;
    """)
    assert rc == 0
    assert found == []


def test_non_rights_boolean_is_not_a_finding(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        @НаСервере @ДоступноСКлиента
        метод Отправить(Пост: Публикация.Ссылка, Общая: Булево)
            если Общая
                выбросить новый ИсключениеНедопустимоеСостояние("Общую отправляет выкат")
            ;
        ;
    """)
    assert rc == 0
    assert found == []


def test_rights_named_non_boolean_is_not_a_finding(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        @НаСервере @ДоступноСКлиента
        метод Назначить(Модератор: Участники.Ссылка)
            если Модератор == Неопределено
                выбросить новый ИсключениеНедопустимоеСостояние("Не выбран модератор")
            ;
        ;
    """)
    assert rc == 0
    assert found == []


def test_flag_in_nested_if_after_block(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        @НаСервере @ДоступноСКлиента
        метод Удалить(Пост: Публикация.Ссылка, ПравоУдаления: Булево)
            если Пост == Неопределено
                возврат
            ;
            если ПравоУдаления
                для Комментарий из Комментарии(Пост)
                    Удалить(Комментарий)
                ;
            иначе
                выбросить новый ИсключениеНедопустимоеСостояние("Нет прав")
            ;
        ;
    """)
    assert rc == 1
    assert lines(found) == [("ПР-28", 6)]


def test_word_inside_name_is_not_a_right(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        @НаСервере @ДоступноСКлиента
        метод Выровнять(Пост: Публикация.Ссылка, Справа: Булево)
            если Справа
                выбросить новый ИсключениеНедопустимоеСостояние("Не поддерживается")
            ;
        ;
    """)
    assert rc == 0
    assert found == []
