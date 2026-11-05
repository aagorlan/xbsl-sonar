"""ПР-19: сборка строки сложением в цикле. Положительные и отрицательные примеры."""

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


def check(tmp_path, monkeypatch, data_dir, code: str) -> tuple[int, list[dict]]:
    module = tmp_path / "IT" / "Проект" / "Основное" / "Модуль.xbsl"
    module.parent.mkdir(parents=True)
    module.write_text(textwrap.dedent(code).lstrip(), encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    rc = cli.main(["check", "IT", "--data-dir", str(data_dir), "--json", "находки.json",
                   "--rules", "ПР-19"])
    found = json.loads((tmp_path / "находки.json").read_text(encoding="utf-8"))["findings"]
    return rc, found


def lines(found: list[dict]) -> list[tuple[str, int]]:
    return [(f["rule"], f["line"]) for f in found]


def test_concatenation_in_for_is_a_finding(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        метод Список(Слова: Массив<Строка>): Строка
            пер Итог = ""
            для Слово из Слова
                Итог += Слово + ", "
            ;
            возврат Итог
        ;
    """)
    assert rc == 1
    assert lines(found) == [("ПР-19", 4)]


def test_self_addition_in_while_is_a_finding(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        метод Строки(Чтение: ЧтениеТекста): Строка
            пер Текст: Строка = ""
            пока Чтение.Следующая()
                если не Чтение.Строка.Пусто()
                    Текст = Текст + Чтение.Строка + "\\н"
                ;
            ;
            возврат Текст
        ;
    """)
    assert rc == 1
    assert lines(found) == [("ПР-19", 5)]


def test_literal_appended_to_unknown_variable_is_a_finding(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        метод Заполнить(Слова: Массив<Строка>)
            для Слово из Слова
                Результат += "%{Слово}; "
            ;
        ;
    """)
    assert rc == 1
    assert lines(found) == [("ПР-19", 3)]


def test_number_in_loop_is_not_a_finding(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        метод Сумма(Числа: Массив<Число>): Число
            пер Счёт = 0
            пер Итог: Число = 0
            для Ч из Числа
                Счёт += 1
                Итог = Итог + Ч
            ;
            возврат Итог / Счёт
        ;
    """)
    assert rc == 0
    assert found == []


def test_join_and_concatenation_outside_loop_are_not_findings(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        метод Список(Слова: Массив<Строка>): Строка
            знч Части = новый Массив<Строка>()
            для Слово из Слова
                Части.Добавить(Слово)
            ;
            пер Итог = "Слова: "
            Итог += Строки.Соединить(Части, ", ")
            возврат Итог
        ;
    """)
    assert rc == 0
    assert found == []


def test_variable_of_another_method_is_not_a_finding(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        метод Заголовок(): Строка
            пер Итог = ""
            возврат Итог
        ;

        метод Сумма(Числа: Массив<Число>): Число
            пер Итог = 0
            для Ч из Числа
                Итог += Ч
            ;
            возврат Итог
        ;
    """)
    assert rc == 0
    assert found == []


def test_loop_closed_before_addition_is_not_a_finding(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        метод Строка(Слова: Массив<Строка>): Строка
            пер Итог = ""
            для Слово из Слова
                если Слово.Пусто()
                    продолжить
                ;
            ;
            Итог += "конец"
            возврат Итог
        ;
    """)
    assert rc == 0
    assert found == []
