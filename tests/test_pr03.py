"""ПР-03: точка без аутентификации вне согласованного перечня. Положительные и отрицательные примеры."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from xbsl_sonar import cli, data

HELP = Path(__file__).parent / "help"

ГОСТЬ = """
    ВидЭлемента: КомпонентИнтерфейса
    Имя: Лендинг
    Наследует:
        Тип: ПроизвольноеКлиентскоеПриложение
        РежимАутентификации: НеАутентифицированный
"""

ВОШЕДШИЙ = """
    ВидЭлемента: КомпонентИнтерфейса
    Имя: Лендинг
    Наследует:
        Тип: ПроизвольноеКлиентскоеПриложение
"""

МОДУЛЬ = """
    @Локально
    @НаСервере
    статический метод Витрина(): Число
        исп КонтекстДоступа.Привилегированный()
        возврат 5
    ;
"""


@pytest.fixture(scope="session")
def data_dir(tmp_path_factory) -> Path:
    return data.build(HELP, tmp_path_factory.mktemp("data"))


def check(tmp_path, monkeypatch, data_dir, files: dict[str, str], perimeter: str = "") -> list[tuple[str, int]]:
    root = tmp_path / "IT" / "Проект" / "Основное"
    root.mkdir(parents=True)
    for name, text in files.items():
        (root / name).write_text(textwrap.dedent(text).lstrip(), encoding="utf-8")
    args = ["check", "IT", "--data-dir", str(data_dir), "--rules", "ПР-03", "--json", "находки.json"]
    if perimeter:
        (tmp_path / "периметр.txt").write_text(textwrap.dedent(perimeter).lstrip(), encoding="utf-8")
        args += ["--perimeter", "периметр.txt"]
    monkeypatch.chdir(tmp_path)
    cli.main(args)
    found = json.loads((tmp_path / "находки.json").read_text(encoding="utf-8"))["findings"]
    return sorted((Path(f["path"]).name, f["line"]) for f in found if f["debt"] is None)


def test_unauthenticated_element(tmp_path, monkeypatch, data_dir):
    assert check(tmp_path, monkeypatch, data_dir, {"Лендинг.yaml": ГОСТЬ}) == [("Лендинг.yaml", 5)]


def test_allowed_for_all_rights_and_http_service(tmp_path, monkeypatch, data_dir):
    assert check(tmp_path, monkeypatch, data_dir, {"Сервис.yaml": """
        ВидЭлемента: HttpСервис
        Имя: Сервис
        КонтрольДоступа:
            Вызов: РазрешеноВсем
            ПоУмолчанию: РазрешеноАутентифицированным
    """, "Справочник.yaml": """
        ВидЭлемента: Справочник
        Имя: Справочник
        КонтрольДоступа:
            Чтение: РазрешеноВсем
            Изменение: РазрешеноАдминистраторам
    """}) == [("Сервис.yaml", 1), ("Сервис.yaml", 4), ("Справочник.yaml", 4)]


def test_privileged_in_guest_module(tmp_path, monkeypatch, data_dir):
    assert check(tmp_path, monkeypatch, data_dir, {"Лендинг.yaml": ГОСТЬ, "Лендинг.xbsl": МОДУЛЬ}) \
        == [("Лендинг.xbsl", 4), ("Лендинг.yaml", 5)]


def test_privileged_for_signed_in_is_not_perimeter(tmp_path, monkeypatch, data_dir):
    assert check(tmp_path, monkeypatch, data_dir, {"Лендинг.yaml": ВОШЕДШИЙ, "Лендинг.xbsl": МОДУЛЬ}) == []


def test_perimeter_mark_in_code(tmp_path, monkeypatch, data_dir):
    marked = МОДУЛЬ.replace("        исп", "        // анализ:периметр — витрина гостю\n        исп")
    assert check(tmp_path, monkeypatch, data_dir, {"Лендинг.yaml": ГОСТЬ, "Лендинг.xbsl": marked},
                 "IT/Проект/Основное/Лендинг.yaml: РежимАутентификации — лендинг\n") == []


def test_perimeter_list_covers_only_named_key(tmp_path, monkeypatch, data_dir):
    assert check(tmp_path, monkeypatch, data_dir, {"Сервис.yaml": """
        ВидЭлемента: HttpСервис
        Имя: Сервис
        КонтрольДоступа:
            Вызов: РазрешеноВсем
            ПоУмолчанию: РазрешеноВсем
    """}, """
        # перечень периметра
        IT/Проект/Основное/Сервис.yaml: ВидЭлемента — приём сообщений
        IT/Проект/Основное/Сервис.yaml: Вызов — без входа по замыслу
    """) == [("Сервис.yaml", 5)]


def test_authenticated_rights_are_not_perimeter(tmp_path, monkeypatch, data_dir):
    assert check(tmp_path, monkeypatch, data_dir, {"Справочник.yaml": """
        ВидЭлемента: Справочник
        Имя: Справочник
        КонтрольДоступа:
            Чтение: РазрешеноАутентифицированным
    """}) == []
