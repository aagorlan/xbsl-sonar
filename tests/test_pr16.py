"""ПР-16: повторяющийся таймер клиента вызывает сервер. Положительные и отрицательные примеры."""

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
    rc = cli.main(["check", "IT", "--data-dir", str(data_dir), "--rules", "ПР-16",
                   "--json", "находки.json", *extra])
    found = json.loads((tmp_path / "находки.json").read_text(encoding="utf-8"))["findings"]
    return rc, found


FORM = """
    @Обработчик
    метод ПослеСоздания()
        ПодключитьОбработчикТаймера({обработчик}, {интервал}{однократно})
    ;

    метод Обновить()
        Надпись = Данные()
    ;

    @НаСервере @ДоступноСКлиента
    статический метод Данные(): Строка
        возврат ""
    ;

    метод Мигнуть()
        Видимость = не Видимость
    ;
"""


def form(обработчик: str, интервал: str, однократно: str = ", Ложь") -> dict[str, str]:
    return {"Форма.xbsl": FORM.format(обработчик=обработчик, интервал=интервал,
                                      однократно=однократно)}


def test_repeating_timer_reaching_server(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, form("&Обновить", "10с"))
    assert rc == 1
    assert [(f["rule"], f["line"]) for f in found] == [("ПР-16", 3)]
    assert found[0]["message"].startswith("Таймер Обновить: ")


def test_lambda_handler_and_default_repeat(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, form("() -> Обновить()", "1с", ""))
    assert rc == 1
    assert [f["rule"] for f in found] == ["ПР-16"]


def test_server_method_of_common_module(tmp_path, monkeypatch, data_dir):
    files = {
        "Форма.xbsl": """
            метод ПослеСоздания()
                ПодключитьОбработчикТаймера(() -> Проверить(), Длительность.ИзСекунд(5), Ложь)
            ;

            метод Проверить()
                Флаг = ОбщийМодуль.ЕстьНовое()
            ;
        """,
        "ОбщийМодуль.xbsl": """
            @ВПроекте
            @НаСервере @ДоступноСКлиента
            метод ЕстьНовое(): Булево
                возврат Ложь
            ;
        """,
    }
    rc, found = check(tmp_path, monkeypatch, data_dir, files)
    assert rc == 1
    assert [(f["path"].split("/")[-1], f["rule"]) for f in found] == [("Форма.xbsl", "ПР-16")]


@pytest.mark.parametrize("обработчик, интервал, однократно", [
    ("&Обновить", "1мс", ", Истина"),   # однократный
    ("&Обновить", "1м", ", Ложь"),      # от порога
    ("&Обновить", "Интервал", ", Ложь"),  # не посчитать
    ("&Мигнуть", "1с", ", Ложь"),       # сервер не трогает
])
def test_not_a_finding(tmp_path, monkeypatch, data_dir, обработчик, интервал, однократно):
    rc, found = check(tmp_path, monkeypatch, data_dir, form(обработчик, интервал, однократно))
    assert (rc, found) == (0, [])


def test_min_period_parameter(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, form("&Обновить", "10с"),
                      "--min-period", "5")
    assert (rc, found) == (0, [])


def test_agreed_finding(tmp_path, monkeypatch, data_dir):
    (tmp_path / "согласовано.txt").write_text(
        "IT/Проект/Основное/Форма.xbsl: ПР-16 Таймер Обновить — пункт долга ТД-1\n",
        encoding="utf-8")
    rc, found = check(tmp_path, monkeypatch, data_dir, form("&Обновить", "10с"),
                      "--agreed", "согласовано.txt")
    assert rc == 0
    assert [f["debt"] for f in found] == ["согласовано"]


def test_call_only_on_change_is_not_a_finding(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, {"Форма.xbsl": """
        метод ПослеСоздания()
            ПодключитьОбработчикТаймера(&Проверка, 1с, Ложь)
        ;

        метод Проверка()
            если Беседа != ОткрытаяБеседа
                ОткрытаяБеседа = Беседа
                Показать(Данные(Беседа))
            иначе если Версия != ОткрытаяВерсия
                Показать(Данные(Беседа))
            ;
        ;

        @НаСервере @ДоступноСКлиента
        статический метод Данные(Беседа: Строка): Строка
            возврат Беседа
        ;
    """})
    assert (rc, found) == (0, [])


def test_call_in_condition_is_a_finding(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, {"Форма.xbsl": """
        метод ПослеСоздания()
            ПодключитьОбработчикТаймера(&ЖдатьЗадание, 1с, Ложь)
        ;

        метод ЖдатьЗадание()
            если Статус() != "Выполняется"
                ОтключитьОбработчикТаймера(&ЖдатьЗадание)
            ;
        ;

        @НаСервере @ДоступноСКлиента
        статический метод Статус(): Строка
            возврат ""
        ;
    """})
    assert rc == 1
    assert "('Статус')" in found[0]["message"]
