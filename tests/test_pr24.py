"""ПР-24: открытый переход. Положительные и отрицательные примеры.

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
                   "--rules", "ПР-24"])
    found = json.loads((tmp_path / "находки.json").read_text(encoding="utf-8"))["findings"]
    return rc, found


def lines(found: list[dict]) -> list[tuple[str, int]]:
    return [(f["rule"], f["line"]) for f in found]


def test_page_parameter_is_a_finding(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        @Обработчик
        метод ПриОткрытииПоСсылке(ПараметрыОткрытия: ПараметрыUrl)
            знч Куда = ПараметрыОткрытия.ПолучитьПервый("next") ?? "/"
            ПерейтиПоСсылке(Куда)
        ;
    """)
    assert rc == 1
    assert lines(found) == [("ПР-24", 4)]
    assert "ПерейтиПоСсылке" in found[0]["message"]


def test_form_field_through_variable_is_a_finding(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        @Локально
        метод ПерейтиПриНажатии(Источник: Кнопка, Событие: СобытиеПриНажатии)
            знч Адрес = Компоненты.Адрес.Значение
            ПерейтиПоСсылке("" + Адрес, Истина)
        ;
    """)
    assert lines(found) == [("ПР-24", 4)]


def test_html_container_on_logout_is_a_finding(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        @Локально
        метод Выйти()
            Аутентификация.ЗавершитьТекущийСеанс(Компоненты.Куки.ВызватьМетод("ahNext") как Строка)
        ;
    """)
    assert lines(found) == [("ПР-24", 3)]


def test_settings_and_navigation_link_are_not_findings(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        @Локально
        метод Выйти()
            Аутентификация.ЗавершитьТекущийСеанс(ОбщийМодуль.АдресВыхода())
            Аутентификация.ЗавершитьТекущийСеанс(НавигационнаяСсылка.Абсолютная(Тип<Приложение>))
            Аутентификация.ЗавершитьТекущийСеанс()
            ПерейтиПоСсылке(ПараметрыСистемы.АдресЛендинга(), Ложь)
        ;
    """)
    assert rc == 0
    assert found == []


def test_fixed_host_and_own_method_named_like_call_are_not_findings(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        метод ПерейтиПоСсылке(ПараметрыАдреса: ПараметрыUrl?)
            Пространства.ПерейтиПоСсылке(ПараметрыАдреса)
        ;

        @Локально
        метод Поделиться()
            знч Текст = Компоненты.Текст.Значение
            ПерейтиПоСсылке("https://t.me/share/url?text=" + Текст)
        ;
    """)
    assert found == []


def test_stored_field_is_not_a_finding(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, """
        @Локально
        метод ОткрытьСайт(ДанныеСтроки: СтрокаДинамическогоСписка<Профили.Данные>)
            ПерейтиПоСсылке(ДанныеСтроки.Данные.Сайт, Истина)
        ;
    """)
    assert found == []
