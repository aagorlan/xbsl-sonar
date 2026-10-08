"""ПР-01: объект по ссылке с клиента под повышенными правами. Положительные и отрицательные примеры."""

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


def check(tmp_path, monkeypatch, data_dir, code: str, other: str = "") -> list[tuple[str, int]]:
    module = tmp_path / "IT" / "Проект" / "Основное" / "Модуль.xbsl"
    module.parent.mkdir(parents=True)
    module.write_text(textwrap.dedent(code).lstrip(), encoding="utf-8")
    if other:
        (module.parent / "ОбщийМодуль.xbsl").write_text(textwrap.dedent(other).lstrip(), encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    cli.main(["check", "IT", "--data-dir", str(data_dir), "--rules", "ПР-01", "--json", "находки.json"])
    found = json.loads((tmp_path / "находки.json").read_text(encoding="utf-8"))["findings"]
    return [(f["rule"], f["line"]) for f in found]


COMMON = """
    @ВПроекте
    @НаСервере @ДоступноСКлиента
    метод ПолучитьУчастника(): Участники.Ссылка?
        возврат Запрос{ВЫБРАТЬ ПЕРВЫЕ 1 Т.Владелец КАК Ссылка ИЗ Т КАК Т
            ГДЕ Т.Пользователь == %{Пользователи.ТекущийПользователь}}.Выполнить().ЕдинственныйИлиНеопределено()?.Ссылка
    ;

    @ВПроекте
    @НаСервере @ДоступноСКлиента
    метод ЭтоАдминистратор(): Булево
        возврат Пользователи.ТекущийПользователь?.Администратор ?? Ложь
    ;
"""


def test_reference_from_client_under_privilege(tmp_path, monkeypatch, data_dir):
    assert check(tmp_path, monkeypatch, data_dir, """
        @ВПроекте
        @НаСервере @ДоступноСКлиента
        статический метод ЗафиксироватьДоступ(Участник: Участники.Ссылка)
            знч НоваяЗапись = новый Журнал.Запись()
            НоваяЗапись.Пользователь = Пользователи.ТекущийПользователь
            НоваяЗапись.Участник = Участник
            исп КонтекстДоступа.Привилегированный()
            Журнал.Записать(НоваяЗапись)
        ;
    """) == [("ПР-01", 3)]


def test_nullable_reference_param(tmp_path, monkeypatch, data_dir):
    assert check(tmp_path, monkeypatch, data_dir, """
        @НаСервере @ДоступноСКлиента
        метод Заявка(Участник: Участники.Ссылка?, Вид: Строка): Заявки.Запись?
            исп КонтекстДоступа.Привилегированный()
            возврат новый Заявки.КлючЗаписи(Участник = Участник).ЗагрузитьЗапись()
        ;
    """) == [("ПР-01", 2)]


def test_participant_taken_on_server_is_not_a_finding(tmp_path, monkeypatch, data_dir):
    assert check(tmp_path, monkeypatch, data_dir, """
        @НаСервере @ДоступноСКлиента
        метод ОтметитьОзнакомление(Подобласть: Области.Ссылка)
            знч ТекУчастник = ОбщийМодуль.ПолучитьУчастника()
            если ТекУчастник == Неопределено
                возврат
            ;
            исп КонтекстДоступа.Привилегированный()
            Подписки.Удалить(новый Подписки.КлючЗаписи(Участник = ТекУчастник, Область = Подобласть))
        ;
    """, COMMON) == []


def test_guard_method_is_a_check(tmp_path, monkeypatch, data_dir):
    assert check(tmp_path, monkeypatch, data_dir, """
        @Локально
        метод ПроверитьПрава()
            если не ОбщийМодуль.ЭтоАдминистратор()
                выбросить новый ИсключениеНедостаточноПрав("Только администратор")
            ;
        ;

        @НаСервере @ДоступноСКлиента
        метод Отключить(Обращение: Обращения.Ссылка)
            ПроверитьПрава()
            исп КонтекстДоступа.Привилегированный()
            Обращение.ЗагрузитьОбъект().Удалить()
        ;
    """, COMMON) == []


def test_same_name_in_other_module_is_not_a_check(tmp_path, monkeypatch, data_dir):
    assert check(tmp_path, monkeypatch, data_dir, """
        @НаСервере @ДоступноСКлиента
        метод Снять(Участник: Участники.Ссылка)
            исп КонтекстДоступа.Привилегированный()
            Заявки.Удалить(новый Заявки.КлючЗаписи(Участник = Участник))
            Проверить()
        ;

        @Локально
        метод Проверить()
        ;
    """, COMMON + """
        метод Проверить()
            если Пользователи.ТекущийПользователь == Неопределено
                возврат
            ;
        ;
    """) == [("ПР-01", 2)]


def test_current_user_in_condition_is_a_check(tmp_path, monkeypatch, data_dir):
    assert check(tmp_path, monkeypatch, data_dir, """
        @НаСервере @ДоступноСКлиента
        метод Профиль(Пользователь: Пользователи.Ссылка): Строка
            если Пользователь != Пользователи.ТекущийПользователь
                выбросить новый ИсключениеНедостаточноПрав("Чужой профиль")
            ;
            исп КонтекстДоступа.Привилегированный()
            возврат Пользователь.ЗагрузитьОбъект().Имя
        ;
    """) == []


def test_right_check_before_privilege_is_a_check(tmp_path, monkeypatch, data_dir):
    assert check(tmp_path, monkeypatch, data_dir, """
        @НаСервере @ДоступноСКлиента
        статический метод Удалить(Страница: Страницы.Ссылка)
            знч Объект = Страница.ЗагрузитьОбъект(Истина)
            КонтрольДоступа.ПроверитьПраво(Объект, Сущность.Право.Удаление)
            исп КонтекстДоступа.Привилегированный()
            Объект.Удалить()
        ;
    """) == []


def test_without_privilege_is_not_a_finding(tmp_path, monkeypatch, data_dir):
    assert check(tmp_path, monkeypatch, data_dir, """
        @НаСервере @ДоступноСКлиента
        метод Скрыть(Опрос: Опросы.Ссылка, Участник: Участники.Ссылка)
            знч НоваяЗапись = новый СкрытыеОпросы.Запись()
            НоваяЗапись.Участник = Участник
            СкрытыеОпросы.Записать(НоваяЗапись)
        ;
    """) == []


def test_server_only_and_no_reference_params_are_not_findings(tmp_path, monkeypatch, data_dir):
    assert check(tmp_path, monkeypatch, data_dir, """
        @НаСервере
        метод ЗаписатьПриглашение(Приглашенный: Участники.Ссылка, Код: Строка)
            исп КонтекстДоступа.Привилегированный()
            Приглашения.Записать(новый Приглашения.Запись(Приглашенный = Приглашенный))
        ;

        @НаСервере @ДоступноСКлиента
        метод Количество(Код: Строка, Пределы: Массив<Число>): Число
            исп КонтекстДоступа.Привилегированный()
            возврат 0
        ;
    """) == []
