"""ПР-05: повышение прав с клиента без сверки. Положительные и отрицательные примеры."""

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


def check(tmp_path, monkeypatch, data_dir, code: str, other: str = "",
          rules: str = "ПР-05") -> list[tuple[str, int]]:
    module = tmp_path / "IT" / "Проект" / "Основное" / "Модуль.xbsl"
    module.parent.mkdir(parents=True)
    module.write_text(textwrap.dedent(code).lstrip(), encoding="utf-8")
    if other:
        (module.parent / "ОбщийМодуль.xbsl").write_text(textwrap.dedent(other).lstrip(), encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    cli.main(["check", "IT", "--data-dir", str(data_dir), "--rules", rules, "--json", "находки.json"])
    found = json.loads((tmp_path / "находки.json").read_text(encoding="utf-8"))["findings"]
    return [(f["rule"], f["line"]) for f in found]


COMMON = """
    @ВПроекте
    @НаСервере @ДоступноСКлиента
    метод ЭтоАдминистратор(): Булево
        возврат Пользователи.ТекущийПользователь?.Администратор ?? Ложь
    ;

    @ВПроекте
    @НаСервере @ДоступноСКлиента
    метод ПолучитьУчастника(): Участники.Ссылка?
        возврат Запрос{ВЫБРАТЬ ПЕРВЫЕ 1 Т.Владелец КАК Ссылка ИЗ Т КАК Т
            ГДЕ Т.Пользователь == %{Пользователи.ТекущийПользователь}}.Выполнить().ЕдинственныйИлиНеопределено()?.Ссылка
    ;
"""


def test_secret_returned_to_any_caller(tmp_path, monkeypatch, data_dir):
    assert check(tmp_path, monkeypatch, data_dir, """
        @ВПодсистеме
        @НаСервере @ДоступноСКлиента
        метод Настройки(): НастройкиПочты.Запись?
            исп КонтекстДоступа.Привилегированный()
            возврат новый НастройкиПочты.КлючЗаписи().ЗагрузитьЗапись()
        ;
    """) == [("ПР-05", 3)]


def test_record_from_client_written_under_privilege(tmp_path, monkeypatch, data_dir):
    assert check(tmp_path, monkeypatch, data_dir, """
        @НаСервере @ДоступноСКлиента
        метод Сохранить(Запись: Заявки.Запись)
            исп КонтекстДоступа.Привилегированный()
            Заявки.Записать(Запись)
        ;
    """) == [("ПР-05", 2)]


def test_group_operation_in_privileged_mode(tmp_path, monkeypatch, data_dir):
    assert check(tmp_path, monkeypatch, data_dir, """
        @НаСервере @ДоступноСКлиента
        метод Заполнить()
            исп ГрупповаяОперация.Начать(Транзакция = Истина, ПривилегированныйРежим = Истина)
            Данные.Заполнить()
        ;
    """) == [("ПР-05", 2)]


def test_admin_check_is_a_check(tmp_path, monkeypatch, data_dir):
    assert check(tmp_path, monkeypatch, data_dir, """
        @Локально
        метод ПроверитьПрава()
            если не ОбщийМодуль.ЭтоАдминистратор()
                выбросить новый ИсключениеНедопустимоеСостояние("Только администратор")
            ;
        ;

        @НаСервере @ДоступноСКлиента
        метод Разобрать(Файл: Строка): Строка
            ПроверитьПрава()
            исп КонтекстДоступа.Привилегированный()
            возврат Файл
        ;
    """, COMMON) == []


def test_participant_taken_on_server_is_a_check(tmp_path, monkeypatch, data_dir):
    assert check(tmp_path, monkeypatch, data_dir, """
        @НаСервере @ДоступноСКлиента
        метод МоиНастройки(): Настройки.Запись?
            знч ТекУчастник = ОбщийМодуль.ПолучитьУчастника()
            исп КонтекстДоступа.Привилегированный()
            возврат новый Настройки.КлючЗаписи(Участник = ТекУчастник).ЗагрузитьЗапись()
        ;
    """, COMMON) == []


def test_current_user_only_written_is_not_a_check(tmp_path, monkeypatch, data_dir):
    assert check(tmp_path, monkeypatch, data_dir, """
        @НаСервере @ДоступноСКлиента
        метод СоздатьУчастника()
            исп КонтекстДоступа.Привилегированный()
            знч Новый = новый Участники.Объект()
            Новый.Пользователь = Пользователи.ТекущийПользователь
            Новый.Записать()
        ;
    """) == [("ПР-05", 2)]


def test_reference_param_is_left_to_pr01(tmp_path, monkeypatch, data_dir):
    code = """
        @НаСервере @ДоступноСКлиента
        метод Снять(Участник: Участники.Ссылка)
            исп КонтекстДоступа.Привилегированный()
            Заявки.Удалить(новый Заявки.КлючЗаписи(Участник = Участник))
        ;
    """
    assert check(tmp_path, monkeypatch, data_dir, code, rules="ПР-01,ПР-05") == [("ПР-01", 2)]


def test_server_only_method_is_not_a_finding(tmp_path, monkeypatch, data_dir):
    assert check(tmp_path, monkeypatch, data_dir, """
        @НаСервере
        метод ПересчитатьКлючи()
            исп КонтекстДоступа.Привилегированный()
            Ключи.Пересчитать()
        ;

        @НаСервере @ДоступноСКлиента
        метод Количество(): Число
            возврат 0
        ;
    """) == []


def test_context_outliving_its_line(tmp_path, monkeypatch, data_dir):
    assert check(tmp_path, monkeypatch, data_dir, """
        @НаСервере
        метод Повысить(): КонтекстДоступа
            возврат КонтекстДоступа.Привилегированный()
        ;

        @НаСервере
        метод Повышение()
            знч Контекст = КонтекстДоступа.Привилегированный()
        ;
    """) == [("ПР-05", 3), ("ПР-05", 8)]


def test_named_use_is_not_a_finding(tmp_path, monkeypatch, data_dir):
    assert check(tmp_path, monkeypatch, data_dir, """
        @НаСервере
        метод Записать()
            исп Повышение = КонтекстДоступа.Привилегированный()
            Данные.Записать()
            Повышение.Закрыть()
        ;
    """) == []


def test_exception_mark_closes_finding(tmp_path, monkeypatch, data_dir):
    module = tmp_path / "IT" / "Проект" / "Основное" / "Модуль.xbsl"
    module.parent.mkdir(parents=True)
    module.write_text(textwrap.dedent("""
        @НаСервере @ДоступноСКлиента
        // анализ:исключение ПР-05 ТД-1 — до закрытия долга
        метод Путь(): Строка
            исп КонтекстДоступа.Привилегированный()
            возврат Параметры.Путь
        ;
    """).lstrip(), encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    code = cli.main(["check", "IT", "--data-dir", str(data_dir), "--rules", "ПР-05", "--json", "находки.json"])
    found = json.loads((tmp_path / "находки.json").read_text(encoding="utf-8"))["findings"]
    assert [(f["rule"], f["line"], f["debt"]) for f in found] == [("ПР-05", 3, "ТД-1")]
    assert code == 0
