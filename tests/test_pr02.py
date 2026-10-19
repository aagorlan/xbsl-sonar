"""ПР-02: действие, которое интерфейс показывает только администратору, без проверки на сервере."""

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
    rc = cli.main(["check", "IT", "--data-dir", str(data_dir), "--rules", "ПР-02",
                   "--json", "находки.json", *extra])
    found = json.loads((tmp_path / "находки.json").read_text(encoding="utf-8"))["findings"]
    return rc, found


LIST_YAML = """
    ВидЭлемента: КомпонентИнтерфейса
    Имя: СписокКоманд
    Наследует:
        Тип: Форма
        Содержимое:
            Тип: Группа
            Содержимое:
                -
                    Тип: Группа
                    Имя: ГруппаКоманд
                    Видимость: =ДанныеПользователя.Администратор
                    Содержимое:
                        -
                            Тип: Кнопка
                            Имя: Удалить
                            ПриНажатии: УдалитьПриНажатии
                -
                    Тип: Кнопка
                    Имя: Обновить
                    ПриНажатии: ОбновитьПриНажатии
"""

LIST_XBSL = """
    импорт Основное

    @НаКлиенте
    метод УдалитьПриНажатии(Источник: Кнопка, Событие: СобытиеПриНажатии)
        УдалитьНаСервере(ТекущаяКоманда)
    ;

    @НаКлиенте
    метод ОбновитьПриНажатии(Источник: Кнопка, Событие: СобытиеПриНажатии)
        Команды.Удалить(ТекущаяКоманда)
    ;

    @НаСервере @ДоступноСКлиента
    статический метод УдалитьНаСервере(Команда: Команды.Ссылка)
        {проверка}
        Команды.Удалить(Команда)
    ;
"""

# Без повышения прав удаление идёт по правам объекта — их проверяет платформа
PLAIN_COMMANDS = """
    @ВПроекте
    @НаСервере @ДоступноСКлиента
    статический метод Удалить(Команда: Команды.Ссылка)
        Команда.ЗагрузитьОбъект().Удалить()
    ;
"""

COMMANDS = """
    @ВПроекте
    @НаСервере @ДоступноСКлиента
    статический метод Удалить(Команда: Команды.Ссылка)
        исп КонтекстДоступа.Привилегированный()
        Команда.ЗагрузитьОбъект().Удалить()
    ;
"""

ADMIN = """
    @ВПроекте
    @НаСервере
    статический метод ЭтоАдминистратор(): Булево
        возврат Пользователи.ТекущийПользователь.Администратор
    ;
"""


def test_admin_button_reaches_unchecked_writer(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, {
        "СписокКоманд.yaml": LIST_YAML, "СписокКоманд.xbsl": LIST_XBSL.format(проверка=""),
        "Команды.xbsl": COMMANDS, "Админ.xbsl": ADMIN})
    assert rc == 1
    assert [(f["rule"], f["line"]) for f in found] == [("ПР-02", 16)]
    message = found[0]["message"]
    assert message.startswith("Видимость ГруппаКоманд: элемент виден только администратору")
    assert "'СписокКоманд.УдалитьНаСервере'" in message


def test_check_on_server_is_not_a_finding(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, {
        "СписокКоманд.yaml": LIST_YAML,
        "СписокКоманд.xbsl": LIST_XBSL.format(проверка="если не Админ.ЭтоАдминистратор()\n"
                                                       "            выбросить новый ИсключениеВыполнения(\"\")\n"
                                                       "        ;"),
        "Команды.xbsl": COMMANDS, "Админ.xbsl": ADMIN})
    assert (rc, found) == (0, [])


def test_check_in_called_method_is_not_a_finding(tmp_path, monkeypatch, data_dir):
    commands = COMMANDS.replace("исп КонтекстДоступа", "ПроверитьПрава()\n    исп КонтекстДоступа") + """
        @ВПроекте
        @НаСервере
        статический метод ПроверитьПрава()
            если не Админ.ЭтоАдминистратор()
                выбросить новый ИсключениеВыполнения("")
            ;
        ;
    """
    # Обработчик зовёт метод другого модуля, а тот проверяет права через вызываемый
    xbsl = LIST_XBSL.format(проверка="").replace("УдалитьНаСервере(ТекущаяКоманда)",
                                                  "Команды.Удалить(ТекущаяКоманда)")
    xbsl = xbsl[:xbsl.index("    @НаСервере @ДоступноСКлиента")]
    rc, found = check(tmp_path, monkeypatch, data_dir, {
        "СписокКоманд.yaml": LIST_YAML,
        "СписокКоманд.xbsl": xbsl,
        "Команды.xbsl": textwrap.dedent(commands), "Админ.xbsl": ADMIN})
    assert (rc, found) == (0, [])


def test_button_visible_to_all_is_not_a_finding(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, {
        "СписокКоманд.yaml": LIST_YAML.replace("Видимость: =ДанныеПользователя.Администратор",
                                               "Видимость: =ЕстьКоманды"),
        "СписокКоманд.xbsl": LIST_XBSL.format(проверка=""),
        "Команды.xbsl": COMMANDS, "Админ.xbsl": ADMIN})
    assert (rc, found) == (0, [])


FORM_YAML = """
    ВидЭлемента: КомпонентИнтерфейса
    Имя: ПостФорма
    Наследует:
        Тип: ФормаОбъекта<Пост.Объект>
        Содержимое:
            Тип: Группа
            Содержимое:
                -
                    Тип: Флажок
                    Имя: ФлажокОбщая
                    Значение: =Объект.Общая
                    Видимость: =Администратор
                -
                    Тип: ПолеВвода<Строка>
                    Имя: Заголовок
                    Значение: =Объект.Заголовок
"""

POST_YAML = """
    ВидЭлемента: Справочник
    Имя: Пост
    КонтрольДоступа:
        Разрешения:
            Изменение: {изменение}
"""

OBJECT = """
    @Обработчик
    метод ПередЗаписью()
        {проверка}
        Дата = ДатаВремя.Сейчас()
    ;
"""


POST = POST_YAML.format(изменение="РазрешенияВычисляютсяДляКаждогоОбъекта")


def test_admin_field_without_check_in_object(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, {
        "ПостФорма.yaml": FORM_YAML, "Пост.Объект.xbsl": OBJECT.format(проверка=""), "Пост.yaml": POST,
        "Админ.xbsl": ADMIN})
    assert rc == 1
    assert [(f["rule"], f["line"]) for f in found] == [("ПР-02", 11)]
    assert found[0]["message"].startswith(
        "Видимость ФлажокОбщая: поле Общая видно только администратору, а 'Пост.ПередЗаписью'")


def test_admin_field_checked_in_object(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, {
        "ПостФорма.yaml": FORM_YAML, "Пост.yaml": POST,
        "Пост.Объект.xbsl": OBJECT.format(проверка="если Общая и не Админ.ЭтоАдминистратор()\n"
                                                    "            Общая = Ложь\n        ;"),
        "Админ.xbsl": ADMIN})
    assert (rc, found) == (0, [])


def test_agreed_finding(tmp_path, monkeypatch, data_dir):
    (tmp_path / "согласовано.txt").write_text(
        "IT/Проект/Основное/ПостФорма.yaml: ПР-02 Видимость ФлажокОбщая — модерация\n",
        encoding="utf-8")
    rc, found = check(tmp_path, monkeypatch, data_dir, {
        "ПостФорма.yaml": FORM_YAML, "Пост.Объект.xbsl": OBJECT.format(проверка=""), "Пост.yaml": POST,
        "Админ.xbsl": ADMIN}, "--agreed", "согласовано.txt")
    assert rc == 0
    assert len(found) == 1


def test_write_under_object_rights_is_not_a_finding(tmp_path, monkeypatch, data_dir):
    xbsl = LIST_XBSL.format(проверка="").replace("УдалитьНаСервере(ТекущаяКоманда)",
                                                  "Команды.Удалить(ТекущаяКоманда)")
    rc, found = check(tmp_path, monkeypatch, data_dir, {
        "СписокКоманд.yaml": LIST_YAML,
        "СписокКоманд.xbsl": xbsl[:xbsl.index("    @НаСервере @ДоступноСКлиента")],
        "Команды.xbsl": PLAIN_COMMANDS, "Админ.xbsl": ADMIN})
    assert (rc, found) == (0, [])


def test_admin_fields_reported_once_per_element(tmp_path, monkeypatch, data_dir):
    form = FORM_YAML.replace("""                -
                    Тип: ПолеВвода<Строка>
                    Имя: Заголовок
                    Значение: =Объект.Заголовок
""", """                    Содержимое:
                        -
                            Тип: ПолеВвода<Строка>
                            Имя: Код
                            Значение: =Объект.Код
""")
    rc, found = check(tmp_path, monkeypatch, data_dir, {
        "ПостФорма.yaml": form, "Пост.Объект.xbsl": OBJECT.format(проверка=""), "Пост.yaml": POST,
        "Админ.xbsl": ADMIN})
    assert rc == 1
    assert len(found) == 1
    assert "поля Общая, Код видны только администратору" in found[0]["message"]


@pytest.mark.parametrize("described", [
    POST_YAML.format(изменение="РазрешеноАдминистраторам"),
    "ВидЭлемента: Справочник\nИмя: Пост\n",
])
def test_admin_field_of_admin_only_object(tmp_path, monkeypatch, data_dir, described):
    rc, found = check(tmp_path, monkeypatch, data_dir, {
        "ПостФорма.yaml": FORM_YAML, "Пост.Объект.xbsl": OBJECT.format(проверка=""),
        "Пост.yaml": described, "Админ.xbsl": ADMIN})
    assert (rc, found) == (0, [])


def test_privileged_without_write_is_not_a_finding(tmp_path, monkeypatch, data_dir):
    # Запись идёт по правам объекта, повышение — только в пересчёте ключей после неё
    commands = """
        @ВПроекте
        @НаСервере @ДоступноСКлиента
        статический метод Удалить(Команда: Команды.Ссылка)
            Команда.ЗагрузитьОбъект().Удалить()
            ПересчитатьКлючи()
        ;

        @ВПроекте
        @НаСервере
        статический метод ПересчитатьКлючи()
            исп КонтекстДоступа.Привилегированный()
            КонтрольДоступа.ПересчитатьКлючиДоступа()
        ;
    """
    xbsl = LIST_XBSL.format(проверка="").replace("УдалитьНаСервере(ТекущаяКоманда)",
                                                  "Команды.Удалить(ТекущаяКоманда)")
    rc, found = check(tmp_path, monkeypatch, data_dir, {
        "СписокКоманд.yaml": LIST_YAML,
        "СписокКоманд.xbsl": xbsl[:xbsl.index("    @НаСервере @ДоступноСКлиента")],
        "Команды.xbsl": commands, "Админ.xbsl": ADMIN})
    assert (rc, found) == (0, [])
