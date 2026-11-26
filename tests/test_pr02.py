"""ПР-02: действие, которое интерфейс показывает только администратору, без проверки на сервере."""

from __future__ import annotations

import json
import os
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
        path = tmp_path / "компоненты" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(code).lstrip(), encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    rc = cli.main(["check", "компоненты", "--data-dir", str(data_dir), "--rules", "ПР-02",
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
    assert message.startswith("Видимость ГруппаКоманд: интерфейс ограничивает доступ к элементу")
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

# Модуль типа: расчёт разрешений выдаёт изменение всем вошедшим — объект открыт
POST_TYPE_OPEN = """
    @Обработчик
    метод ВычислитьРазрешенияДоступа(): ЧитаемаяКоллекция<РазрешениеДоступа>
        возврат [новый РазрешениеДоступа([новый КлючДоступаДляАутентифицированных.Объект()],
            [Сущность.Право.Чтение, Сущность.Право.Изменение])]
    ;
"""

# Изменение — только своему ключу редакторов, всем вошедшим — чтение: объект закрыт
POST_TYPE_OWN_KEY = """
    @Обработчик
    метод ВычислитьРазрешенияДоступа(): ЧитаемаяКоллекция<РазрешениеДоступа>
        возврат [
            новый РазрешениеДоступа([новый КлючРедакторов.Объект()], [Сущность.Право.Изменение]),
            новый РазрешениеДоступа([новый КлючДоступаДляАутентифицированных.Объект()],
                [Сущность.Право.Чтение])]
    ;
"""

# Права переменной, а не списком: не знаем — считаем выданными
POST_TYPE_RIGHTS_VARIABLE = """
    @Обработчик
    метод ВычислитьРазрешенияДоступа(): ЧитаемаяКоллекция<РазрешениеДоступа>
        знч Права = ПраваПоНастройке()
        возврат [новый РазрешениеДоступа([новый КлючДоступаДляВсех.Объект()], Права)]
    ;
"""


def test_admin_field_without_check_in_object(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, {
        "ПостФорма.yaml": FORM_YAML, "Пост.Объект.xbsl": OBJECT.format(проверка=""), "Пост.yaml": POST, "Пост.xbsl": POST_TYPE_OPEN,
        "Админ.xbsl": ADMIN})
    assert rc == 1
    assert [(f["rule"], f["line"]) for f in found] == [("ПР-02", 11)]
    assert found[0]["message"].startswith(
        "Видимость ФлажокОбщая: поле Общая ограничено в интерфейсе, а 'Пост.ПередЗаписью'")


def test_admin_field_checked_in_object(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, {
        "ПостФорма.yaml": FORM_YAML, "Пост.yaml": POST, "Пост.xbsl": POST_TYPE_OPEN,
        "Пост.Объект.xbsl": OBJECT.format(проверка="если Общая и не Админ.ЭтоАдминистратор()\n"
                                                    "            Общая = Ложь\n        ;"),
        "Админ.xbsl": ADMIN})
    assert (rc, found) == (0, [])


def test_agreed_finding(tmp_path, monkeypatch, data_dir):
    (tmp_path / "согласовано.txt").write_text(
        "компоненты/ПостФорма.yaml: ПР-02 Видимость ФлажокОбщая — модерация\n",
        encoding="utf-8")
    rc, found = check(tmp_path, monkeypatch, data_dir, {
        "ПостФорма.yaml": FORM_YAML, "Пост.Объект.xbsl": OBJECT.format(проверка=""), "Пост.yaml": POST, "Пост.xbsl": POST_TYPE_OPEN,
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
        "ПостФорма.yaml": form, "Пост.Объект.xbsl": OBJECT.format(проверка=""), "Пост.yaml": POST, "Пост.xbsl": POST_TYPE_OPEN,
        "Админ.xbsl": ADMIN})
    assert rc == 1
    assert len(found) == 1
    assert "поля Общая, Код ограничены в интерфейсе" in found[0]["message"]


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


@pytest.mark.parametrize("type_module", [POST_TYPE_OWN_KEY, None])
def test_computed_rights_without_open_key_is_not_a_finding(tmp_path, monkeypatch, data_dir, type_module):
    files = {"ПостФорма.yaml": FORM_YAML, "Пост.Объект.xbsl": OBJECT.format(проверка=""), "Пост.yaml": POST,
             "Админ.xbsl": ADMIN}
    if type_module:
        files["Пост.xbsl"] = type_module
    rc, found = check(tmp_path, monkeypatch, data_dir, files)
    assert (rc, found) == (0, [])


def test_computed_rights_given_by_variable_are_open(tmp_path, monkeypatch, data_dir):
    rc, found = check(tmp_path, monkeypatch, data_dir, {
        "ПостФорма.yaml": FORM_YAML, "Пост.Объект.xbsl": OBJECT.format(проверка=""), "Пост.yaml": POST,
        "Пост.xbsl": POST_TYPE_RIGHTS_VARIABLE, "Админ.xbsl": ADMIN})
    assert rc == 1
    assert [(f["rule"], f["line"]) for f in found] == [("ПР-02", 11)]

def test_vendor_democrm_matches_review(tmp_path, monkeypatch, data_dir):
    vendor = os.environ.get("XBSL_VENDOR_DEMO")
    if not vendor:
        pytest.skip("Укажите XBSL_VENDOR_DEMO для сверки с исходниками вендора")
    source = Path(vendor).resolve() / "DemoCRM"
    assert source.is_dir()
    monkeypatch.chdir(tmp_path)
    output = tmp_path / "vendor.json"
    cli.main(["check", str(source), "--data-dir", str(data_dir), "--rules", "ПР-02", "--json", str(output)])
    findings = json.loads(output.read_text(encoding="utf-8"))["findings"]
    assert [(Path(f["path"]).name, f["line"]) for f in findings] == [
        ("СотрудникиФормаОбъекта.yaml", 35),
    ]

@pytest.mark.parametrize(("condition", "found"), [
    ("Редактирование.ЕстьПраво()", True),
    ("Проверки.Можно()", True),
    ("не Редактирование.ЕстьПраво()", False),
    ("Редактирование.ЕстьПраво() или ЕстьКоманды", False),
    ("АдминистраторПанели", False),
])
def test_interface_action_right(tmp_path, monkeypatch, data_dir, condition, found):
    _, findings = check(tmp_path, monkeypatch, data_dir, {
        "СписокКоманд.yaml": LIST_YAML.replace("ДанныеПользователя.Администратор", condition),
        "СписокКоманд.xbsl": LIST_XBSL.format(проверка="исп КонтекстДоступа.Привилегированный()"),
        "Редактирование.yaml": "ВидЭлемента: ПравоНаДействие\nИмя: Редактирование\n",
        "Проверки.xbsl": """
            метод Можно(): Булево
                возврат Определить()
            ;
            метод Определить(): Булево
                возврат Редактирование.ЕстьПраво()
            ;
        """,
    })
    assert bool(findings) is found

def test_action_right_is_enforced_on_server(tmp_path, monkeypatch, data_dir):
    _, findings = check(tmp_path, monkeypatch, data_dir, {
        "СписокКоманд.yaml": LIST_YAML.replace(
            "ДанныеПользователя.Администратор", "Редактирование.ЕстьПраво()"),
        "СписокКоманд.xbsl": LIST_XBSL.format(
            проверка="Редактирование.Проверить()\n        исп КонтекстДоступа.Привилегированный()"),
        "Редактирование.yaml": "ВидЭлемента: ПравоНаДействие\nИмя: Редактирование\n",
    })
    assert findings == []

def test_form_can_be_nested_below_object_metadata(tmp_path, monkeypatch, data_dir):
    _, findings = check(tmp_path, monkeypatch, data_dir, {
        "экраны/вкладки/редакторы/ПостФорма.yaml": FORM_YAML,
        "Пост.Объект.xbsl": OBJECT.format(проверка=""),
        "Пост.yaml": POST,
        "Пост.xbsl": POST_TYPE_OPEN,
        "Админ.xbsl": ADMIN,
    })
    assert len(findings) == 1
