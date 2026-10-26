"""ПР-08: загрузка файла без проверки размера и типа. Положительные и отрицательные примеры."""

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


def check(tmp_path, monkeypatch, data_dir, code: str, form: str = "",
          files: dict[str, str] | None = None) -> list[tuple[str, str, int]]:
    """Модуль `Модуль.xbsl`, форма `Форма.xbsl` (из неё идёт загрузка) и прочие файлы рядом."""
    folder = tmp_path / "IT" / "Проект" / "Основное"
    folder.mkdir(parents=True)
    (folder / "Модуль.xbsl").write_text(textwrap.dedent(code).lstrip(), encoding="utf-8")
    if form:
        (folder / "Форма.xbsl").write_text(textwrap.dedent(form).lstrip(), encoding="utf-8")
    for name, text in (files or {}).items():
        (folder / name).write_text(textwrap.dedent(text).lstrip(), encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    cli.main(["check", "IT", "--data-dir", str(data_dir), "--rules", "ПР-08", "--json", "находки.json"])
    found = json.loads((tmp_path / "находки.json").read_text(encoding="utf-8"))["findings"]
    return [(f["rule"], Path(f["path"]).name, f["line"]) for f in found]


UPLOAD = """
    метод ФайлПриВыборе(Источник: ВыборФайлов, Событие: СобытиеПриИзменении<ЧитаемыйМассив<ВыбранныйФайл>>)
        знч Ссылка = ЗагрузкаФайлов.НачатьЗагрузку(Событие.НовоеЗначение.Первый()).ПолучитьРезультат()
        Модуль.Сохранить(Ссылка)
    ;
"""

COMMON = """
    @ВПроекте
    @НаСервере @ДоступноСКлиента
    метод ЭтоАдминистратор(): Булево
        возврат Запрос{ВЫБРАТЬ ПЕРВЫЕ 1 Пользователи.Администратор ИЗ Пользователи КАК Пользователи
            ГДЕ Пользователи.Ссылка == %{Пользователи.ТекущийПользователь}}.Выполнить().ЕдинственныйИлиНеопределено()?.Администратор ?? Ложь
    ;
"""


def test_uploaded_file_saved_without_checks(tmp_path, monkeypatch, data_dir):
    assert check(tmp_path, monkeypatch, data_dir, """
        @НаСервере @ДоступноСКлиента
        метод Сохранить(Файл: ДвоичныйОбъект.Ссылка)
            знч Вложение = новый Вложения.Объект()
            Вложение.Файл = Файл
            Вложение.Записать()
        ;
    """, UPLOAD) == [("ПР-08", "Модуль.xbsl", 2)]


def test_file_reaches_reader_through_calls(tmp_path, monkeypatch, data_dir):
    assert check(tmp_path, monkeypatch, data_dir, """
        @НаСервере @ДоступноСКлиента
        метод Сохранить(Файл: ДвоичныйОбъект.Ссылка): Строка
            возврат Прочитать(Файл)
        ;

        @НаСервере @ДоступноСКлиента
        метод Прочитать(Файл: ДвоичныйОбъект.Ссылка): Строка
            исп Поток = Файл.Загрузить().ОткрытьПотокЧтения()
            возврат Поток.ПрочитатьКакСтроку()
        ;
    """, UPLOAD) == [("ПР-08", "Модуль.xbsl", 7)]


def test_type_only_selects_preview(tmp_path, monkeypatch, data_dir):
    assert check(tmp_path, monkeypatch, data_dir, """
        @НаСервере @ДоступноСКлиента
        метод Сохранить(Файл: ДвоичныйОбъект.Ссылка): ДвоичныйОбъект.Ссылка?
            знч Объект = Файл.Загрузить()
            если Объект.ТипСодержимого == "image/png"
                знч Картинка = новый ОбрабатываемоеИзображение(Объект.ОткрытьПотокЧтения())
                возврат ОбъектноеХранилище.Загрузить("превью", Картинка.ПолучитьИзображение()).Ссылка
            ;
            возврат Неопределено
        ;
    """, UPLOAD) == [("ПР-08", "Модуль.xbsl", 2)]


def test_http_body_read_as_bytes(tmp_path, monkeypatch, data_dir):
    assert check(tmp_path, monkeypatch, data_dir, """
        метод ОбработатьЗагрузку(Запрос: HttpСервисЗапрос)
            знч Файл = ОбъектноеХранилище.Загрузить("файл", Запрос.Тело.ПрочитатьКакБайты())
            Запрос.Ответ.УстановитьТело(Файл.Ссылка.Ид.ВСтроку())
        ;
    """) == [("ПР-08", "Модуль.xbsl", 1)]


def test_form_writes_upload_into_attribute(tmp_path, monkeypatch, data_dir):
    assert check(tmp_path, monkeypatch, data_dir, "", files={
        "КарточкаФорма.yaml": """
            ВидЭлемента: КомпонентИнтерфейса
            Имя: КарточкаФорма
            Наследует:
                Тип: ФормаОбъекта<Карточки.Объект>
        """,
        "КарточкаФорма.xbsl": """
            метод ОбложкаПриВыборе(Источник: ВыборФайлов, Событие: СобытиеПриИзменении<ЧитаемыйМассив<ВыбранныйФайл>>)
                Объект.Обложка = ЗагрузкаФайлов.НачатьЗагрузку(Событие.НовоеЗначение.Первый()).ПолучитьРезультат()
            ;
        """,
    }) == [("ПР-08", "КарточкаФорма.xbsl", 2)]


def test_size_and_type_checked(tmp_path, monkeypatch, data_dir):
    assert check(tmp_path, monkeypatch, data_dir, """
        @НаСервере @ДоступноСКлиента
        метод Сохранить(Файл: ДвоичныйОбъект.Ссылка)
            знч Объект = Файл.Загрузить()
            если Объект.Размер > 5мб
                выбросить новый ИсключениеНедопустимоеСостояние("Файл больше 5 Мб")
            ;
            если Объект.РасширениеФайла != "pdf"
                выбросить новый ИсключениеНедопустимоеСостояние("Принимается только PDF")
            ;
            знч Вложение = новый Вложения.Объект()
            Вложение.Файл = Файл
            Вложение.Записать()
        ;
    """, UPLOAD) == []


def test_choice_of_extension_with_refusal_is_a_type_check(tmp_path, monkeypatch, data_dir):
    assert check(tmp_path, monkeypatch, data_dir, """
        @НаСервере @ДоступноСКлиента
        метод Сохранить(Файл: ДвоичныйОбъект.Ссылка)
            знч Объект = Файл.Загрузить()
            если Объект.Размер > 5мб
                выбросить новый ИсключениеНедопустимоеСостояние("Файл больше 5 Мб")
            ;
            выбор Объект.РасширениеФайла
            когда "pdf", "docx"
                Объект.ОткрытьПотокЧтения()
            иначе
                выбросить новый ИсключениеНедопустимыйАргумент("Не тот тип")
            ;
        ;
    """, UPLOAD) == []


def test_image_reencoded_counts_as_type_but_not_size(tmp_path, monkeypatch, data_dir):
    assert check(tmp_path, monkeypatch, data_dir, """
        @НаСервере @ДоступноСКлиента
        метод Сохранить(Файл: ДвоичныйОбъект.Ссылка): ДвоичныйОбъект.Ссылка
            знч Картинка = новый ОбрабатываемоеИзображение(Файл.Загрузить().ОткрытьПотокЧтения())
            возврат ОбъектноеХранилище.Загрузить("фото", Картинка.ПолучитьИзображение()).Ссылка
        ;
    """, UPLOAD) == [("ПР-08", "Модуль.xbsl", 2)]


def test_admin_upload_is_not_a_finding(tmp_path, monkeypatch, data_dir):
    assert check(tmp_path, monkeypatch, data_dir, """
        @Локально
        метод ПроверитьПрава()
            если не ОбщийМодуль.ЭтоАдминистратор()
                выбросить новый ИсключениеНедопустимоеСостояние("Только администратор")
            ;
        ;

        @НаСервере @ДоступноСКлиента
        метод Сохранить(Файл: ДвоичныйОбъект.Ссылка)
            ПроверитьПрава()
            исп Поток = Файл.Загрузить().ОткрытьПотокЧтения()
            Пакеты.Применить(Поток.ПрочитатьКакСтроку())
        ;
    """, UPLOAD, {"ОбщийМодуль.xbsl": COMMON}) == []


def test_stored_file_not_from_upload_is_not_a_finding(tmp_path, monkeypatch, data_dir):
    assert check(tmp_path, monkeypatch, data_dir, """
        @НаСервере @ДоступноСКлиента
        метод ВосстановитьВерсию(Версия: ДвоичныйОбъект.Ссылка)
            исп Поток = Версия.Загрузить().ОткрытьПотокЧтения()
            Страницы.Восстановить(Поток.ПрочитатьКакСтроку())
        ;
    """, """
        метод ВосстановитьПриНажатии(Команда: ОбычнаяКоманда)
            Модуль.ВосстановитьВерсию(Компоненты.Версии.ВыделеннаяСтрока.Версия)
        ;
    """) == []


def test_json_body_and_server_only_method_are_not_findings(tmp_path, monkeypatch, data_dir):
    assert check(tmp_path, monkeypatch, data_dir, """
        метод ОбработатьСообщение(Запрос: HttpСервисЗапрос)
            Сообщения.Принять(Запрос.Тело.ПрочитатьКакСтроку())
        ;

        @НаСервере
        метод Сохранить(Файл: ДвоичныйОбъект.Ссылка)
            знч Вложение = новый Вложения.Объект()
            Вложение.Файл = Файл
            Вложение.Записать()
        ;
    """, UPLOAD) == []


def test_reading_properties_of_stored_file_is_not_a_finding(tmp_path, monkeypatch, data_dir):
    assert check(tmp_path, monkeypatch, data_dir, """
        @НаСервере @ДоступноСКлиента
        метод Сохранить(Файл: ДвоичныйОбъект.Ссылка): Строка
            возврат Файл.Загрузить().ИмяФайла
        ;
    """, UPLOAD) == []
