"""ПР-04: разметка из данных выполняется в браузере без очистки. Положительные и отрицательные примеры."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from xbsl_sonar import cli, data

HELP = Path(__file__).parent / "help"


def контейнер(режим: str, содержимое: str) -> str:
    строка_режима = f"\n                    БезопасныйРежим: {режим}" if режим else ""
    return f"""
        ВидЭлемента: КомпонентИнтерфейса
        Имя: Форма
        Наследует:
            Тип: Форма
            Содержимое:
                Тип: Группа
                Содержимое:
                    -
                        Тип: КонтейнерHtml
                        Имя: Текст{строка_режима.replace(chr(10) + '                    ', chr(10) + '                        ')}
                        Содержимое: {содержимое}
                    -
                        Тип: Надпись
                        Имя: Подпись
    """


@pytest.fixture(scope="session")
def data_dir(tmp_path_factory) -> Path:
    return data.build(HELP, tmp_path_factory.mktemp("data"))


def check(tmp_path, monkeypatch, data_dir, files: dict[str, str], *extra: str) -> list[tuple[str, int]]:
    root = tmp_path / "IT" / "Проект" / "Основное"
    root.mkdir(parents=True)
    for name, text in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(textwrap.dedent(text).lstrip(), encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    cli.main(["check", "IT", "--data-dir", str(data_dir), "--rules", "ПР-04", "--json", "находки.json", *extra])
    found = json.loads((tmp_path / "находки.json").read_text(encoding="utf-8"))["findings"]
    return sorted((Path(f["path"]).name, f["line"]) for f in found if f["debt"] is None)


def test_unsafe_container_with_expression(tmp_path, monkeypatch, data_dir):
    found = check(tmp_path, monkeypatch, data_dir, {"Форма.yaml": контейнер("Ложь", "=Объект.Текст")})
    assert [имя for имя, _ in found] == ["Форма.yaml"]


def test_safe_mode_by_default(tmp_path, monkeypatch, data_dir):
    assert check(tmp_path, monkeypatch, data_dir, {"Форма.yaml": контейнер("", "=Объект.Текст")}) == []


def test_resource_literal(tmp_path, monkeypatch, data_dir):
    files = {"Форма.yaml": контейнер("Ложь", "=Ресурс{Страница.html}.Ссылка")}
    assert check(tmp_path, monkeypatch, data_dir, files) == []


def test_function_returning_resource(tmp_path, monkeypatch, data_dir):
    files = {
        "Форма.yaml": контейнер("Ложь", "=Страница()"),
        "Форма.xbsl": """
            метод Страница(): Строка
                возврат СтраницаНаСервере()
            ;

            @Локально
            @НаСервере @ДоступноСКлиента
            статический метод СтраницаНаСервере(): Строка
                возврат Ресурс{Страница.html}.ОткрытьПотокЧтения().ПрочитатьКакСтроку()
            ;
        """,
    }
    assert check(tmp_path, monkeypatch, data_dir, files) == []


def test_resource_with_escaped_substitution(tmp_path, monkeypatch, data_dir):
    files = {
        "Форма.yaml": контейнер("Ложь", "=Страница()"),
        "Форма.xbsl": """
            метод Страница(): Строка
                возврат Ресурс{Страница.html}.ОткрытьПотокЧтения().ПрочитатьКакСтроку()
                    .Заменить("@@", СериализацияJson.ЗаписатьОбъект(Данные).Заменить("<", "\\\\u003c"))
            ;
        """,
    }
    assert check(tmp_path, monkeypatch, data_dir, files) == []


def test_resource_with_raw_substitution(tmp_path, monkeypatch, data_dir):
    files = {
        "Форма.yaml": контейнер("Ложь", "=Страница()"),
        "Форма.xbsl": """
            метод Страница(): Строка
                возврат Ресурс{Страница.html}.ОткрытьПотокЧтения().ПрочитатьКакСтроку().Заменить("@@", Объект.Текст)
            ;
        """,
    }
    assert [имя for имя, _ in check(tmp_path, monkeypatch, data_dir, files)] == ["Форма.yaml"]


def test_assignment_in_module(tmp_path, monkeypatch, data_dir):
    files = {
        "Форма.yaml": контейнер("Ложь", "=Ресурс{Страница.html}.Ссылка"),
        "Форма.xbsl": """
            метод Показать(Текст: Строка)
                Компоненты.Текст.Содержимое = Текст
            ;

            метод Сбросить()
                Компоненты.Текст.Содержимое = Ресурс{Страница.html}.Ссылка
            ;
        """,
    }
    assert check(tmp_path, monkeypatch, data_dir, files) == [("Форма.xbsl", 2)]


def test_inner_html_in_resource(tmp_path, monkeypatch, data_dir):
    files = {
        "Ресурсы/Виджет.html": """
            <script>
            var ЗНАЧКИ = { a: '<b>a</b>' };
            function очистить(html) {
                var шаблон = document.createElement('template');
                шаблон.innerHTML = html || '';
                return шаблон.content;
            }
            function показать(узел, д, код) {
                узел.innerHTML = '';
                узел.innerHTML = ЗНАЧКИ[код];
                узел.innerHTML = (ЗНАЧКИ[код] || '') + '<span>';
                узел.innerHTML = д.Текст;
            }
            </script>
        """,
    }
    assert check(tmp_path, monkeypatch, data_dir, files) == [("Виджет.html", 12)]


def test_other_sanitizer(tmp_path, monkeypatch, data_dir):
    files = {
        "Ресурсы/Виджет.html": """
            <script>
            function почистить(html) {
                var шаблон = document.createElement('template');
                шаблон.innerHTML = html;
            }
            </script>
        """,
    }
    assert check(tmp_path, monkeypatch, data_dir, files, "--sanitizers", "почистить") == []


def test_unknown_sanitizer_is_a_finding(tmp_path, monkeypatch, data_dir):
    files = {
        "Ресурсы/Виджет.html": """
            <script>
            function почистить(html) {
                var шаблон = document.createElement('template');
                шаблон.innerHTML = html;
            }
            </script>
        """,
    }
    assert check(tmp_path, monkeypatch, data_dir, files) == [("Виджет.html", 4)]


def test_agreed_finding(tmp_path, monkeypatch, data_dir):
    (tmp_path / "согласовано.txt").write_text(
        "# путь: ПР-04 Ключ — причина\n"
        "IT/Проект/Основное/Форма.yaml: ПР-04 КонтейнерHtml Текст — экранировано при подстановке\n"
        "IT/Проект/Основное/Чужая.yaml: ПР-04 КонтейнерHtml Текст\n",
        encoding="utf-8")
    files = {"Форма.yaml": контейнер("Ложь", "=Объект.Текст")}
    assert check(tmp_path, monkeypatch, data_dir, files, "--agreed", "согласовано.txt") == []


def test_agreed_needs_reason(tmp_path, monkeypatch, data_dir):
    (tmp_path / "согласовано.txt").write_text(
        "IT/Проект/Основное/Форма.yaml: ПР-04 КонтейнерHtml Текст\n", encoding="utf-8")
    files = {"Форма.yaml": контейнер("Ложь", "=Объект.Текст")}
    assert [имя for имя, _ in check(tmp_path, monkeypatch, data_dir, files, "--agreed", "согласовано.txt")] == ["Форма.yaml"]
