"""Правила xbsl-sonar для движка keyfire/xbsl.

Модуль подключается точкой расширения `xbsl.rules`: импорт регистрирует правила декоратором
`@rule`. Встроенные правила движка в анализе не участвуют — запуск идёт с `--select` только
по правилам отсюда (`RULE_IDS`).

Одна проверка — одно правило; код правила — `ПР-NN`, как в своде проверок. Описание
для SonarQube — в `RULES`: из него собирается файл описаний (`xbsl-sonar rules-file`).
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterable
from dataclasses import dataclass

from xbsl.diagnostics import Diagnostic, Severity
from xbsl.engine import SourceFile, rule
from xbsl.rules._syntax import code_tokens, query_ranges


@dataclass(frozen=True)
class RuleText:
    code: str
    name: str
    description: str
    type: str  # BUG | VULNERABILITY | CODE_SMELL | SECURITY_HOTSPOT
    severity: str  # INFO | MINOR | MAJOR | CRITICAL | BLOCKER
    cwe: str
    effort_minutes: int


RULES: dict[str, RuleText] = {
    "ПР-01": RuleText(
        code="ПР-01",
        name="Объект по ссылке с клиента под повышенными правами",
        description=(
            "<p>Метод, доступный с клиента, принимает ссылку на объект и работает с ней "
            "в привилегированном контексте, ни разу не сверившись с текущим пользователем. "
            "Аргументы такого метода приходят с клиента: подставив чужую ссылку, пользователь "
            "прочитает или изменит то, на что у него нет прав, — права объекта "
            "привилегированный контекст отключает.</p>"
            "<p><b>Находка:</b> метод с аннотациями <code>@НаСервере @ДоступноСКлиента</code>, "
            "у которого есть параметр типа <code>….Ссылка</code>, в теле открыт "
            "<code>КонтекстДоступа.Привилегированный()</code>, а сверки с текущим "
            "пользователем нет. Сверка — вызов метода, который читает текущего пользователя "
            "или сам зовёт такой метод (набор собирается по всему проверяемому коду: "
            "<code>ПолучитьУчастника()</code>, <code>ЭтоАдминистратор()</code>, "
            "<code>ПроверитьПрава()</code>…), либо <code>ТекущийПользователь</code> в условии "
            "<code>если</code>, либо проверка права объекта <code>КонтрольДоступа.ПроверитьПраво</code> "
            "или <code>ЕстьПраво</code> до повышения прав. Текущий пользователь, только "
            "записанный в данные, сверкой не считается.</p>"
            "<p><b>Не находка:</b> метод без параметров-ссылок (участник берётся на сервере); "
            "метод без привилегированного контекста — действуют права объекта; метод, "
            "сверяющий ссылку с текущим пользователем или проверяющий администратора.</p>"
            "<p><b>Как исправить:</b> брать текущего пользователя или участника на сервере, "
            "а не из параметра; если ссылка нужна — сверить её с текущим пользователем "
            "до открытия привилегированного контекста или не повышать права.</p>"
            "<p>CWE-639: Authorization Bypass Through User-Controlled Key; CWE-862, CWE-863 "
            "(OWASP A01:2021 Broken Access Control).</p>"
        ),
        type="VULNERABILITY",
        severity="CRITICAL",
        cwe="CWE-639",
        effort_minutes=30,
    ),
    "ПР-15": RuleText(
        code="ПР-15",
        name="Обращение к данным в цикле",
        description=(
            "<p>На каждый виток цикла уходит отдельное обращение: запрос к базе или вызов "
            "сервера из клиентского метода. "
            "Цена метода растёт вместе с данными и видна только на настоящих объёмах.</p>"
            "<p><b>Находка:</b></p><ul>"
            "<li>литерал <code>Запрос{…}</code> в теле цикла <code>для</code>: запрос "
            "с параметром из витка повторяется на каждом витке, а без него — тем более "
            "выносится из цикла;</li>"
            "<li>в методе с окружением <code>@НаКлиенте</code> вызов в теле цикла метода того "
            "же модуля с окружением <code>@НаСервере</code> (и без <code>@НаКлиенте</code>).</li>"
            "</ul><p><b>Не находка:</b> запрос в заголовке цикла (<code>для Стр из "
            "Запрос{…}.Выполнить()</code>) — цикл по результату самого запроса; запрос "
            "в цикле <code>пока</code> — обход порциями или по уровням дерева; запись "
            "и загрузка объекта в цикле — штатный способ записать набор объектов.</p>"
            "<p><b>Как исправить:</b> собрать значения витков в массив и выполнить один "
            "запрос с условием <code>В (%Значения)</code>; вызов сервера — один на весь "
            "набор, с массивом в параметре.</p>"
            "<p>CWE-1050: Excessive Platform Resource Consumption within a Loop "
            "(ISO/IEC 5055, производительность).</p>"
        ),
        type="CODE_SMELL",
        severity="MAJOR",
        cwe="CWE-1050",
        effort_minutes=30,
    ),
    "ПР-03": RuleText(
        code="ПР-03",
        name="Точка без аутентификации вне согласованного перечня",
        description=(
            "<p>Элемент открыт тем, кто не вошёл в приложение, или код гостя работает "
            "с повышенными правами. Каждая такая точка — часть периметра безопасности: "
            "её открывают намеренно и проверяют отдельно, а не узнают о ней после выпуска.</p>"
            "<p><b>Находка:</b></p><ul>"
            "<li>в YAML — <code>РежимАутентификации: НеАутентифицированный</code>, "
            "право со значением <code>РазрешеноВсем</code> (в том числе "
            "<code>Вызов: РазрешеноВсем</code> HTTP-сервиса), элемент "
            "<code>ВидЭлемента: HttpСервис</code>;</li>"
            "<li>в XBSL — <code>КонтекстДоступа.Привилегированный()</code> в модуле элемента, "
            "у которого в паре <code>.yaml</code> задан "
            "<code>РежимАутентификации: НеАутентифицированный</code>.</li>"
            "</ul><p><b>Не находка:</b> точка из перечня периметра (параметр "
            "<code>--perimeter</code>: строка <code>путь: Ключ</code>) или с пометкой "
            "<code>анализ:периметр — причина</code> в строке находки или строкой выше; "
            "права <code>РазрешеноАутентифицированным</code> и уже; привилегированный "
            "контекст в модуле элемента для вошедших.</p>"
            "<p><b>Как исправить:</b> если точка открыта намеренно — внести её в перечень "
            "периметра, чтобы решение было видно в PR; если нет — закрыть: права "
            "<code>РазрешеноАутентифицированным</code>, без повышения прав в коде гостя.</p>"
            "<p>CWE-732: Incorrect Permission Assignment for Critical Resource; CWE-284, "
            "CWE-276 (OWASP A01:2021 Broken Access Control).</p>"
        ),
        type="VULNERABILITY",
        severity="MAJOR",
        cwe="CWE-732",
        effort_minutes=15,
    ),
    "ПР-04": RuleText(
        code="ПР-04",
        name="Разметка из данных выполняется в браузере без очистки",
        description=(
            "<p>Разметка, пришедшая из данных, вставляется в страницу там, где браузер "
            "выполнит её скрипты: в HTML-контейнер с выключенным безопасным режимом или "
            "присваиванием <code>innerHTML</code> в скрипте ресурса. Текст, который ввёл "
            "пользователь, становится кодом у того, кто его открыл.</p>"
            "<p><b>Находка:</b></p><ul>"
            "<li>в YAML — компонент <code>КонтейнерHtml</code> с <code>БезопасныйРежим: Ложь</code>, "
            "у которого <code>Содержимое</code> — выражение (<code>=…</code>), а не "
            "<code>Ресурс{…}</code>: содержимое считается при работе и может прийти из данных;</li>"
            "<li>в XBSL — присваивание <code>….Имя.Содержимое = …</code> компоненту такого "
            "контейнера из пары <code>.yaml</code>, если справа не <code>Ресурс{…}</code>;</li>"
            "<li>в ресурсе <code>.html</code> / <code>.js</code> — <code>.innerHTML = …</code> "
            "со значением, которое не строковый литерал, вне функции очистки "
            "(по умолчанию <code>очистить</code>; параметр <code>--sanitizers</code>).</li>"
            "</ul><p><b>Не находка:</b> контейнер с безопасным режимом по умолчанию — платформа "
            "запрещает в нём запуск скриптов; содержимое из ресурса; <code>innerHTML</code> "
            "внутри функции очистки или со строковым литералом.</p>"
            "<p><b>Как исправить:</b> оставить безопасный режим; если скрипт нужен — давать "
            "контейнеру ресурс, а данные передавать вызовом функции скрипта; в скрипте — "
            "пропускать разметку через функцию очистки с перечнем разрешённых тегов "
            "или писать текст через <code>textContent</code>.</p>"
            "<p>CWE-79: Improper Neutralization of Input During Web Page Generation "
            "(OWASP A03:2021 Injection).</p>"
        ),
        type="VULNERABILITY",
        severity="CRITICAL",
        cwe="CWE-79",
        effort_minutes=30,
    ),
}

RULE_IDS = tuple(RULES)

# `конструктор` не открывает блок (у маркера в структуре нет `;`), как и в движке.
_OPENERS = {
    "METHOD", "STRUCTURE", "ENUMERATION", "EXCEPTION",
    "IF", "FOR", "WHILE", "TRY", "CASE", "SCOPE",
}
_CLIENT = {"НаКлиенте", "OnClient"}
_SERVER = {"НаСервере", "OnServer"}
_FROM_CLIENT = {"ДоступноСКлиента", "AvailableFromClient"}
_PRIVILEGED = {"Привилегированный", "Privileged"}
_CURRENT_USER = {"ТекущийПользователь", "CurrentUser"}
_REFERENCE = {"Ссылка", "Ref"}
# `КонтрольДоступа.ПроверитьПраво(Объект, …)` / `ЕстьПраво` — сверка правами самого объекта
_RIGHT_CHECK = {"ПроверитьПраво", "ЕстьПраво", "CheckRight", "HasRight"}

# Методы проверяемого кода, которые читают текущего пользователя: их собирает `check`
# до запуска движка (`identity_methods`) и передаёт сюда через окружение.
IDENTITY_ENV = "XBSL_SONAR_IDENTITY"
# Функции очистки разметки для ПР-04 — параметр `--sanitizers` команды `check`.
SANITIZERS_ENV = "XBSL_SONAR_SANITIZERS"
DEFAULT_SANITIZERS = ("очистить",)


@dataclass
class _Frame:
    canonical: str
    line: int
    body: int = 0  # индекс первого токена тела: заголовок цикла выполняется один раз
    method: str | None = None
    client: bool = False


def _annotations(toks: list, i: int) -> set[str]:
    """Имена аннотаций перед токеном `метод` с индексом i (`@Имя` подряд, можно с переносом)."""
    names: set[str] = set()
    k = i - 1
    while k >= 1 and toks[k].kind in ("IDENT", "KEYWORD") and toks[k - 1].kind == "OP" \
            and toks[k - 1].value == "@":
        names.add(toks[k].value)
        k -= 2
    return names


def _method_name(toks: list, i: int) -> str | None:
    j = i + 1
    if j < len(toks) and toks[j].kind == "IDENT":
        return toks[j].value
    return None


def _server_methods(toks: list) -> set[str]:
    found: set[str] = set()
    for i, t in enumerate(toks):
        if t.kind == "KEYWORD" and t.canonical == "METHOD" and t.value[:1].islower():
            ann = _annotations(toks, i)
            name = _method_name(toks, i)
            if name and ann & _SERVER and not ann & _CLIENT:
                found.add(name)
    return found


def _body_start(source: SourceFile, toks: list, i: int) -> int:
    """Индекс первого токена тела цикла, открытого токеном i.

    Заголовок — строка `для`/`пока` и её продолжение: незакрытые скобки, литерал запроса
    (его содержимого нет среди токенов кода, поэтому строка продолжается до конца литерала)
    и строки, начатые с `.` или `?.` — цепочка вызовов от выражения заголовка.
    """
    depth = 0
    line = toks[i].line
    k = i + 1
    while k < len(toks):
        t = toks[k]
        if t.line > line and depth == 0 and not (t.kind == "OP" and t.value in (".", "?.")):
            return k
        if t.kind == "OP" and t.value in "([{":
            depth += 1
        elif t.kind == "OP" and t.value in ")]}":
            depth -= 1
        elif t.kind == "KEYWORD" and t.canonical == "QUERY":
            rng = next(((a, b) for a, b in query_ranges(source) if a >= t.start), None)
            if rng is not None:
                line = source.text.count("\n", 0, rng[1]) + 1
                k += 1
                continue
        line = max(line, t.line)
        k += 1
    return k


@rule("ПР-15", "Обращение к данным в цикле", "D", severity=Severity.WARNING)
def access_in_loop(source: SourceFile) -> Iterable[Diagnostic]:
    if source.kind != "xbsl":
        return []
    toks = code_tokens(source)
    servers = _server_methods(toks)
    frames: list[_Frame] = []
    out: list[Diagnostic] = []
    prev = None
    for i, t in enumerate(toks):
        if t.kind == "KEYWORD" and t.canonical in _OPENERS and t.value[:1].islower():
            is_else_if = (t.canonical == "IF" and prev is not None and prev.kind == "KEYWORD"
                          and prev.canonical == "ELSE" and prev.line == t.line)
            is_abstract = (t.canonical == "METHOD" and prev is not None and prev.kind == "KEYWORD"
                           and prev.canonical == "ABSTRACT")
            if not is_else_if and not is_abstract:
                frame = _Frame(t.canonical, t.line)
                if t.canonical in ("FOR", "WHILE"):
                    frame.body = _body_start(source, toks, i)
                elif t.canonical == "METHOD":
                    frame.method = _method_name(toks, i)
                    frame.client = bool(_annotations(toks, i) & _CLIENT)
                frames.append(frame)
        elif t.kind == "OP" and t.value == ";":
            if frames:
                frames.pop()
        elif t.kind == "KEYWORD" and t.canonical == "QUERY":
            loop = next((f for f in reversed(frames) if f.canonical == "FOR" and i >= f.body), None)
            if loop is not None:
                out.append(Diagnostic(
                    source.rel, t.line, t.col, "ПР-15", Severity.WARNING,
                    f"Запрос в теле цикла 'для' (строка {loop.line}): каждый виток – отдельное "
                    f"обращение к базе. Собрать значения в массив и выполнить один запрос "
                    f"с условием 'В (%Значения)' или вынести запрос из цикла.",
                ))
        elif (t.kind == "IDENT" and t.value in servers and i + 1 < len(toks)
              and toks[i + 1].kind == "OP" and toks[i + 1].value == "("
              and not (prev is not None and prev.kind == "OP" and prev.value in (".", "?."))
              and not (prev is not None and prev.kind == "KEYWORD" and prev.canonical == "METHOD")):
            method = next((f for f in reversed(frames) if f.canonical == "METHOD"), None)
            loop = next((f for f in reversed(frames)
                         if f.canonical in ("FOR", "WHILE") and i >= f.body), None)
            if method is not None and method.client and loop is not None:
                out.append(Diagnostic(
                    source.rel, t.line, t.col, "ПР-15", Severity.WARNING,
                    f"Вызов серверного метода '{t.value}' в цикле (строка {loop.line}) "
                    f"клиентского метода '{method.method}': каждый виток – отдельный вызов "
                    f"сервера. Передать на сервер весь набор одним вызовом.",
                ))
        prev = t
    return out


def _reference_params(toks: list, i: int) -> list[str]:
    """Имена параметров метода (токен `метод` с индексом i), тип которых — `….Ссылка`."""
    k = i + 2
    if k >= len(toks) or toks[k].value != "(":
        return []
    depth, names, current, is_ref = 0, [], None, False
    while k < len(toks):
        t = toks[k]
        if t.kind == "OP" and t.value in "(<[":
            depth += 1
        elif t.kind == "OP" and t.value in ")>]":
            depth -= 1
            if depth == 0:
                break
        elif t.kind == "OP" and t.value == "," and depth == 1:
            if current and is_ref:
                names.append(current)
            current, is_ref = None, False
        elif depth == 1 and t.kind == "IDENT" and current is None:
            current = t.value
        elif t.kind == "IDENT" and t.value in _REFERENCE and toks[k - 1].value == ".":
            is_ref = True
        k += 1
    if current and is_ref:
        names.append(current)
    return names


@rule("ПР-01", "Объект по ссылке с клиента под повышенными правами", "S",
      severity=Severity.WARNING)
def reference_from_client(source: SourceFile) -> Iterable[Diagnostic]:
    if source.kind != "xbsl":
        return []
    identity = set(filter(None, os.environ.get(IDENTITY_ENV, "").split(",")))
    own = source.path.name.split(".")[0]
    toks = code_tokens(source)
    out: list[Diagnostic] = []
    frames: list[str] = []
    method = None  # (имя, строка, параметры-ссылки, глубина, привилегии, сверка)
    condition = -1  # строка последнего `если`: сверка — обращение к пользователю в условии
    prev = None
    for i, t in enumerate(toks):
        if t.kind == "KEYWORD" and t.canonical in _OPENERS and t.value[:1].islower():
            is_else_if = (t.canonical == "IF" and prev is not None and prev.kind == "KEYWORD"
                          and prev.canonical == "ELSE" and prev.line == t.line)
            is_abstract = (t.canonical == "METHOD" and prev is not None and prev.kind == "KEYWORD"
                           and prev.canonical == "ABSTRACT")
            if t.canonical == "IF":
                condition = t.line
            if not is_else_if and not is_abstract:
                frames.append(t.canonical)
                if t.canonical == "METHOD":
                    static = prev is not None and prev.value in ("статический", "static")
                    ann = _annotations(toks, i - 1 if static else i)
                    params = _reference_params(toks, i)
                    if ann & _SERVER and ann & _FROM_CLIENT and params:
                        method = [_method_name(toks, i), t.line, params, len(frames), False, False]
                    else:
                        method = None
        elif t.kind == "OP" and t.value == ";":
            if frames:
                if method is not None and len(frames) == method[3]:
                    name, line, params, _, privileged, checked = method
                    if privileged and not checked:
                        out.append(Diagnostic(
                            source.rel, line, 1, "ПР-01", Severity.WARNING,
                            f"Метод '{name}' доступен с клиента, принимает ссылку "
                            f"({', '.join(params)}) и открывает привилегированный контекст "
                            f"без сверки с текущим пользователем: подставленная с клиента "
                            f"ссылка даст доступ к чужому объекту. Брать пользователя "
                            f"на сервере или сверить ссылку до повышения прав.",
                        ))
                    method = None
                frames.pop()
        elif method is not None and t.kind == "IDENT":
            if t.value in _PRIVILEGED:
                method[4] = True
            elif t.value in _RIGHT_CHECK and not method[4]:
                method[5] = True
            elif t.value in _CURRENT_USER and t.line == condition:
                method[5] = True
            elif i + 1 < len(toks) and toks[i + 1].value == "(" and not (
                    prev is not None and prev.kind == "KEYWORD" and prev.canonical == "METHOD"):
                qualified = (prev is not None and prev.value == "." and i >= 2
                             and toks[i - 2].kind == "IDENT")
                module = toks[i - 2].value if qualified else own
                if f"{module}.{t.value}" in identity:
                    method[5] = True
        prev = t
    return out


# ПР-03: точки периметра. Ключ находки — первое слово сообщения до двоеточия: по нему
# `check` сверяет находку с перечнем периметра (`путь: Ключ`).
_YAML_UNAUTH = re.compile(r"^\s*(РежимАутентификации|AuthenticationMode):\s*"
                          r"(НеАутентифицированный|NotAuthenticated)\s*$")
_YAML_ALL = re.compile(r"^\s*([^\s:#][^:#]*?):\s*(РазрешеноВсем|AllowedForAll)\s*$")
_YAML_HTTP = re.compile(r"^(ВидЭлемента|ElementKind):\s*(HttpСервис|HttpService)\s*$")


def _pair_unauthenticated(source: SourceFile) -> bool:
    pair = source.path.with_name(source.path.name.split(".")[0] + ".yaml")
    try:
        text = pair.read_text(encoding="utf-8-sig")
    except OSError:
        return False
    return any(_YAML_UNAUTH.match(line) for line in text.splitlines())


@rule("ПР-03", "Точка без аутентификации вне согласованного перечня", "S",
      severity=Severity.WARNING)
def perimeter(source: SourceFile) -> Iterable[Diagnostic]:
    out: list[Diagnostic] = []
    if source.kind == "yaml":
        for n, line in enumerate(source.text.splitlines(), 1):
            m = _YAML_UNAUTH.match(line) or _YAML_HTTP.match(line) or _YAML_ALL.match(line)
            if m:
                key = m.group(1).strip()
                out.append(Diagnostic(
                    source.rel, n, line.find(key) + 1, "ПР-03", Severity.WARNING,
                    f"{key}: {m.group(2)} — точка без аутентификации. Открыта намеренно — "
                    f"внести в перечень периметра; нет — закрыть.",
                ))
    elif source.kind == "xbsl" and _pair_unauthenticated(source):
        for t in code_tokens(source):
            if t.kind == "IDENT" and t.value in _PRIVILEGED:
                out.append(Diagnostic(
                    source.rel, t.line, t.col, "ПР-03", Severity.WARNING,
                    f"{t.value}: повышение прав в модуле элемента для неаутентифицированных — "
                    f"гость получает данные в обход прав. Пометить «анализ:периметр — причина», "
                    f"если отдаётся ровно то, что решено показать гостю.",
                ))
    return out


# ПР-04: разметка из данных без очистки. Контейнер ищется в YAML по строке `Тип: КонтейнерHtml`,
# его свойства — строки с тем же отступом до конца компонента.
_YAML_CONTAINER = re.compile(r"^(\s*)(-\s+)?Тип:\s*КонтейнерHtml\s*$")
_YAML_KEY = re.compile(r"^(\s*)(?:-\s+)?([^\s:#][^:#]*?):\s*(.*?)\s*$")
_INNER_HTML = re.compile(r"\.innerHTML\s*=(?!=)\s*(.)")
_FUNCTION = re.compile(r"function\s+([^\s(]+)\s*\(")
_CALL = re.compile(r"^=\s*(\w+)\(\)$")
# Подстановка в ресурс безопасна, если в подставляемом экранирован `<`: тогда ни тег,
# ни `</script>` из данных не закроют скрипт и не откроют свой
_ESCAPED_LT = re.compile(r"\.Заменить\(\s*\"<\"\s*,\s*\"\\\\u003c\"\s*\)")
_CONSTANT_RHS = re.compile(r"^(?:\s|\(|\)|\|\||\+|'[^']*'|\"[^\"]*\"|[A-ZА-ЯЁ_][A-ZА-ЯЁ0-9_]*(?:\[[^\]]*\])?)*$")


def _method_body(text: str, name: str) -> str | None:
    m = re.search(rf"метод\s+{re.escape(name)}\s*\(", text)
    if not m:
        return None
    end = text.find("\n;", m.end())
    return text[m.end():end if end >= 0 else len(text)]


def _returns_resource(text: str, name: str, depth: int = 3) -> bool:
    """Метод модуля возвращает текст ресурса — сам или через метод того же модуля."""
    body = _method_body(text, name)
    if body is None or depth == 0:
        return False
    if "Ресурс{" in body:
        substituted = "Заменить(" in body
        return not substituted or bool(_ESCAPED_LT.search(body))
    call = re.search(r"возврат\s+(\w+)\(", body)
    return bool(call) and _returns_resource(text, call.group(1), depth - 1)



def _unsafe_containers(text: str) -> list[tuple[str, int, str]]:
    """Контейнеры с выключенным безопасным режимом: (имя, строка Содержимое, значение)."""
    lines = text.splitlines()
    found: list[tuple[str, int, str]] = []
    for n, line in enumerate(lines):
        m = _YAML_CONTAINER.match(line)
        if not m:
            continue
        indent = len(m.group(1)) + len(m.group(2) or "")
        props: dict[str, tuple[int, str]] = {}
        for k in range(n + 1, len(lines)):
            row = lines[k]
            if not row.strip():
                continue
            own = len(row) - len(row.lstrip())
            if own < indent or (own == indent - 2 and row.lstrip().startswith("-")):
                break
            km = _YAML_KEY.match(row)
            if km and len(km.group(1)) == indent:
                props[km.group(2).strip()] = (k + 1, km.group(3).strip("'\""))
        if props.get("БезопасныйРежим", (0, ""))[1] in ("Ложь", "False"):
            name = props.get("Имя", (0, ""))[1]
            line_no, value = props.get("Содержимое", (n + 1, ""))
            found.append((name, line_no, value))
    return found


def _sanitizers() -> set[str]:
    names = set(filter(None, os.environ.get(SANITIZERS_ENV, "").split(",")))
    return names or set(DEFAULT_SANITIZERS)


def _function_ranges(text: str) -> list[tuple[str, int, int]]:
    """Тела функций скрипта: (имя, начало, конец) по фигурным скобкам."""
    ranges = []
    for m in _FUNCTION.finditer(text):
        start = text.find("{", m.end())
        if start < 0:
            continue
        depth, k = 0, start
        while k < len(text):
            if text[k] == "{":
                depth += 1
            elif text[k] == "}":
                depth -= 1
                if depth == 0:
                    break
            k += 1
        ranges.append((m.group(1), start, k))
    return ranges


@rule("ПР-04", "Разметка из данных выполняется в браузере без очистки", "S",
      severity=Severity.WARNING)
def unsanitized_html(source: SourceFile) -> Iterable[Diagnostic]:
    out: list[Diagnostic] = []
    if source.kind == "yaml":
        for name, line, value in _unsafe_containers(source.text):
            if value.startswith("=") and not value[1:].lstrip().startswith("Ресурс{") \
                    and not _resource_function(source, value):
                out.append(Diagnostic(
                    source.rel, line, 1, "ПР-04", Severity.WARNING,
                    f"КонтейнерHtml '{name}': безопасный режим выключен, а содержимое считается "
                    f"выражением ({value[:60]}) — разметка из данных выполнит свои скрипты. "
                    f"Оставить безопасный режим или давать контейнеру ресурс.",
                ))
    elif source.kind == "xbsl":
        pair = source.path.with_name(source.path.name.split(".")[0] + ".yaml")
        try:
            names = {n for n, _, _ in _unsafe_containers(pair.read_text(encoding="utf-8-sig")) if n}
        except OSError:
            names = set()
        if names:
            toks = code_tokens(source)
            for i, t in enumerate(toks):
                if (t.kind == "IDENT" and t.value == "Содержимое" and i >= 2
                        and toks[i - 1].value == "." and toks[i - 2].value in names
                        and i + 2 < len(toks) and toks[i + 1].value == "="
                        and toks[i + 2].value not in ("Ресурс", "Resource")):
                    out.append(Diagnostic(
                        source.rel, t.line, t.col, "ПР-04", Severity.WARNING,
                        f"Содержимое контейнера '{toks[i - 2].value}' с выключенным безопасным "
                        f"режимом задаётся не ресурсом — разметка из данных выполнит свои скрипты.",
                    ))
    elif source.kind in ("html", "js"):
        text = source.text
        clean = _sanitizers()
        functions = _function_ranges(text)
        for m in _INNER_HTML.finditer(text):
            end = text.find(";", m.end(1) - 1)
            rhs = text[m.end(1) - 1:end if end >= 0 else len(text)]
            if m.group(1) in ("'", '"', "`") or _CONSTANT_RHS.match(rhs):
                continue
            pos = m.start()
            inner = [f for f in functions if f[1] <= pos <= f[2]]
            if inner and min(inner, key=lambda f: f[2] - f[1])[0] in clean:
                continue
            line = text.count("\n", 0, pos) + 1
            col = pos - (text.rfind("\n", 0, pos) + 1) + 1
            out.append(Diagnostic(
                source.rel, line, col, "ПР-04", Severity.WARNING,
                f"innerHTML получает значение не литералом и вне функции очистки "
                f"({', '.join(sorted(clean))}) — разметка из данных выполнит свои скрипты. "
                f"Пропустить через очистку или писать textContent.",
            ))
    return out


def _resource_function(source: SourceFile, value: str) -> bool:
    """`Содержимое: =Метод()`, где метод пары `.xbsl` отдаёт ресурс — без подстановок
    или с подстановкой, в которой экранирован `<`."""
    m = _CALL.match(value)
    if not m:
        return False
    pair = source.path.with_name(source.path.name.split(".")[0] + ".xbsl")
    try:
        text = pair.read_text(encoding="utf-8-sig")
    except OSError:
        return False
    return _returns_resource(text, m.group(1))
