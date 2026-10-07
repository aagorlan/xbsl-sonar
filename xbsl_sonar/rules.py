"""Правила xbsl-sonar для движка keyfire/xbsl.

Модуль подключается точкой расширения `xbsl.rules`: импорт регистрирует правила декоратором
`@rule`. Встроенные правила движка в анализе не участвуют — запуск идёт с `--select` только
по правилам отсюда (`RULE_IDS`).

Одна проверка — одно правило; код правила — `ПР-NN`, как в своде проверок. Описание
для SonarQube — в `RULES`: из него собирается файл описаний (`xbsl-sonar rules-file`).
"""

from __future__ import annotations

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
}

RULE_IDS = tuple(RULES)

# `конструктор` не открывает блок (у маркера в структуре нет `;`), как и в движке.
_OPENERS = {
    "METHOD", "STRUCTURE", "ENUMERATION", "EXCEPTION",
    "IF", "FOR", "WHILE", "TRY", "CASE", "SCOPE",
}
_CLIENT = {"НаКлиенте", "OnClient"}
_SERVER = {"НаСервере", "OnServer"}


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
