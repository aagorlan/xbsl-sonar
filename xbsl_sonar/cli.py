"""Командная строка xbsl-sonar.

    xbsl-sonar check IT --help-dir docs/vendor [--perimeter периметр.txt] [--sanitizers очистить]
                    [--agreed согласовано.txt] [--min-period 60] [--max-accesses 3]
                    [--pd-entities Сущность,…] [--pd-journal Модуль.Метод,…]
                    [--incident-sinks Модуль.Метод,…]
                    [--bsl-report отчёт.json]
                    [--json находки.json]
    xbsl-sonar data --help-dir docs/vendor --out каталог
    xbsl-sonar rules-file --out universal.json

`check` возвращает 1, если есть находка без пометки исключения, 2 — при ошибке запуска.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from xbsl_sonar import __version__, data, report
from xbsl_sonar.rules import (DATA_ENV, IDENTITY_ENV, INCIDENT_SINKS_ENV, MAX_ACCESSES_ENV,
                               MIN_PERIOD_ENV, PD_ENTITIES_ENV, PD_JOURNAL_ENV, PD_JOURNALED_ENV,
                               RULE_IDS, SANITIZERS_ENV, SERVER_ENV, UNGUARDED_ENV)

_METHOD = re.compile(r"^\s*(?:статический\s+|static\s+)?(?:метод|method)\s+(\w+)", re.IGNORECASE)
_CURRENT_USER = re.compile(r"\b(?:ТекущийПользователь|CurrentUser)\b")
_QUERY = re.compile(r"(?<![\w.])(?:Запрос|Query)\s*\{")


_CALL = re.compile(r"(?<![\w.])(?:(\w+)\s*\.\s*)?(\w+)\s*\(")
_ANNOTATION = re.compile(r"@(\w+)")
_ON_SERVER = {"НаСервере", "OnServer"}
_ON_CLIENT = {"НаКлиенте", "OnClient"}
_FROM_CLIENT = {"ДоступноСКлиента", "AvailableFromClient"}
_PRIVILEGED = re.compile(r"(?<![\w])(?:Привилегированный|Privileged)\s*\(")
_WRITE = re.compile(r"\.(?:Записать|Удалить|УстановитьПометкуУдаления|Write|Delete|SetDeletionMark)\s*\(")
_RIGHT_CHECK = re.compile(r"(?<![\w])(?:ПроверитьПраво|ЕстьПраво|CheckRight|HasRight)\s*\(")


def identity_methods(paths: list[str]) -> set[str]:
    """Методы, которые сверяют с текущим пользователем (для ПР-01), — `Модуль.Метод`.

    Такой метод читает `ТекущийПользователь` или вызывает другой такой метод — набор
    замыкается по вызовам: `ПроверитьПрава()`, зовущий `ЭтоАдминистратор()`, тоже сверка.
    Модуль — имя элемента (файл `Модуль.xbsl`, `Модуль.Объект.xbsl`); вызов без модуля
    относится к своему. Разбор по строкам: тело метода — от заголовка до следующего.
    """
    bodies, _ = _bodies(paths)
    found = {key for key, lines in bodies.items() if _CURRENT_USER.search("\n".join(lines))}
    return _closure(found, bodies)


def _bodies(paths: list[str]) -> tuple[dict[str, list[str]], dict[str, set[str]]]:
    """Тела методов по строкам и их аннотации: `Модуль.Метод` → строки тела, аннотации.

    Модуль — имя элемента (файл `Модуль.xbsl`, `Модуль.Объект.xbsl`); аннотации — строки
    `@…` перед заголовком. Тело — от заголовка до следующего.
    """
    bodies: dict[str, list[str]] = {}
    annotations: dict[str, set[str]] = {}
    files: list[Path] = []
    for p in map(Path, paths):
        files.extend(sorted(p.rglob("*.xbsl")) if p.is_dir() else [p])
    for file in files:
        module = file.name.split(".")[0]
        current = None
        pending: set[str] = set()
        for line in file.read_text(encoding="utf-8", errors="replace").splitlines():
            m = _METHOD.match(line)
            if m:
                current = f"{module}.{m.group(1)}"
                bodies.setdefault(current, [])
                annotations[current] = pending
                pending = set()
            elif line.lstrip().startswith("@"):
                pending |= set(_ANNOTATION.findall(line))
            elif current:
                bodies[current].append(line)
    return bodies, annotations


def _closure(found: set[str], bodies: dict[str, list[str]]) -> set[str]:
    """Добавить к набору методы, которые вызывают метод из набора, — пока набор растёт.
    Вызов без модуля относится к своему."""
    calls: dict[str, set[str]] = {}
    for key, lines in bodies.items():
        own = key.split(".")[0]
        calls[key] = {f"{q or own}.{name}" for q, name in _CALL.findall("\n".join(lines))}
    while True:
        more = {key for key, called in calls.items() if key not in found and called & found}
        if not more:
            return found
        found |= more


def server_methods(paths: list[str]) -> set[str]:
    """Методы, вызов которых доходит до сервера (для ПР-16), — `Модуль.Метод`.

    Серверный — с `@НаСервере` и без `@НаКлиенте`; набор замыкается по вызовам: клиентский
    метод, зовущий серверный, тоже ходит на сервер.
    """
    bodies, annotations = _bodies(paths)
    found = {key for key, ann in annotations.items() if ann & _ON_SERVER and not ann & _ON_CLIENT}
    return _closure(found, bodies)


def data_methods(paths: list[str]) -> set[str]:
    """Методы, вызов которых доходит до сервера или базы (для ПР-17), — `Модуль.Метод`.

    Серверные (как для ПР-16) и методы с литералом `Запрос{…}`; набор замыкается по вызовам.
    """
    bodies, annotations = _bodies(paths)
    found = {key for key, ann in annotations.items() if ann & _ON_SERVER and not ann & _ON_CLIENT}
    found |= {key for key, lines in bodies.items() if _QUERY.search("\n".join(lines))}
    return _closure(found, bodies)


def unguarded_methods(paths: list[str]) -> set[str]:
    """Методы с доступом с клиента, которые работают в повышенных правах без сверки (для ПР-02),
    — `Модуль.Метод`.

    Запись в повышенных правах — метод, где есть и привилегированный контекст, и `Записать(`/
    `Удалить(`; набор замыкается по вызовам. Без повышения прав действуют права объекта, и их
    проверяет платформа; повышение без записи (пересчёт ключей, чтение) тоже не находка. Сверка — как
    в ПР-01: метод из набора `identity_methods` или проверка права (`ПроверитьПраво`/`ЕстьПраво`),
    сама или в вызываемых.
    """
    bodies, annotations = _bodies(paths)
    writers = _closure({k for k, lines in bodies.items()
                        if _PRIVILEGED.search(text := "\n".join(lines)) and _WRITE.search(text)}, bodies)
    checked = identity_methods(paths)
    checked |= {k for k, lines in bodies.items() if _RIGHT_CHECK.search("\n".join(lines))}
    checked = _closure(checked, bodies)
    return {k for k in writers - checked
            if annotations.get(k, set()) & _ON_SERVER and annotations[k] & _FROM_CLIENT}


def journaled_methods(paths: list[str], journal: list[str]) -> set[str]:
    """Методы, которые пишут журнал доступа ПДн (для ПР-07): сами зовут метод журнала
    или зовут такой метод — набор замыкается по вызовам, как у `identity_methods`."""
    bodies, _ = _bodies(paths)
    keys = set(journal)
    found = {key for key, lines in bodies.items()
             if {f"{q or key.split('.')[0]}.{n}" for q, n in _CALL.findall("\n".join(lines))} & keys}
    return _closure(found | keys, bodies)


_YAML_NAME = re.compile(r"^(?:Имя|Name):\s*(\w+)\s*$", re.MULTILINE)
_YAML_DIMENSIONS = re.compile(r"^(?:Измерения|Dimensions):\s*$", re.MULTILINE)


def pd_entities(paths: list[str], names: list[str]) -> str:
    """Сущности ПДн с измерениями для ПР-07: `Сущность:Изм1|Изм2,…`. Измерения — ключ записи,
    сами по себе не ПДн; их берёт из YAML элемента (`Измерения:` → `Имя:` каждого)."""
    dims: dict[str, list[str]] = {n: [] for n in names}
    files: list[Path] = []
    for p in map(Path, paths):
        files.extend(sorted(p.rglob("*.yaml")) if p.is_dir() else [])
    for file in files:
        if file.stem not in dims:
            continue
        text = file.read_text(encoding="utf-8-sig", errors="replace")
        name = _YAML_NAME.search(text)
        block = _YAML_DIMENSIONS.search(text)
        if not name or name.group(1) != file.stem or not block:
            continue
        for line in text[block.end():].splitlines():
            if line and not line[0].isspace():
                break
            m = re.match(r"^\s+(?:-\s+)?(?:Имя|Name):\s*(\w+)", line)
            if m:
                dims[file.stem].append(m.group(1))
    return ",".join(f"{n}:{'|'.join(d)}" for n, d in dims.items())


def _run_engine(paths: list[str], data_dir: Path, rules: list[str],
                sanitizers: str = "", min_period: str = "",
                server_file: Path | None = None, data_file: Path | None = None,
                max_accesses: str = "", unguarded_file: Path | None = None,
                pd: dict[str, str] | None = None) -> list[report.Finding]:
    cmd = [sys.executable, "-m", "xbsl", "--data-dir", str(data_dir), "--lang", "ru",
           "--select", ",".join(rules), "--format", "json", *paths]
    env = dict(os.environ, **{IDENTITY_ENV: ",".join(sorted(identity_methods(paths))),
                              SANITIZERS_ENV: sanitizers,
                              SERVER_ENV: str(server_file or ""),
                              DATA_ENV: str(data_file or ""),
                              UNGUARDED_ENV: str(unguarded_file or ""),
                              MIN_PERIOD_ENV: min_period,
                              MAX_ACCESSES_ENV: max_accesses, **(pd or {})})
    done = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", env=env)
    try:
        result = json.loads(done.stdout)
    except json.JSONDecodeError:
        sys.stderr.write(done.stderr or done.stdout)
        raise SystemExit(2)
    return [
        report.Finding(d["path"], d["line"], d["col"], d["rule"], d["message"])
        for d in result["diagnostics"]
        if d["rule"] in rules
    ]


def _check(args) -> int:
    root = Path.cwd()
    rules = args.rules.split(",") if args.rules else list(RULE_IDS)
    unknown = [r for r in rules if r not in RULE_IDS]
    if unknown:
        print(f"Неизвестные правила: {', '.join(unknown)}; есть: {', '.join(RULE_IDS)}",
              file=sys.stderr)
        return 2
    with tempfile.TemporaryDirectory() as tmp:
        data_dir = Path(args.data_dir) if args.data_dir else data.build(Path(args.help_dir), Path(tmp))
        server_file = Path(tmp) / "server.txt"
        server_file.write_text("\n".join(sorted(server_methods(args.paths))), encoding="utf-8")
        data_file = Path(tmp) / "data.txt"
        data_file.write_text("\n".join(sorted(data_methods(args.paths))), encoding="utf-8")
        unguarded_file = Path(tmp) / "unguarded.txt"
        unguarded_file.write_text("\n".join(sorted(unguarded_methods(args.paths))), encoding="utf-8")
        pd_names = list(filter(None, (args.pd_entities or "").split(",")))
        journal = list(filter(None, (args.pd_journal or "").split(",")))
        journaled_file = Path(tmp) / "journaled.txt"
        journaled_file.write_text("\n".join(sorted(journaled_methods(args.paths, journal))),
                                  encoding="utf-8")
        pd = {PD_ENTITIES_ENV: pd_entities(args.paths, pd_names) if pd_names else "",
              PD_JOURNAL_ENV: ",".join(journal), PD_JOURNALED_ENV: str(journaled_file),
              INCIDENT_SINKS_ENV: args.incident_sinks or ""}
        findings = _run_engine(args.paths, data_dir, rules, args.sanitizers or "",
                               args.min_period or "", server_file, data_file,
                               args.max_accesses or "", unguarded_file, pd)
    report.apply_exceptions(findings, root)
    if args.perimeter:
        report.apply_perimeter(findings, report.read_perimeter(Path(args.perimeter)))
    if args.agreed:
        report.apply_agreed(findings, report.read_agreed(Path(args.agreed)))
    open_ = [f for f in findings if f.debt is None]
    for f in findings:
        mark = "" if f.debt is None else f" (исключение по {f.debt})"
        print(f"{f.path}:{f.line}:{f.col}: [{f.rule}]{mark} {f.message}")
    if "ПР-07" in rules and not args.pd_entities:
        print("ПР-07: сущности ПДн не заданы (--pd-entities) — чтение ПДн мимо журнала "
              "не проверялось, проверены только журнал событий и обращения")
    print(f"\nПравил: {len(rules)} ({', '.join(rules)}); находок: {len(findings)}, "
          f"из них под исключением: {len(findings) - len(open_)}")
    if args.json:
        report.write_json({"version": __version__, "rules": rules,
                           "findings": [f.__dict__ for f in findings]}, Path(args.json))
    if args.bsl_report:
        report.write_json(report.bsl_report(findings, root), Path(args.bsl_report))
    return 1 if open_ else 0


def _data(args) -> int:
    out = data.build(Path(args.help_dir), Path(args.out))
    print(f"Данные о языке: {out}")
    return 0


def _rules_file(args) -> int:
    report.write_json(report.rules_file(), Path(args.out))
    print(f"Описания правил: {args.out}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="xbsl-sonar", description=__doc__.splitlines()[0])
    ap.add_argument("--version", action="version", version=f"xbsl-sonar {__version__}")
    sub = ap.add_subparsers(dest="command", required=True)

    c = sub.add_parser("check", help="проверить код")
    c.add_argument("paths", nargs="+", help="каталоги или файлы проекта")
    src = c.add_mutually_exclusive_group(required=True)
    src.add_argument("--help-dir", help="выгрузка справки 1С:Элемент (каталог с topics/)")
    src.add_argument("--data-dir", help="готовые данные о языке (xbsl-sonar data)")
    c.add_argument("--rules", help="правила через запятую; по умолчанию все")
    c.add_argument("--perimeter", help="перечень периметра для ПР-03: строки «путь: Ключ — причина»")
    c.add_argument("--agreed", help="согласованные находки ПР-02, ПР-04, ПР-05, ПР-07, ПР-16 и ПР-17: "
                                    "строки «путь: ПР-NN Ключ — причина»")
    c.add_argument("--sanitizers", help="функции очистки разметки для ПР-04 через запятую; "
                                        "по умолчанию «очистить»")
    c.add_argument("--min-period", help="порог интервала таймера для ПР-16, секунды; по умолчанию 60")
    c.add_argument("--max-accesses", help="порог обращений к серверу и базе в обработчике формы "
                                          "для ПР-17; по умолчанию 3")
    c.add_argument("--pd-entities", help="сущности персональных данных для ПР-07 через запятую; "
                                         "без них чтение ПДн мимо журнала не проверяется")
    c.add_argument("--pd-journal", help="методы журнала доступа ПДн для ПР-07 (Модуль.Метод) "
                                        "через запятую")
    c.add_argument("--incident-sinks", help="методы, которые пишут обращения в поддержку, для ПР-07 "
                                            "(Модуль.Метод) через запятую")
    c.add_argument("--json", help="находки файлом JSON")
    c.add_argument("--bsl-report", help="отчёт для SonarQube (формат BSL Language Server)")
    c.set_defaults(func=_check)

    d = sub.add_parser("data", help="собрать данные о языке из выгрузки справки")
    d.add_argument("--help-dir", required=True)
    d.add_argument("--out", required=True)
    d.set_defaults(func=_data)

    r = sub.add_parser("rules-file", help="описания правил для SonarQube")
    r.add_argument("--out", default="universal.json")
    r.set_defaults(func=_rules_file)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
