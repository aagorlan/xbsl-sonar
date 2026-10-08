"""Командная строка xbsl-sonar.

    xbsl-sonar check IT --help-dir docs/vendor [--bsl-report отчёт.json] [--json находки.json]
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
from xbsl_sonar.rules import IDENTITY_ENV, RULE_IDS

_METHOD = re.compile(r"^\s*(?:статический\s+|static\s+)?(?:метод|method)\s+(\w+)", re.IGNORECASE)
_CURRENT_USER = re.compile(r"\b(?:ТекущийПользователь|CurrentUser)\b")


_CALL = re.compile(r"(?<![\w.])(?:(\w+)\s*\.\s*)?(\w+)\s*\(")


def identity_methods(paths: list[str]) -> set[str]:
    """Методы, которые сверяют с текущим пользователем (для ПР-01), — `Модуль.Метод`.

    Такой метод читает `ТекущийПользователь` или вызывает другой такой метод — набор
    замыкается по вызовам: `ПроверитьПрава()`, зовущий `ЭтоАдминистратор()`, тоже сверка.
    Модуль — имя элемента (файл `Модуль.xbsl`, `Модуль.Объект.xbsl`); вызов без модуля
    относится к своему. Разбор по строкам: тело метода — от заголовка до следующего.
    """
    bodies: dict[str, list[str]] = {}
    files: list[Path] = []
    for p in map(Path, paths):
        files.extend(sorted(p.rglob("*.xbsl")) if p.is_dir() else [p])
    for file in files:
        module = file.name.split(".")[0]
        current = None
        for line in file.read_text(encoding="utf-8", errors="replace").splitlines():
            m = _METHOD.match(line)
            if m:
                current = f"{module}.{m.group(1)}"
                bodies.setdefault(current, [])
            elif current:
                bodies[current].append(line)
    calls: dict[str, set[str]] = {}
    found: set[str] = set()
    for key, lines in bodies.items():
        text = "\n".join(lines)
        own = key.split(".")[0]
        calls[key] = {f"{q or own}.{name}" for q, name in _CALL.findall(text)}
        if _CURRENT_USER.search(text):
            found.add(key)
    while True:
        more = {key for key, called in calls.items() if key not in found and called & found}
        if not more:
            return found
        found |= more


def _run_engine(paths: list[str], data_dir: Path, rules: list[str]) -> list[report.Finding]:
    cmd = [sys.executable, "-m", "xbsl", "--data-dir", str(data_dir), "--lang", "ru",
           "--select", ",".join(rules), "--format", "json", *paths]
    env = dict(os.environ, **{IDENTITY_ENV: ",".join(sorted(identity_methods(paths)))})
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
        findings = _run_engine(args.paths, data_dir, rules)
    report.apply_exceptions(findings, root)
    open_ = [f for f in findings if f.debt is None]
    for f in findings:
        mark = "" if f.debt is None else f" (исключение по {f.debt})"
        print(f"{f.path}:{f.line}:{f.col}: [{f.rule}]{mark} {f.message}")
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
