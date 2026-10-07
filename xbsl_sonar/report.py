"""Находки: пометки исключения и отчёт для плагина 1С к SonarQube."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from xbsl_sonar.rules import RULES

# `// анализ:исключение ПР-15 ТД-12 — причина` — в строке находки или строкой выше.
# Пункт долга обязателен: исключение без него не действует.
MARK = re.compile(r"//\s*анализ:исключение\s+(ПР-\d+)\s+(\S+)(?:\s+[—–-]\s*(.*))?")


@dataclass
class Finding:
    path: str
    line: int
    col: int
    rule: str
    message: str
    debt: str | None = None  # пункт долга из пометки исключения
    reason: str | None = None


def sonar_key(rule: str) -> str:
    """Ключ правила в SonarQube: латиницей, чтобы не зависеть от разбора ключей сервером."""
    return rule.replace("ПР-", "PR-")


def apply_exceptions(findings: list[Finding], root: Path) -> None:
    lines_cache: dict[str, list[str]] = {}
    for f in findings:
        lines = lines_cache.get(f.path)
        if lines is None:
            lines = (root / f.path).read_text(encoding="utf-8-sig").splitlines()
            lines_cache[f.path] = lines
        for n in (f.line, f.line - 1):
            if 1 <= n <= len(lines):
                m = MARK.search(lines[n - 1])
                if m and m.group(1) == f.rule:
                    f.debt = m.group(2)
                    f.reason = (m.group(3) or "").strip() or None
                    break


def marks(paths: list[Path]) -> list[tuple[Path, int, str, str]]:
    """Все пометки исключения в файлах: (файл, строка, правило, пункт долга)."""
    out = []
    for p in paths:
        for n, line in enumerate(p.read_text(encoding="utf-8-sig").splitlines(), 1):
            m = MARK.search(line)
            if m:
                out.append((p, n, m.group(1), m.group(2)))
    return out


def bsl_report(findings: list[Finding], root: Path) -> dict:
    """Отчёт в формате BSL Language Server: его принимает `sonar.bsl.languageserver.reportPaths`.

    Строки и позиции — с нуля, как в LSP. Путь — абсолютный: плагин ищет файл анализа
    по абсолютному пути. Находка под пометкой исключения уходит с понижением до подсказки
    и с номером долга в тексте — в SonarQube она видна, но не за ней следят.
    """
    by_file: dict[str, list[dict]] = {}
    for f in findings:
        path = (root / f.path).resolve()
        text = path.read_text(encoding="utf-8-sig").splitlines()
        line_text = text[f.line - 1] if 0 < f.line <= len(text) else ""
        start = max(f.col - 1, 0)
        end = max(len(line_text), start + 1)
        message = f.message if f.debt is None else f"Исключение по {f.debt}: {f.message}"
        by_file.setdefault(str(path), []).append({
            "range": {"start": {"line": f.line - 1, "character": start},
                      "end": {"line": f.line - 1, "character": end}},
            "severity": "Warning" if f.debt is None else "Hint",
            "code": sonar_key(f.rule),
            "source": "universal",
            "message": message,
        })
    return {
        "date": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "fileinfos": [{"path": p, "diagnostics": d} for p, d in sorted(by_file.items())],
    }


def rules_file() -> dict:
    """Описания правил для `sonar.bsl.universal.rulesPaths` (формат RulesFile плагина 1С)."""
    return {"rules": [
        {
            "code": sonar_key(r.code),
            "name": f"{r.code}. {r.name}",
            "description": r.description,
            "type": r.type,
            "severity": r.severity,
            "active": True,
            "needForCertificate": False,
            "effortMinutes": r.effort_minutes,
            "internalCode": r.code,
        }
        for r in RULES.values()
    ]}


def write_json(data: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
