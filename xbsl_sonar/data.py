"""Данные о языке XBSL для движка keyfire/xbsl — из выгрузки справки 1С:Элемент.

Движку нужен корень данных `<корень>/index.json` и `<корень>/<версия>/language.json`
(ключевые слова и операторы). Его автор извлекает их из дистрибутива; дистрибутива у нас нет,
а справка охраняется правом 1С, поэтому данные не хранятся в этом репозитории, а строятся
при запуске из выгрузки справки потребителя: таблица ключевых слов из
`topics/keywords/index.md` плюс слова, которых в таблице нет, но которые разбор требует.
Операторы — знаки языка, справка их таблицей не перечисляет.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

VERSION = "9.2"

# Английское слово таблицы → каноническое имя ключевого слова движка (правило грамматики
# без RULE_ и _KW). Совпадает с верхним регистром слова, кроме перечисленных здесь.
_CANONICAL = {"enum": "ENUMERATION"}

# Слов нет в таблице ключевых слов справки, а разбор без них ломается: литералы, тип
# и запрос, модификаторы. Найдены пробным разбором кода, собирающегося в среде разработки.
_EXTRA = {
    "TRUE": ["Истина", "True"],
    "FALSE": ["Ложь", "False"],
    "UNDEFINED": ["Неопределено", "Undefined"],
    "TYPE": ["Тип", "Type"],
    "QUERY": ["Запрос", "Query"],
    "ABSTRACT": ["абстрактный", "abstract"],
    "NEVER": ["никогда", "never"],
}

OPERATORS = [
    "...", "??=", "?.", "??", "::", "->", "=>", "==", "!=", "<>", "<=", ">=", "+=", "-=",
    "*=", "/=", "%=", "&&", "||", "++", "--",
    "+", "-", "*", "/", "%", "=", "<", ">", "!", "?", ":", ";", ",", ".", "@", "#", "&", "|",
    "(", ")", "[", "]", "{", "}",
]

_ROW = re.compile(r"^\|\s*`([^`]+)`\s*\|\s*`([^`]+)`\s*\|")


def keywords_from_help(index_md: Path) -> dict[str, dict]:
    keywords: dict[str, dict] = {}
    for line in index_md.read_text(encoding="utf-8").splitlines():
        m = _ROW.match(line.strip())
        if not m:
            continue
        ru, en = m.group(1), m.group(2)
        canon = _CANONICAL.get(en, en.upper())
        keywords[canon] = {"forms": [ru, en], "rules": [f"RULE_{canon}_KW"]}
    if not keywords:
        raise SystemExit(f"В {index_md} не найдена таблица ключевых слов")
    for canon, forms in _EXTRA.items():
        keywords.setdefault(canon, {"forms": [], "rules": [f"RULE_{canon}_KW"]})
        for f in forms:
            if f not in keywords[canon]["forms"]:
                keywords[canon]["forms"].append(f)
    return dict(sorted(keywords.items()))


def build(help_dir: Path, out: Path) -> Path:
    """Собрать корень данных `out` из выгрузки справки `help_dir` (каталог `docs/vendor`)."""
    index_md = help_dir / "topics" / "keywords" / "index.md"
    if not index_md.is_file():
        raise SystemExit(f"Нет таблицы ключевых слов справки: {index_md}")
    keywords = keywords_from_help(index_md)
    ops = sorted(set(OPERATORS), key=lambda s: (-len(s), s))
    language = {
        "meta": {
            "element_version": VERSION,
            "generated_from": "xbsl-sonar: справка topics/keywords",
            "keyword_groups": len(keywords),
            "keyword_forms": sum(len(v["forms"]) for v in keywords.values()),
            "operators": len(ops),
        },
        "keywords": keywords,
        "operators": ops,
        "token_ids": {},
    }
    (out / VERSION).mkdir(parents=True, exist_ok=True)
    (out / VERSION / "language.json").write_text(
        json.dumps(language, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (out / "index.json").write_text(
        json.dumps({"available": [VERSION], "default": VERSION}, ensure_ascii=False) + "\n",
        encoding="utf-8")
    return out
