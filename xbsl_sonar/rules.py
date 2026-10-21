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
    "ПР-02": RuleText(
        code="ПР-02",
        name="Действие администратора без проверки на сервере",
        description=(
            "<p>Элемент формы, который интерфейс показывает только администратору, — права "
            "проверены одной видимостью. Видимость решает клиент: данные формы и вызовы "
            "серверных методов собирает браузер, и пользователь без прав может их подставить. "
            "Если за таким элементом стоит запись данных без своей проверки на сервере, "
            "сделать её может любой вошедший.</p>"
            "<p><b>Находка:</b> в YAML компонента элемент с <code>Видимость</code> или "
            "<code>Доступность</code>, выражение которых говорит об администраторе "
            "(<code>=ДанныеПользователя.Администратор</code>, <code>=Администратор</code>, "
            "<code>ЭтоАдминистратор()</code>), и внутри него:</p><ul>"
            "<li>обработчик (<code>ПриНажатии</code>, <code>ПриИзменении</code>, "
            "<code>Обработчик</code>…), который сам или через методы модуля формы вызывает "
            "метод <code>@НаСервере @ДоступноСКлиента</code>, который пишет данные "
            "(<code>Записать</code>, <code>Удалить</code>) в привилегированном контексте — сам "
            "или через вызываемые — без сверки с текущим пользователем ни в нём, ни в вызываемых; "
            "без повышения прав действуют права объекта, их проверяет платформа;</li>"
            "<li>поле, привязанное к реквизиту объекта формы (<code>Значение: =Объект.Реквизит</code>), "
            "если менять объект вправе не только администратор (право <code>Изменение</code> "
            "или <code>ПоУмолчанию</code> указано и не <code>РазрешеноАдминистраторам</code>), "
            "а <code>ПередЗаписью</code> модуля объекта не сверяет этот реквизит "
            "с текущим пользователем: объект пишется стандартной командой формы, и значение "
            "приходит из данных формы.</li></ul>"
            "<p>Сверка — как в ПР-01: вызов метода, читающего текущего пользователя (набор "
            "собирается по проверяемому коду и замыкается по вызовам: <code>ЭтоАдминистратор()</code>, "
            "<code>ПроверитьПрава()</code>…), или <code>КонтрольДоступа.ПроверитьПраво</code>/"
            "<code>ЕстьПраво</code>.</p>"
            "<p><b>Не находка:</b> серверный метод, который сам или через вызываемые проверяет "
            "права; элемент, видимый не только администратору; поле, чей реквизит сверяется "
            "в <code>ПередЗаписью</code>; форма, открытая из такого элемента, — её методы "
            "проверяет ПР-01; находка из перечня согласованных (<code>--agreed</code>: строка "
            "<code>путь: ПР-02 Ключ — причина</code>).</p>"
            "<p><b>Как исправить:</b> проверить администратора в самом серверном методе "
            "(первой строкой, отказ исключением) или в <code>ПередЗаписью</code> объекта для "
            "реквизита, который ставит только администратор.</p>"
            "<p>CWE-285: Improper Authorization; CWE-424: Improper Protection of Alternate Path "
            "(OWASP A01:2021 Broken Access Control).</p>"
        ),
        type="VULNERABILITY",
        severity="CRITICAL",
        cwe="CWE-285",
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
            "внутри функции очистки или со строковым литералом; находка из перечня согласованных "
            "(параметр <code>--agreed</code>: строка <code>путь: ПР-04 Ключ — причина</code>, "
            "ключ — начало сообщения до двоеточия).</p>"
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
    "ПР-05": RuleText(
        code="ПР-05",
        name="Повышение прав с клиента без сверки",
        description=(
            "<p>Метод, доступный с клиента, открывает привилегированный контекст и ни разу "
            "не сверяется с тем, кто его вызвал. Вызвать такой метод может любой вошедший: "
            "вызовы серверных методов собирает браузер. В повышенных правах метод читает "
            "и пишет всё, что угодно, — права объектов отключены, а проверить, кому он это "
            "отдаёт, некому.</p>"
            "<p><b>Находка:</b></p><ul>"
            "<li>метод <code>@НаСервере @ДоступноСКлиента</code> без параметров-ссылок открывает "
            "<code>КонтекстДоступа.Привилегированный()</code> или "
            "<code>ГрупповаяОперация.Начать(…, ПривилегированныйРежим = Истина)</code>, "
            "а сверки с текущим пользователем нет. Сверка — как в ПР-01: вызов метода, "
            "читающего текущего пользователя (набор собирается по проверяемому коду "
            "и замыкается по вызовам: <code>ЭтоАдминистратор()</code>, "
            "<code>ПолучитьУчастника()</code>, <code>ПроверитьПрава()</code>…), "
            "<code>ТекущийПользователь</code> в условии <code>если</code> или "
            "<code>КонтрольДоступа.ПроверитьПраво</code>/<code>ЕстьПраво</code> до повышения прав;</li>"
            "<li>привилегированный контекст, который переживает строку открытия: "
            "<code>КонтекстДоступа.Привилегированный()</code> не в инструкции <code>исп</code> — "
            "присвоен, возвращён, передан аргументом — в любом методе.</li></ul>"
            "<p><b>Не находка:</b> метод с параметром-ссылкой — его проверяет ПР-01; серверный "
            "метод без доступа с клиента — его видимость задаёт вызывающий; "
            "<code>исп</code> с именем (<code>исп П = КонтекстДоступа.Привилегированный()</code>) — "
            "контекст закрывается вместе с блоком; находка из перечня согласованных "
            "(<code>--agreed</code>: строка <code>путь: ПР-05 Ключ — причина</code>).</p>"
            "<p><b>Как исправить:</b> проверить права вызывающего первой строкой метода "
            "(администратор — отказ исключением, участник — брать его на сервере); "
            "если повышение не нужно — убрать его; не отдавать на клиент того, что "
            "прочитано в повышенных правах, — секретов, чужих данных.</p>"
            "<p>CWE-269: Improper Privilege Management (OWASP A01:2021 Broken Access Control; "
            "A04:2021 Insecure Design).</p>"
        ),
        type="VULNERABILITY",
        severity="CRITICAL",
        cwe="CWE-269",
        effort_minutes=30,
    ),
    "ПР-16": RuleText(
        code="ПР-16",
        name="Таймер клиента регулярно вызывает сервер",
        description=(
            "<p>Повторяющийся таймер клиента ходит на сервер: каждая открытая форма "
            "у каждого пользователя шлёт вызов раз в несколько секунд, даже когда ничего "
            "не изменилось. Нагрузка растёт с числом открытых окон, а не с работой.</p>"
            "<p><b>Находка:</b> <code>ПодключитьОбработчикТаймера(обработчик, интервал)</code> "
            "без признака однократности (или с <code>Ложь</code>), интервал короче порога "
            "(параметр <code>--min-period</code>, по умолчанию 60 с), а обработчик — "
            "<code>&amp;Метод</code> или лямбда — вызывает серверный метод: сам или через "
            "методы проекта. Серверный — метод с окружением <code>@НаСервере</code> "
            "без <code>@НаКлиенте</code>; набор собирается по проверяемому коду и замыкается "
            "по вызовам.</p>"
            "<p><b>Не находка:</b> однократный таймер (<code>Истина</code> третьим параметром); "
            "интервал от порога и больше; интервал, который не литерал и не "
            "<code>Длительность.Из…(число)</code>, — его не посчитать; таймер, обработчик "
            "которого сервер не трогает; находка из перечня согласованных "
            "(<code>--agreed</code>: строка <code>путь: ПР-16 Ключ — причина</code>). "
            "Вызов сервера в цикле на клиенте — ПР-15.</p>"
            "<p><b>Как исправить:</b> проверять изменения на клиенте и идти на сервер только "
            "по ним; реже опрашивать; отдавать серверу одну дешёвую сверку версии, а данные — "
            "по её результату.</p>"
            "<p>CWE-1060: Excessive Number of Inefficient Server-Side Data Accesses "
            "(ISO/IEC 5055, производительность).</p>"
        ),
        type="CODE_SMELL",
        severity="MAJOR",
        cwe="CWE-1060",
        effort_minutes=60,
    ),
    "ПР-17": RuleText(
        code="ПР-17",
        name="Обращение к серверу при каждой перерисовке формы",
        description=(
            "<p>Форма сама решает, когда пересчитать выражения своих компонентов: при открытии, "
            "при изменении данных, на каждую строку списка. Если выражение зовёт метод, который "
            "идёт на сервер или в базу, каждая перерисовка — вызов сервера, а в строке списка — "
            "по вызову на каждую строку. Так же дорог обработчик формы, который на открытии "
            "ходит на сервер много раз подряд.</p>"
            "<p><b>Находка:</b></p><ul>"
            "<li>в YAML компонента — свойство-выражение (<code>Значение: =Метод()</code>, "
            "<code>Видимость: =…</code>, <code>ЦветФона: =…</code> и любое другое с <code>=</code>), "
            "которое вызывает метод, доходящий до сервера или базы: с окружением "
            "<code>@НаСервере</code> без <code>@НаКлиенте</code> или с литералом "
            "<code>Запрос{…}</code> — сам или через методы проекта (набор собирается "
            "по проверяемому коду и замыкается по вызовам); в строке списка "
            "(<code>ПроизвольнаяСтрокаСписка</code>) находка отмечается особо;</li>"
            "<li>в модуле компонента — обработчик (<code>@Обработчик</code>), в теле которого "
            "запросов и вызовов таких методов больше порога (параметр <code>--max-accesses</code>, "
            "по умолчанию 3).</li>"
            "</ul><p><b>Не находка:</b> выражение без вызова метода (<code>=ДанныеСтроки.Данные.Текст</code>); "
            "<code>ЗначениеПоУмолчанию</code> свойства компонента — оно считается один раз, при создании; "
            "метод, который считает на клиенте из уже полученных данных; обработчик с обращениями "
            "не больше порога; находка из перечня согласованных (<code>--agreed</code>: строка "
            "<code>путь: ПР-17 Ключ — причина</code>).</p>"
            "<p><b>Как исправить:</b> получить данные один раз — в обработчике открытия или полем "
            "запроса списка — и держать их в свойстве компонента; чистые вычисления (цвет "
            "по состоянию, подпись по числу) — без окружения <code>@НаСервере</code>; несколько "
            "вызовов обработчика — одним вызовом, отдающим структуру.</p>"
            "<p>CWE-1073: Non-SQL Invokable Control Element with Excessive Number of Data Resource "
            "Accesses (ISO/IEC 5055, производительность).</p>"
        ),
        type="CODE_SMELL",
        severity="MAJOR",
        cwe="CWE-1073",
        effort_minutes=30,
    ),
    "ПР-06": RuleText(
        code="ПР-06",
        name="Секрет строкой в коде",
        description=(
            "<p>Токен, пароль или ключ, записанный в коде строкой, уходит вместе с исходниками: "
            "в репозиторий, в его копии и историю, в выгрузку проекта. Сменить его можно только "
            "новой сборкой, а прочитать — любому, у кого есть код.</p>"
            "<p><b>Находка:</b></p><ul>"
            "<li>строковый литерал присваивается или передаётся именованным аргументом туда, "
            "чьё имя говорит о секрете: <code>Токен</code>, <code>Пароль</code>, "
            "<code>Секрет</code>, <code>КлючAPI</code>, <code>ПриватныйКлюч</code> и латиницей "
            "<code>token</code>, <code>password</code>, <code>secret</code>, <code>apikey</code> "
            "(в любом месте имени: <code>ТокенБота</code>, <code>ПарольОтправителя</code>), "
            "или кладётся в соответствие под таким ключом-строкой "
            "(<code>Вставить(\"password\", \"…\")</code>);</li>"
            "<li>литерал, похожий на секрет сам по себе, где бы он ни стоял: токен "
            "Telegram-бота (<code>цифры:35 знаков</code>), заголовок "
            "<code>Bearer …</code> или <code>Basic …</code> с длинным значением;</li>"
            "<li>в YAML — <code>ЗначениеПоУмолчанию</code> реквизита с таким именем "
            "или типа <code>СекретПриложения</code>.</li>"
            "</ul><p>Секретом считается значение не короче 8 знаков, без пробелов, кириллицы "
            "и подстановок <code>%</code>: подписи, сообщения и шаблоны адресов "
            "(<code>\"/bot%{Токен()}/…\"</code>) не находки.</p>"
            "<p><b>Не находка:</b> литерал там, где имя не про секрет "
            "(<code>Пользователь = \"AUTH_TOKEN\"</code>); имя поля протокола, а значение — "
            "переменная (<code>Вставить(\"secret_token\", Токен)</code>); пустая строка "
            "и короткие заглушки; значение из реквизита настроек или <code>СекретПриложения</code>.</p>"
            "<p><b>Как исправить:</b> хранить секрет в реквизите типа <code>СекретПриложения</code> "
            "или в настройках приложения и читать на сервере; секрет, уже попавший в репозиторий, "
            "считать раскрытым и сменить.</p>"
            "<p>CWE-798: Use of Hard-coded Credentials.</p>"
        ),
        type="VULNERABILITY",
        severity="CRITICAL",
        cwe="CWE-798",
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
# Методы, вызов которых с клиента доходит до сервера (для ПР-16), — `Модуль.Метод` по строке;
# набор собирает `check` до запуска движка (`server_methods`) и кладёт файлом: на большом
# проекте он не помещается в окружение. Здесь — путь к этому файлу.
SERVER_ENV = "XBSL_SONAR_SERVER"
# Порог интервала таймера для ПР-16, секунды — параметр `--min-period` команды `check`.
MIN_PERIOD_ENV = "XBSL_SONAR_MIN_PERIOD"
DEFAULT_MIN_PERIOD = 60
# Методы, вызов которых доходит до сервера или базы (для ПР-17): серверные и с литералом
# запроса, замкнутые по вызовам, — `Модуль.Метод` по строке; набор собирает `check`
# (`data_methods`) и кладёт файлом. Здесь — путь к этому файлу.
DATA_ENV = "XBSL_SONAR_DATA"
# Методы с доступом с клиента, которые пишут данные без сверки с текущим пользователем
# (для ПР-02), — `Модуль.Метод` по строке; набор собирает `check` (`unguarded_methods`)
# и кладёт файлом. Здесь — путь к этому файлу.
UNGUARDED_ENV = "XBSL_SONAR_UNGUARDED"
# Порог обращений к серверу и базе в обработчике формы для ПР-17 — параметр `--max-accesses`.
MAX_ACCESSES_ENV = "XBSL_SONAR_MAX_ACCESSES"
DEFAULT_MAX_ACCESSES = 3
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
            static = i >= 1 and toks[i - 1].value in ("статический", "static")
            ann = _annotations(toks, i - 1 if static else i)
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


# ПР-05: повышение прав на границе клиента. Метод с параметром-ссылкой — забота ПР-01;
# здесь — остальные методы с доступом с клиента и контекст, открытый не инструкцией `исп`.
_USE = {"исп", "use"}
_GROUP_PRIVILEGED = {"ПривилегированныйРежим", "PrivilegedMode"}
_TRUE = {"Истина", "True"}


def _privileged_at(toks: list, i: int) -> bool:
    """Токен i открывает привилегированный контекст: `Привилегированный(` или
    `ПривилегированныйРежим = Истина` в аргументах (`ГрупповаяОперация.Начать`)."""
    t = toks[i]
    if t.value in _PRIVILEGED:
        return i + 1 < len(toks) and toks[i + 1].value == "("
    return (t.value in _GROUP_PRIVILEGED and i + 2 < len(toks) and toks[i + 1].value == "="
            and toks[i + 2].value in _TRUE)


def _line_start(toks: list, i: int) -> int:
    k = i
    while k > 0 and toks[k - 1].line == toks[i].line:
        k -= 1
    return k


@rule("ПР-05", "Повышение прав с клиента без сверки", "S", severity=Severity.WARNING)
def privileged_from_client(source: SourceFile) -> Iterable[Diagnostic]:
    if source.kind != "xbsl":
        return []
    identity = set(filter(None, os.environ.get(IDENTITY_ENV, "").split(",")))
    own = source.path.name.split(".")[0]
    toks = code_tokens(source)
    out: list[Diagnostic] = []
    frames: list[str] = []
    method = None  # [имя, строка, глубина, привилегии, сверка, с клиента]
    condition = -1
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
                    client = bool(ann & _SERVER and ann & _FROM_CLIENT) and not _reference_params(toks, i)
                    method = [_method_name(toks, i), t.line, len(frames), False, False, client]
        elif t.kind == "OP" and t.value == ";":
            if frames:
                if method is not None and len(frames) == method[2]:
                    name, line, _, privileged, checked, client = method
                    if client and privileged and not checked:
                        out.append(Diagnostic(
                            source.rel, line, 1, "ПР-05", Severity.WARNING,
                            f"Повышение прав {name}: метод доступен с клиента и открывает "
                            f"привилегированный контекст без сверки с текущим пользователем — "
                            f"вызвать его может любой вошедший. Проверить права вызывающего "
                            f"до повышения или не повышать права.",
                        ))
                    method = None
                frames.pop()
        elif t.kind == "IDENT":
            if _privileged_at(toks, i):
                if method is not None:
                    method[3] = True
                start = _line_start(toks, i)
                if t.value in _PRIVILEGED and toks[start].value.lower() not in _USE:
                    out.append(Diagnostic(
                        source.rel, t.line, t.col, "ПР-05", Severity.WARNING,
                        f"Контекст {t.value}: привилегированный контекст открыт не инструкцией "
                        f"«исп» и переживает строку — повышение прав шире блока. Открывать "
                        f"через «исп» в том методе, где оно нужно.",
                    ))
            elif method is not None:
                if t.value in _RIGHT_CHECK and not method[3]:
                    method[4] = True
                elif t.value in _CURRENT_USER and t.line == condition:
                    method[4] = True
                elif i + 1 < len(toks) and toks[i + 1].value == "(" and not (
                        prev is not None and prev.kind == "KEYWORD" and prev.canonical == "METHOD"):
                    qualified = (prev is not None and prev.value == "." and i >= 2
                                 and toks[i - 2].kind == "IDENT")
                    module = toks[i - 2].value if qualified else own
                    if f"{module}.{t.value}" in identity:
                        method[4] = True
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
                    f"КонтейнерHtml {name}: безопасный режим выключен, а содержимое считается "
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
                        f"Содержимое {toks[i - 2].value}: контейнеру с выключенным безопасным "
                        f"режимом задаётся не ресурс — разметка из данных выполнит свои скрипты.",
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
                f"innerHTML: значение не литерал и не из констант, вне функции очистки "
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


# ПР-16: повторяющийся таймер клиента с обработчиком, который доходит до сервера.
_TIMER = {"ПодключитьОбработчикТаймера", "AttachTimerHandler"}
_UNITS = {"мс": 0.001, "ms": 0.001, "с": 1, "s": 1, "м": 60, "m": 60, "ч": 3600, "h": 3600}
_FROM_UNITS = {"ИзМиллисекунд": 0.001, "FromMilliseconds": 0.001, "ИзСекунд": 1,
               "FromSeconds": 1, "ИзМинут": 60, "FromMinutes": 60, "ИзЧасов": 3600,
               "FromHours": 3600}
_DURATION = re.compile(r"^(\d+(?:\.\d+)?)(\D+)$")


def _arguments(toks: list, i: int) -> tuple[list[list], int]:
    """Аргументы вызова, у которого токен i — `(`: списки токенов по запятым верхнего уровня."""
    args: list[list] = [[]]
    depth = 0
    k = i + 1
    while k < len(toks):
        t = toks[k]
        if t.kind == "OP" and t.value in "([{":
            depth += 1
        elif t.kind == "OP" and t.value in ")]}":
            if depth == 0:
                return ([] if args == [[]] else args), k
            depth -= 1
        elif t.kind == "OP" and t.value == "," and depth == 0:
            args.append([])
            k += 1
            continue
        args[-1].append(t)
        k += 1
    return args, k


def _seconds(arg: list) -> float | None:
    """Интервал в секундах: литерал `10с`, `250мс` или `Длительность.ИзСекунд(10)`."""
    if len(arg) == 1 and arg[0].kind == "NUMBER":
        m = _DURATION.match(arg[0].value)
        if m and m.group(2) in _UNITS:
            return float(m.group(1)) * _UNITS[m.group(2)]
        return None
    if (len(arg) == 6 and arg[0].value in ("Длительность", "Duration") and arg[1].value == "."
            and arg[2].value in _FROM_UNITS and arg[4].kind == "NUMBER"):
        try:
            return float(arg[4].value) * _FROM_UNITS[arg[2].value]
        except ValueError:
            return None
    return None


def _method_bodies(toks: list) -> dict[str, tuple[int, int]]:
    """Методы модуля: имя → (первый, последний) индекс токенов тела."""
    out: dict[str, tuple[int, int]] = {}
    frames: list[tuple[str, int, str | None]] = []
    prev = None
    for i, t in enumerate(toks):
        if t.kind == "KEYWORD" and t.canonical in _OPENERS and t.value[:1].islower():
            is_else_if = (t.canonical == "IF" and prev is not None and prev.kind == "KEYWORD"
                          and prev.canonical == "ELSE" and prev.line == t.line)
            is_abstract = (t.canonical == "METHOD" and prev is not None and prev.kind == "KEYWORD"
                           and prev.canonical == "ABSTRACT")
            if not is_else_if and not is_abstract:
                name = _method_name(toks, i) if t.canonical == "METHOD" else None
                frames.append((t.canonical, i, name))
        elif t.kind == "OP" and t.value == ";" and frames:
            canonical, start, name = frames.pop()
            if canonical == "METHOD" and name:
                out[name] = (start, i)
        prev = t
    return out


def _calls(toks: list, start: int, end: int, own: str) -> list[tuple[str, str]]:
    """Безусловные вызовы в токенах [start, end): (ключ `Модуль.Метод`, имя метода).

    Вызов в теле `если` или `выбор` — условный: так обработчик и должен идти на сервер,
    только когда что-то сменилось. Вызов в условии `если` — безусловный: условие
    считается на каждом срабатывании.
    """
    out = []
    frames: list[tuple[str, int]] = []
    prev = None
    for k in range(start, end):
        t = toks[k]
        if t.kind == "KEYWORD" and t.canonical in _OPENERS and t.value[:1].islower():
            is_else_if = (t.canonical == "IF" and prev is not None and prev.kind == "KEYWORD"
                          and prev.canonical == "ELSE" and prev.line == t.line)
            if not is_else_if:
                frames.append((t.canonical, t.line))
        elif t.kind == "OP" and t.value == ";" and frames:
            frames.pop()
        elif (t.kind == "IDENT" and k + 1 < len(toks) and toks[k + 1].value == "("
              and not (prev is not None and prev.kind == "KEYWORD" and prev.canonical == "METHOD")
              and not any(c in ("IF", "CASE") and t.line > line for c, line in frames)):
            if prev is not None and prev.value in (".", "?."):
                if k >= 2 and toks[k - 2].kind == "IDENT" and (k < 3 or toks[k - 3].value != "."):
                    out.append((f"{toks[k - 2].value}.{t.value}", t.value))
            else:
                out.append((f"{own}.{t.value}", t.value))
        prev = t
    return out


def _reaches_server(name: str, toks: list, bodies: dict[str, tuple[int, int]], own: str,
                    server: set[str], local: set[str], seen: set[str]) -> str | None:
    """Серверный метод, до которого безусловно доходит метод модуля `name`, или None."""
    if name in local:
        return name
    if name in seen or name not in bodies:
        return None
    seen.add(name)
    start, end = bodies[name]
    for key, called in _calls(toks, start + 2, end, own):
        if key.split(".")[0] == own and called in bodies:
            found = _reaches_server(called, toks, bodies, own, server, local, seen)
        else:
            found = called if key in server else None
        if found:
            return found
    return None


_SERVER_SET: dict[str, frozenset[str]] = {}


def _server_set() -> frozenset[str]:
    path = os.environ.get(SERVER_ENV, "")
    if path not in _SERVER_SET:
        try:
            with open(path, encoding="utf-8") as f:
                _SERVER_SET[path] = frozenset(filter(None, f.read().splitlines()))
        except OSError:
            _SERVER_SET[path] = frozenset()
    return _SERVER_SET[path]


@rule("ПР-16", "Таймер клиента регулярно вызывает сервер", "D", severity=Severity.WARNING)
def timer_to_server(source: SourceFile) -> Iterable[Diagnostic]:
    if source.kind != "xbsl":
        return []
    toks = code_tokens(source)
    if not any(t.kind == "IDENT" and t.value in _TIMER for t in toks):
        return []
    own = source.path.name.split(".")[0]
    server = _server_set()
    try:
        limit = float(os.environ.get(MIN_PERIOD_ENV) or DEFAULT_MIN_PERIOD)
    except ValueError:
        limit = DEFAULT_MIN_PERIOD
    local = _server_methods(toks)
    bodies = _method_bodies(toks)
    out: list[Diagnostic] = []
    for i, t in enumerate(toks):
        if (t.kind != "IDENT" or t.value not in _TIMER or i + 1 >= len(toks)
                or toks[i + 1].value != "("):
            continue
        args, _ = _arguments(toks, i + 1)
        if len(args) < 2:
            continue
        if len(args) > 2 and not (len(args[2]) == 1 and args[2][0].canonical == "FALSE"):
            continue
        period = _seconds(args[1])
        if period is None or period >= limit:
            continue
        handler = args[0]
        if len(handler) == 2 and handler[0].value == "&" and handler[1].kind == "IDENT":
            name = handler[1].value
            called = [(f"{own}.{name}", name)]
        else:
            arrow = next((k for k, a in enumerate(handler) if a.value == "->"), None)
            if arrow is None:
                continue
            lambda_toks = handler[arrow + 1:]
            name = next((a.value for a in lambda_toks if a.kind == "IDENT"), "лямбда")
            called = _calls(lambda_toks, 0, len(lambda_toks), own)
        via = None
        for key, method in called:
            if key.split(".")[0] == own and (method in bodies or method in local):
                via = _reaches_server(method, toks, bodies, own, server, local, set())
            elif key in server:
                via = method
            if via:
                break
        if via is None:
            continue
        shown = f"{period:g} с" if period >= 1 else f"{period * 1000:g} мс"
        out.append(Diagnostic(
            source.rel, t.line, t.col, "ПР-16", Severity.WARNING,
            f"Таймер {name}: обработчик повторяется раз в {shown} и вызывает сервер "
            f"('{via}') – каждое открытое окно шлёт вызов, даже когда ничего не изменилось. "
            f"Проверять изменения на клиенте, реже опрашивать или сверять одну версию.",
        ))
    return out


# ПР-17: метод, который форма считает при каждой перерисовке, доходит до сервера или базы;
# обработчик формы с числом обращений больше порога.
_YAML_EXPRESSION = re.compile(r"^(\s*)(?:-\s+)?([^\s:#'\"][^:#]*?):\s*(['\"]?)=(.*?)\3?\s*$")
_EXPRESSION_CALL = re.compile(r"(?<![\w.])(?:(\w+)\s*\.\s*)?(\w+)\s*\(")
_YAML_COMPONENT = re.compile(r"^(ВидЭлемента|ElementKind):\s*(КомпонентИнтерфейса|InterfaceComponent)\s*$",
                             re.MULTILINE)
_LIST_ROW = re.compile(r"ПроизвольнаяСтрокаСписка|CustomListRow")
_HANDLER = {"Обработчик", "Handler"}
# Значение по умолчанию свойства компонента считается один раз, при создании, а не на перерисовке
_ONCE = {"ЗначениеПоУмолчанию", "DefaultValue"}

_DATA_SET: dict[str, frozenset[str]] = {}


def _data_set() -> frozenset[str]:
    path = os.environ.get(DATA_ENV, "")
    if path not in _DATA_SET:
        try:
            with open(path, encoding="utf-8") as f:
                _DATA_SET[path] = frozenset(filter(None, f.read().splitlines()))
        except OSError:
            _DATA_SET[path] = frozenset()
    return _DATA_SET[path]


def _pair_component(source: SourceFile) -> bool:
    pair = source.path.with_name(source.path.name.split(".")[0] + ".yaml")
    try:
        return bool(_YAML_COMPONENT.search(pair.read_text(encoding="utf-8-sig")))
    except OSError:
        return False


def _accesses(toks: list, start: int, end: int, own: str, data_set: frozenset[str]) -> int:
    """Запросы и вызовы методов, доходящих до сервера или базы, в токенах [start, end)."""
    count = 0
    prev = None
    for k in range(start, end):
        t = toks[k]
        if t.kind == "KEYWORD" and t.canonical == "QUERY":
            count += 1
        elif (t.kind == "IDENT" and k + 1 < len(toks) and toks[k + 1].value == "("
              and not (prev is not None and prev.kind == "KEYWORD" and prev.canonical == "METHOD")):
            if prev is not None and prev.value in (".", "?."):
                if k >= 2 and toks[k - 2].kind == "IDENT" and (k < 3 or toks[k - 3].value != "."):
                    count += f"{toks[k - 2].value}.{t.value}" in data_set
            else:
                count += f"{own}.{t.value}" in data_set
        prev = t
    return count


@rule("ПР-17", "Обращение к серверу при каждой перерисовке формы", "D", severity=Severity.WARNING)
def redraw_data_access(source: SourceFile) -> Iterable[Diagnostic]:
    data_set = _data_set()
    own = source.path.name.split(".")[0]
    out: list[Diagnostic] = []
    if source.kind == "yaml":
        if not _YAML_COMPONENT.search(source.text):
            return []
        row = bool(_LIST_ROW.search(source.text))
        for n, line in enumerate(source.text.splitlines(), 1):
            m = _YAML_EXPRESSION.match(line)
            if not m:
                continue
            prop = m.group(2).strip()
            if prop in _ONCE:
                continue
            for call in _EXPRESSION_CALL.finditer(m.group(4)):
                module, name = call.group(1), call.group(2)
                key = f"{module or own}.{name}"
                if key not in data_set:
                    continue
                where = ("строка списка считает его на каждую строку при каждой перерисовке"
                         if row else "форма считает его при каждой перерисовке")
                out.append(Diagnostic(
                    source.rel, n, line.find(prop) + 1, "ПР-17", Severity.WARNING,
                    f"Выражение {prop} ={name}(): {where}, а метод '{key}' идёт на сервер "
                    f"или в базу. Получить данные один раз и держать в свойстве компонента "
                    f"или считать на клиенте.",
                ))
                break
    elif source.kind == "xbsl" and _pair_component(source):
        try:
            limit = int(os.environ.get(MAX_ACCESSES_ENV) or DEFAULT_MAX_ACCESSES)
        except ValueError:
            limit = DEFAULT_MAX_ACCESSES
        toks = code_tokens(source)
        for name, (start, end) in _method_bodies(toks).items():
            static = start >= 1 and toks[start - 1].value in ("статический", "static")
            if not _annotations(toks, start - 1 if static else start) & _HANDLER:
                continue
            count = _accesses(toks, start + 2, end, own, data_set)
            if count > limit:
                out.append(Diagnostic(
                    source.rel, toks[start].line, toks[start].col, "ПР-17", Severity.WARNING,
                    f"Обработчик {name}: {count} обращений к серверу и базе подряд (порог {limit}) – "
                    f"каждое отдельным вызовом. Собрать данные одним серверным методом, "
                    f"отдающим структуру.",
                ))
    return out


# ПР-02: элемент, видимый только администратору, а за ним — запись данных без проверки на сервере.
_ADMIN_SWITCH = re.compile(
    r"^(\s*)(-\s+)?(Видимость|Доступность|Visible|Enabled):\s*(['\"]?)=(.*Администратор.*?)\4?\s*$")
_YAML_HANDLER = re.compile(r"^\s*(?:-\s+)?(При\w+|Обработчик|On\w+|Handler):\s*(\w+)\s*$")
_YAML_FIELD = re.compile(
    r"^\s*(?:-\s+)?(?:Значение|Value):\s*(['\"]?)=\s*(?:Объект|Запись|Object|Record)\.(\w+)\s*\1\s*$")
_YAML_NAME = re.compile(r"^\s*(?:-\s+)?(?:Имя|Name):\s*(\S+)\s*$")
_FORM_OF = re.compile(r"(?:ФормаОбъекта|ФормаЗаписи|ObjectForm|RecordForm)<(\w+)\.")
_TEXT_METHOD = re.compile(r"^\s*(?:статический\s+|static\s+)?(?:метод|method)\s+(\w+)", re.IGNORECASE)
_TEXT_CALL = re.compile(r"(?<![\w.])(?:(\w+)\s*\.\s*)?(\w+)\s*\(")
_BEFORE_WRITE = {"ПередЗаписью", "BeforeWrite"}

_UNGUARDED_SET: dict[str, frozenset[str]] = {}


def _unguarded_set() -> frozenset[str]:
    path = os.environ.get(UNGUARDED_ENV, "")
    if path not in _UNGUARDED_SET:
        try:
            with open(path, encoding="utf-8") as f:
                _UNGUARDED_SET[path] = frozenset(filter(None, f.read().splitlines()))
        except OSError:
            _UNGUARDED_SET[path] = frozenset()
    return _UNGUARDED_SET[path]


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _element_span(lines: list[str], n: int, ind: int) -> tuple[int, int]:
    """Строки [начало, конец) отображения YAML, ключи которого стоят с отступом ind
    и которому принадлежит строка n."""
    start = n
    while start > 0 and (not lines[start - 1].strip() or _indent(lines[start - 1]) >= ind):
        start -= 1
    if start > 0 and lines[start - 1].lstrip().startswith("- ") and _indent(lines[start - 1]) == ind - 2:
        start -= 1
    end = n + 1
    while end < len(lines) and (not lines[end].strip() or (_indent(lines[end]) >= ind
                                and not (_indent(lines[end]) == ind - 2
                                         and lines[end].lstrip().startswith("-")))):
        end += 1
    return start, end


def _text_bodies(text: str, server: set[str] | None = None) -> dict[str, str]:
    """Методы модуля по строкам: имя → тело (от заголовка до следующего метода).
    В `server`, если передан, складываются серверные: `@НаСервере` без `@НаКлиенте`."""
    out: dict[str, list[str]] = {}
    current = None
    pending: set[str] = set()
    for line in text.splitlines():
        m = _TEXT_METHOD.match(line)
        if m:
            current = m.group(1)
            out[current] = []
            if server is not None and pending & _SERVER and not pending & _CLIENT:
                server.add(current)
            pending = set()
        elif line.lstrip().startswith("@"):
            pending |= set(re.findall(r"@(\w+)", line))
        elif current:
            out[current].append(line)
    return {k: "\n".join(v) for k, v in out.items()}


def _reaches_unguarded(name: str, bodies: dict[str, str], own: str, unguarded: frozenset[str],
                       server: set[str], seen: set[str]) -> str | None:
    """Метод с доступом с клиента без сверки, до которого доходит метод модуля `name`.
    Серверный метод — граница: дальше вызовы идут на сервере, и проверка в нём их покрывает."""
    if f"{own}.{name}" in unguarded:
        return f"{own}.{name}"
    if name in seen or name not in bodies:
        return None
    seen.add(name)
    for module, called in _TEXT_CALL.findall(bodies[name]):
        key = f"{module or own}.{called}"
        if key in unguarded:
            return key
        if not module and called in bodies and called not in server:
            found = _reaches_unguarded(called, bodies, own, unguarded, server, seen)
            if found:
                return found
    return None


def _read_pair(path, suffix: str) -> str | None:
    try:
        return path.with_name(path.name.split(".")[0] + suffix).read_text(encoding="utf-8-sig")
    except OSError:
        return None


_RIGHT_LINE = re.compile(r"^\s*(Изменение|ПоУмолчанию|Update|Default):\s*(\w+)\s*$", re.MULTILINE)
_ADMINS_ONLY = {"РазрешеноАдминистраторам", "AllowedToAdministrators"}


def _editable_by_others(yaml_text: str) -> bool:
    """Право изменения объекта указано и не ограничено администраторами: `Изменение`,
    а без него — `ПоУмолчанию`. Не указано вовсе — не знаем, считаем закрытым."""
    rights = dict(_RIGHT_LINE.findall(yaml_text))
    value = rights.get("Изменение") or rights.get("Update") or rights.get("ПоУмолчанию") \
        or rights.get("Default")
    return value is not None and value not in _ADMINS_ONLY


def _object_module(source: SourceFile) -> tuple[str, str] | None:
    """Модуль объекта формы (`Тип.Объект.xbsl`, `Тип.НаборЗаписей.xbsl`) рядом с формой
    или уровнем выше: (имя типа, текст), если объект вправе менять не только администратор
    (по `Тип.yaml` там же)."""
    m = _FORM_OF.search(source.text)
    if not m:
        return None
    for folder in (source.path.parent, source.path.parent.parent):
        for suffix in (".Объект.xbsl", ".НаборЗаписей.xbsl"):
            try:
                text = (folder / (m.group(1) + suffix)).read_text(encoding="utf-8-sig")
                described = (folder / (m.group(1) + ".yaml")).read_text(encoding="utf-8-sig")
            except OSError:
                continue
            return (m.group(1), text) if _editable_by_others(described) else None
    return None


def _field_checked(module: tuple[str, str], field: str, identity: set[str]) -> bool:
    """`ПередЗаписью` модуля объекта упоминает реквизит и сверяется с текущим пользователем."""
    own, text = module
    body = next((b for name, b in _text_bodies(text).items() if name in _BEFORE_WRITE), "")
    if not re.search(rf"(?<![\w]){re.escape(field)}(?![\w])", body):
        return False
    for q, name in _TEXT_CALL.findall(body):
        if name in _RIGHT_CHECK or f"{q or own}.{name}" in identity:
            return True
    return False


@rule("ПР-02", "Действие администратора без проверки на сервере", "S", severity=Severity.WARNING)
def admin_only_in_interface(source: SourceFile) -> Iterable[Diagnostic]:
    if source.kind != "yaml" or not _YAML_COMPONENT.search(source.text):
        return []
    lines = source.text.splitlines()
    switches = [(n, m) for n, line in enumerate(lines) if (m := _ADMIN_SWITCH.match(line))]
    if not switches:
        return []
    own = source.path.name.split(".")[0]
    unguarded = _unguarded_set()
    identity = set(filter(None, os.environ.get(IDENTITY_ENV, "").split(",")))
    pair = _read_pair(source.path, ".xbsl")
    server: set[str] = set()
    bodies = _text_bodies(pair, server) if pair is not None else {}
    module = None
    out: list[Diagnostic] = []
    reported: set[int] = set()
    for n, m in switches:
        ind = len(m.group(1)) + (2 if m.group(2) else 0)
        start, end = _element_span(lines, n, ind)
        names = [nm.group(1) for k in range(start, end)
                 if _indent(lines[k]) <= ind and (nm := _YAML_NAME.match(lines[k]))]
        key = f"{m.group(3)} {names[0] if names else own}"
        fields: list[tuple[int, str]] = []
        for k in range(start, end):
            if k in reported:
                continue
            h = _YAML_HANDLER.match(lines[k])
            if h:
                via = _reaches_unguarded(h.group(2), bodies, own, unguarded, server, set())
                if via:
                    reported.add(k)
                    out.append(Diagnostic(
                        source.rel, k + 1, _indent(lines[k]) + 1, "ПР-02", Severity.WARNING,
                        f"{key}: элемент виден только администратору, а {h.group(1)} "
                        f"{h.group(2)} доходит до '{via}' — метод с доступом с клиента пишет "
                        f"в повышенных правах без проверки текущего пользователя. Видимость решает "
                        f"клиент: проверить права в самом серверном методе.",
                    ))
                continue
            f = _YAML_FIELD.match(lines[k])
            if f:
                if module is None:
                    module = _object_module(source) or ("", "")
                if module[0] and not _field_checked(module, f.group(2), identity):
                    reported.add(k)
                    fields.append((k, f.group(2)))
        if fields:
            k = fields[0][0]
            names = ", ".join(name for _, name in fields)
            out.append(Diagnostic(
                source.rel, k + 1, _indent(lines[k]) + 1, "ПР-02", Severity.WARNING,
                f"{key}: {'поле' if len(fields) == 1 else 'поля'} {names} "
                f"{'видно' if len(fields) == 1 else 'видны'} только администратору, а "
                f"'{module[0]}.ПередЗаписью' не {'сверяет его' if len(fields) == 1 else 'сверяет их'} "
                f"с текущим пользователем — значение приходит из данных формы с клиента. "
                f"Проверить в ПередЗаписью, что {'его' if len(fields) == 1 else 'их'} меняет "
                f"администратор.",
            ))
    return out


# ПР-06: секрет строкой. Имя говорит о секрете — переменная, свойство, именованный
# аргумент, ключ соответствия; значение похоже на секрет — длинное, без пробелов,
# кириллицы и подстановок. Токен бота и заголовок авторизации ловятся по самому литералу.
_SECRET_NAME = re.compile(
    r"токен|пароль|секрет|ключapi|ключапи|приватныйключ|закрытыйключ"
    r"|token|passw|secret|apikey|api_key|privatekey|private_key", re.IGNORECASE)
_SECRET_SHAPED = re.compile(
    r"\d{8,10}:[A-Za-z0-9_-]{35}|(?:Bearer|Basic)\s+[A-Za-z0-9+/=._-]{16,}")
_YAML_DEFAULT = re.compile(r"^(\s*)(?:-\s+)?(ЗначениеПоУмолчанию|DefaultValue):\s*(.*?)\s*$")
_YAML_ITEM_KEY = re.compile(r"^(\s*)(?:-\s+)?(Имя|Name|Тип|Type):\s*(.*?)\s*$")
_APP_SECRET = re.compile(r"СекретПриложения|ApplicationSecret")


def _literal(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def _secret_like(value: str) -> bool:
    return (len(value) >= 8 and not re.search(r"[\sа-яА-ЯёЁ%]", value)
            and not value.startswith("="))


def _secret_in_yaml(source: SourceFile) -> list[Diagnostic]:
    out: list[Diagnostic] = []
    lines = source.text.splitlines()
    for n, line in enumerate(lines):
        m = _YAML_DEFAULT.match(line)
        if not m or not _secret_like(_literal(m.group(3))):
            continue
        ind = len(m.group(1))
        name, kind = "", ""
        for k in range(n - 1, -1, -1):
            if lines[k].strip() and _indent(lines[k]) < ind:
                break
            key = _YAML_ITEM_KEY.match(lines[k])
            if key and len(key.group(1)) + (2 if lines[k].lstrip().startswith("-") else 0) == ind:
                if key.group(2) in ("Имя", "Name"):
                    name = key.group(3)
                else:
                    kind = key.group(3)
        if _SECRET_NAME.search(name) or _APP_SECRET.search(kind):
            out.append(Diagnostic(
                source.rel, n + 1, ind + 1, "ПР-06", Severity.WARNING,
                f"Секрет {name or kind}: значение по умолчанию задано строкой в описании элемента — "
                f"оно уходит с исходниками. Задавать секрет в приложении, а не в YAML.",
            ))
    return out


@rule("ПР-06", "Секрет строкой в коде", "S", severity=Severity.WARNING)
def hardcoded_secret(source: SourceFile) -> Iterable[Diagnostic]:
    if source.kind == "yaml":
        return _secret_in_yaml(source)
    if source.kind != "xbsl":
        return []
    toks = code_tokens(source)
    out: list[Diagnostic] = []
    for i, t in enumerate(toks):
        if t.kind != "STRING":
            continue
        value = _literal(t.value)
        if _SECRET_SHAPED.search(value):
            out.append(Diagnostic(
                source.rel, t.line, t.col, "ПР-06", Severity.WARNING,
                "Секрет в строке: литерал похож на токен или заголовок авторизации — "
                "он уходит с исходниками. Хранить в СекретПриложения или в настройках.",
            ))
            continue
        follows = toks[i + 1].value if i + 1 < len(toks) else ""
        if not _secret_like(value) or follows in ("+", "."):
            continue
        prev = toks[i - 1] if i >= 1 else None
        holder = None
        if prev is not None and prev.kind == "OP" and prev.value == "=" and i >= 2 \
                and toks[i - 2].kind == "IDENT":
            holder = toks[i - 2].value
        elif prev is not None and prev.kind == "OP" and prev.value == "," and i >= 2 \
                and toks[i - 2].kind == "STRING" and i >= 3 and toks[i - 3].value == "(":
            holder = _literal(toks[i - 2].value)
        if holder and _SECRET_NAME.search(holder):
            out.append(Diagnostic(
                source.rel, t.line, t.col, "ПР-06", Severity.WARNING,
                f"Секрет {holder}: значение задано строкой в коде — оно уходит с исходниками "
                f"и меняется только сборкой. Хранить в СекретПриложения или в настройках "
                f"и читать на сервере.",
            ))
    return out
