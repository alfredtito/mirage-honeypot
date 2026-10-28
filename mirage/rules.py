"""Detection rule specs: validation, matching (used for replay verification), and rendering.

The model proposes a small structured spec; deterministic code validates it, replays it against
logged traffic, and renders nginx / ModSecurity / Sigma text. The model never writes config syntax.
"""
from __future__ import annotations

import functools
import hashlib
import json
import re
import uuid
from dataclasses import asdict, dataclass
from urllib.parse import unquote_plus

METHODS = {"", "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"}
MAX_RX = 150
_NESTED_QUANT = re.compile(r"\((?:[^()\\]|\\.)*[+*](?:[^()\\]|\\.)*\)[+*{]")
_BAD_CHARS = re.compile(r"[\"\n\r\x00`]")
_NGINX_VAR = re.compile(r"\$\w")
_TECH = re.compile(r"^T\d{4}(\.\d{3})?$")


class RuleError(ValueError):
    pass


@dataclass(frozen=True)
class RuleSpec:
    title: str
    method: str = ""
    path_regex: str = ""
    query_regex: str = ""
    ua_regex: str = ""
    body_regex: str = ""
    rationale: str = ""
    technique: str = ""

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True)

    @property
    def digest(self) -> str:
        return hashlib.sha1(self.to_json().encode()).hexdigest()

    @property
    def number(self) -> int:
        return 1_000_000 + int(self.digest[:8], 16) % 900_000


def _check_regex(name: str, rx) -> str:
    if rx in (None, ""):
        return ""
    if not isinstance(rx, str):
        raise RuleError(f"{name} must be a string")
    rx = rx.strip()
    if len(rx) > MAX_RX:
        raise RuleError(f"{name} is longer than {MAX_RX} characters")
    if _BAD_CHARS.search(rx):
        raise RuleError(f"{name} contains a forbidden character (double quote, backtick or newline)")
    if _NGINX_VAR.search(rx):
        raise RuleError(f"{name}: use '$' only as an end-of-string anchor")
    if _NESTED_QUANT.search(rx):
        raise RuleError(f"{name} has a nested quantifier (ReDoS risk)")
    try:
        compiled = re.compile(rx, re.I)
    except re.error as e:
        raise RuleError(f"{name} is not a valid regex ({e})") from e
    if compiled.search(""):
        raise RuleError(f"{name} matches the empty string, so it would match everything")
    return rx


def _clean(s, n: int) -> str:
    return re.sub(r"\s+", " ", re.sub(r"[^\w .,:/()+#'-]", "", str(s or ""))).strip()[:n]


def spec_from_dict(d) -> RuleSpec:
    if not isinstance(d, dict):
        raise RuleError("rule must be a JSON object")
    method = str(d.get("method", "") or "").upper().strip()
    if method not in METHODS:
        raise RuleError(f"unsupported method {method!r}")
    fields = {k: _check_regex(k, d.get(k)) for k in ("path_regex", "query_regex", "ua_regex", "body_regex")}
    if not any(fields.values()):
        raise RuleError("rule has no regex condition")
    tech = str(d.get("technique", "") or "").strip()
    return RuleSpec(
        title=_clean(d.get("title"), 80) or "Unnamed rule",
        method=method,
        rationale=_clean(d.get("rationale"), 200),
        technique=tech if _TECH.match(tech) else "",
        **fields,
    )


@functools.lru_cache(maxsize=512)
def _rx(pattern: str):
    return re.compile(pattern, re.I)


def matches(spec: RuleSpec, ev: dict) -> bool:
    """ev: method, path (URL-decoded by the server), query (raw), body, ua."""
    if spec.method and (ev.get("method") or "").upper() != spec.method:
        return False
    targets = (
        (spec.path_regex, ev.get("path") or ""),
        (spec.query_regex, unquote_plus(ev.get("query") or "")),
        (spec.ua_regex, ev.get("ua") or ""),
        (spec.body_regex, unquote_plus((ev.get("body") or "")[:4000])),
    )
    return all(_rx(rx).search(val) for rx, val in targets if rx)


# ---------------- renderers ----------------

def render_nginx(spec: RuleSpec) -> str:
    head = [f"# {spec.title}", f"# {spec.rationale}".rstrip()]
    if spec.body_regex:
        return "\n".join(head + ["# not expressible in stock nginx (needs request-body inspection); use the ModSecurity rule"])
    esc = lambda rx: rx.replace("\\", "\\\\")  # nginx collapses \\ inside quoted strings
    name = f"mr_{spec.number}"
    conds: list[tuple[str, str]] = []
    if spec.method:
        conds.append(("M", f"$request_method = {spec.method}"))
    if spec.path_regex:
        conds.append(("P", f'$uri ~* "{esc(spec.path_regex)}"'))
    if spec.query_regex:
        conds.append(("Q", f'$args ~* "{esc(spec.query_regex)}"'))
    if spec.ua_regex:
        conds.append(("U", f'$http_user_agent ~* "{esc(spec.ua_regex)}"'))
    out = head
    if spec.query_regex:
        out.append("# note: nginx sees $args URL-encoded, so encoded variants may need extra patterns")
    out.append(f'set ${name} "";')
    for flag, cond in conds:
        out.append(f"if ({cond}) {{ set ${name} \"${{{name}}}{flag}\"; }}")
    out.append(f'if (${name} = "{"".join(f for f, _ in conds)}") {{ return 403; }}')
    return "\n".join(out)


def render_modsecurity(spec: RuleSpec) -> str:
    chain: list[tuple[str, str, str]] = []  # (variable, operator, transforms)
    if spec.method:
        chain.append(("REQUEST_METHOD", f"@streq {spec.method}", "t:none"))
    if spec.path_regex:
        chain.append(("REQUEST_FILENAME", f"@rx (?i){spec.path_regex}", "t:none"))
    if spec.query_regex:
        chain.append(("QUERY_STRING", f"@rx (?i){spec.query_regex}", "t:none,t:urlDecodeUni"))
    if spec.ua_regex:
        chain.append(("REQUEST_HEADERS:User-Agent", f"@rx (?i){spec.ua_regex}", "t:none"))
    if spec.body_regex:
        chain.append(("REQUEST_BODY", f"@rx (?i){spec.body_regex}", "t:none,t:urlDecodeUni"))
    phase = 2 if spec.body_regex else 1
    msg = spec.title.replace("'", "")
    lines = [f"# {spec.title}"]
    if spec.body_regex:
        lines.append("# requires: SecRequestBodyAccess On")
    for i, (var, op, tf) in enumerate(chain):
        more = i < len(chain) - 1
        if i == 0:
            actions = f"id:{spec.number},phase:{phase},deny,status:403,log,msg:'{msg}'" + (",chain" if more else "")
            lines.append(f'SecRule {var} "{op}" "{actions}"')
        else:
            lines.append(f'    SecRule {var} "{op}" "{tf}' + (',chain"' if more else '"'))
    return "\n".join(lines)


def _yq(s: str) -> str:
    return "'" + s.replace("'", "''") + "'"


def render_sigma(spec: RuleSpec) -> str:
    if spec.body_regex:  # a Sigma web rule without the body condition would be far broader than what was verified
        return "\n".join([f"# {spec.title}", f"# {spec.rationale}".rstrip(),
                          "# not expressible as a Sigma web-log rule (web servers do not log request bodies); "
                          "use the ModSecurity rule"])
    sel = []
    if spec.method:
        sel.append(f"    cs-method: {spec.method}")
    if spec.path_regex:
        sel.append(f"    c-uri|re: {_yq('(?i)' + spec.path_regex)}")
    if spec.query_regex:
        sel.append(f"    cs-uri-query|re: {_yq('(?i)' + spec.query_regex)}")
    if spec.ua_regex:
        sel.append(f"    cs-user-agent|re: {_yq('(?i)' + spec.ua_regex)}")
    lines = [
        f"title: {_yq(spec.title)}",
        f"id: {uuid.uuid5(uuid.NAMESPACE_URL, spec.digest)}",
        "status: experimental",
        f"description: {_yq(spec.rationale or spec.title)}",
        "author: Mirage honeypot analyst",
        "logsource:",
        "    category: webserver",
        "detection:",
        "  selection:",
        *sel,
    ]
    lines += ["  condition: selection", "level: medium"]
    if spec.technique:
        lines += ["tags:", f"    - attack.{spec.technique.lower()}"]
    return "\n".join(lines)


RENDERERS = {"nginx": render_nginx, "modsecurity": render_modsecurity, "sigma": render_sigma}
