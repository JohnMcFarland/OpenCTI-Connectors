"""Extract Waypoint source profiles from the generated per-source connectors.

usage:
    python scripts/extract_profiles.py [--connectors DIR] [--out FILE]
                                       [--fixtures DIR] [--check]

Reads every generated article connector under connectors/ (the 78 built from
the shared feed template: 8 live Phase 1, Phase 2 and Phases 3-6) and writes
connectors/waypoint/sources.yml, one profile per publisher, keyed by the
connector directory name.

Extraction is static: each main.py is parsed with `ast` (nothing is imported
or executed) and config.yml is read as YAML, falling back to a line reader
when the file is not valid YAML (long_war_journal's apostrophe). The
equivalence test in connectors/waypoint/tests imports the same connectors at
runtime and checks every profile against them, so the two methods check each
other.

With --fixtures DIR it also writes the per-source test data the ported tests
need: each connector's tests/ files (the recon feed sample and any extra
fixture) and fixtures/cases.yml (host, link pattern, scope cases, slug cases,
content wrapper markup) read from its test_main.py.

The script stops with a non-zero exit, naming the connector and the reason,
when a connector has code the profile schema cannot express. It never edits
a connector directory.
"""

import argparse
import ast
import re
import shutil
import sys
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent

# --------------------------------------------------------------------------- #
# What the migration plan enables first: the 8 connectors live on OpenCTI
# today. Every other profile is written with enabled: false.
# --------------------------------------------------------------------------- #
LIVE = {
    "bleepingcomputer", "the_hacker_news", "security_affairs", "techcrunch",
    "the_register", "the_record", "cyberscoop", "dark_web_informer",
}

# --------------------------------------------------------------------------- #
# Template layout. Module-level names every generated main.py defines; any
# other top-level name is site code the schema would have to absorb.
# The two known forks are listed with the profile field that replaces them.
# --------------------------------------------------------------------------- #
FORK_NAMES = {
    # Dark Web Informer's members-only precheck -> skip_if: members_only_paywall
    "PAYWALL_RE", "ARTICLE_START_RE", "ARTICLE_END_RE", "_main_article",
    "_is_members_only", "_precheck_members_only",
}

# Engine-wide constants: identical in all 78 today, kept as engine settings.
# The extractor refuses to continue if any connector differs.
ENGINE_CONSTANTS = {
    "MAX_PDF_BYTES": 25 * 1024 * 1024,
    "MAX_TRANSIENT_ATTEMPTS": 5,
    "MAX_PAGE_PROBES": 50,
    "MAX_DESCRIPTION_CHARS": 2000,
    "MIN_VALID_YEAR": 1990,
}
# __init__ settings that are engine settings (same value everywhere).
ENGINE_SETTINGS = {"max_reports": 0, "render_retries": 3, "pdf_render_timeout": 120}

# Profile field order in sources.yml (the schema in docs/WAYPOINT_SCOPE.md
# plus request_delay and author_description, approved 2026-11-12).
FIELDS = [
    "name", "enabled", "author_name", "author_description", "discovery",
    "discovery_config", "feed_urls", "allowed_hosts", "poll_interval",
    "request_delay", "max_age_days", "category_keep", "category_allow",
    "category_deny", "exclude_url_re", "exclude_title_re", "content_selectors",
    "hide_selectors", "date_text_selector", "byline_author", "file_prefix",
    "slug_from_id", "resolve_redirect_hosts", "no_content_is_transient",
    "render_headers", "skip_if", "confidence", "tlp", "report_type",
]


class ExtractError(Exception):
    """A connector cannot be expressed as a profile; the run stops."""


# --------------------------------------------------------------------------- #
# Static evaluation of the constant forms the template uses
# --------------------------------------------------------------------------- #

def _value(node, names):
    """Evaluate one constant's AST node.

    Supported forms (all that occur in the 78): literals, set literals,
    set(), lists that may reference an earlier constant by name, dict
    literals, re.compile(<one string>) (kept as the pattern string) and
    integer products such as 25 * 1024 * 1024.
    """
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        if node.id not in names:
            raise ExtractError(f"reference to unknown name {node.id}")
        return names[node.id]
    if isinstance(node, (ast.List, ast.Tuple)):
        return [_value(e, names) for e in node.elts]
    if isinstance(node, ast.Set):
        # Kept as an ordered list: source order is the primary host first.
        return [_value(e, names) for e in node.elts]
    if isinstance(node, ast.Dict):
        return {_value(k, names): _value(v, names) for k, v in zip(node.keys, node.values)}
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult):
        return _value(node.left, names) * _value(node.right, names)
    if isinstance(node, ast.Call):
        func = ast.unparse(node.func)
        if func == "set" and not node.args and not node.keywords:
            return []
        if func == "re.compile" and len(node.args) == 1 and not node.keywords:
            return _value(node.args[0], names)
    raise ExtractError(f"unsupported constant form: {ast.unparse(node)[:80]}")


def _module_constants(tree):
    """Top-level NAME = value assignments, evaluated in order."""
    names = {}
    for node in tree.body:
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)):
            try:
                names[node.targets[0].id] = _value(node.value, names)
            except ExtractError:
                names[node.targets[0].id] = None   # private helper regexes etc.
    return names


def _top_level_names(tree):
    """Every name a module defines at top level (assignments, defs, classes)."""
    out = set()
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for t in node.targets:
                out.add(ast.unparse(t))
        elif isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            out.add(node.name)
    return out


# --------------------------------------------------------------------------- #
# Per-connector extraction
# --------------------------------------------------------------------------- #

def _connector_class(tree):
    classes = [n for n in tree.body if isinstance(n, ast.ClassDef) and n.name.endswith("Connector")]
    if len(classes) != 1:
        raise ExtractError("expected exactly one *Connector class")
    return classes[0]


def _init_defaults(cls, names):
    """setting("<key>", <default>, ...) calls in __init__ -> {key: default}."""
    init = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == "__init__")
    out = {}
    for node in ast.walk(init):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id == "setting" and len(node.args) >= 2):
            out[_value(node.args[0], names)] = _value(node.args[1], names)
    return out


def _author_description(cls, names):
    """The description passed when the author Organization is created."""
    for node in ast.walk(cls):
        if isinstance(node, ast.Call) and ast.unparse(node.func).endswith("identity.create"):
            kw = {k.arg: k.value for k in node.keywords}
            if "description" in kw:
                return _value(kw["description"], names)
    raise ExtractError("no identity.create(description=...) call")


def _render_headers(cls, names):
    """Extra headers passed to render_live_pdf (BleepingComputer's fork)."""
    for node in ast.walk(cls):
        if isinstance(node, ast.Call) and ast.unparse(node.func) == "render_live_pdf":
            for k in node.keywords:
                if k.arg == "headers":
                    return _value(k.value, names)
    return {}


def _read_config(path, warnings):
    """config.yml as a dict; a line reader when the YAML is invalid."""
    text = path.read_text(encoding="utf-8")
    try:
        return yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        warnings.append(f"config.yml is not valid YAML ({str(exc).splitlines()[0]}); "
                        f"read line by line")
    # Two-level "section:\n  key: 'value'" files, as every generated one is.
    # A single-quoted value is taken up to its last quote, so an unescaped
    # apostrophe inside it ('FDD's Long War Journal') is kept.
    out, section = {}, None
    for line in text.splitlines():
        top = re.match(r"^(\w+):\s*$", line)
        if top:
            section = out.setdefault(top.group(1), {})
            continue
        kv = re.match(r"^  (\w+):\s*(.*?)\s*(?:#.*)?$", line)
        if kv and section is not None:
            raw = kv.group(2)
            if raw.startswith("'") and raw.endswith("'") and len(raw) >= 2:
                value = raw[1:-1].replace("''", "'")
            else:
                value = yaml.safe_load(raw) if raw else None
            section[kv.group(1)] = value
    return out


def extract(slug, cdir, warnings):
    """Build one source profile from connectors/<slug>/."""
    src = (cdir / "main.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    names = _module_constants(tree)
    cls = _connector_class(tree)

    # Site code the schema cannot express: any top-level name beyond the
    # template's, other than the one known fork (mapped to skip_if below).
    extra = _top_level_names(tree) - TEMPLATE_NAMES - {cls.name, f"{cls.name}._precheck"}
    unknown = extra - FORK_NAMES
    if unknown:
        raise ExtractError(f"site code outside the template: {sorted(unknown)}")

    # Engine-wide constants must match the engine's defaults.
    for key, expected in ENGINE_CONSTANTS.items():
        if names.get(key) != expected:
            raise ExtractError(f"{key} = {names.get(key)!r}, engine default is {expected!r}")

    defaults = _init_defaults(cls, names)
    for key, expected in ENGINE_SETTINGS.items():
        if defaults.get(key) != expected:
            raise ExtractError(f"setting {key} default {defaults.get(key)!r} != {expected!r}")

    # config.yml supplies the values the connector actually runs with
    # (config wins over the __init__ default); a disagreement is reported.
    config = _read_config(cdir / "config.yml", warnings).get(slug, {})
    def cfg(key):
        value = config.get(key, defaults.get(key))
        if key in config and key in defaults and str(config[key]) != str(defaults[key]):
            warnings.append(f"config.yml {key}={config[key]!r} differs from the code "
                            f"default {defaults[key]!r}; config.yml used")
        return value

    if names["CONTENT_SELECTORS"][:1] != [names["CONTENT_SELECTOR"]]:
        raise ExtractError("CONTENT_SELECTORS does not start with CONTENT_SELECTOR")

    # Known fork 2: Dark Web Informer's precheck becomes a named skip check.
    skip_if = None
    if FORK_NAMES & extra:
        if extra & FORK_NAMES != FORK_NAMES:
            raise ExtractError(f"partial members-only fork: {sorted(extra & FORK_NAMES)}")
        if "_precheck_members_only" not in src or f"{cls.name}._precheck = _precheck_members_only" not in src:
            raise ExtractError("members-only helpers present but not wired as the precheck")
        skip_if = "members_only_paywall"

    profile = {
        "name": names["SOURCE_NAME"],
        "enabled": slug in LIVE,
        "author_name": cfg("author_name"),
        "author_description": _author_description(cls, names),
        "discovery": names["DISCOVERY"],
        "discovery_config": names["DISCOVERY_CONFIG"],
        "feed_urls": [u.strip() for u in str(cfg("feed_url")).split(",") if u.strip()],
        "allowed_hosts": names["ALLOWED_HOSTS"],
        "poll_interval": int(cfg("poll_interval")),
        "request_delay": int(cfg("request_delay")),
        "max_age_days": int(cfg("max_age_days")),
        "category_keep": names["CATEGORY_KEEP"],
        "category_allow": names["CATEGORY_ALLOW"],
        "category_deny": names["CATEGORY_DENY"],
        "exclude_url_re": names["EXCLUDE_URL_RE"],
        "exclude_title_re": names["EXCLUDE_TITLE_RE"],
        "content_selectors": names["CONTENT_SELECTORS"],
        "hide_selectors": names["HIDE_SELECTORS"],
        "date_text_selector": names["DATE_TEXT_SELECTOR"],
        "byline_author": names["BYLINE_AUTHOR"],
        "file_prefix": names["FILE_PREFIX"],
        "slug_from_id": names["SLUG_FROM_ID"],
        "resolve_redirect_hosts": names["RESOLVE_REDIRECT_HOSTS"],
        "no_content_is_transient": names["NO_CONTENT_IS_TRANSIENT"],
        "render_headers": _render_headers(cls, names),
        "skip_if": skip_if,
        "confidence": int(cfg("confidence")),
        "tlp": cfg("tlp"),
        "report_type": cfg("report_type"),
    }
    # The constant and config.yml must agree on the age limit, since the
    # connector's own default comes from the constant.
    if names["MAX_AGE_DAYS"] != profile["max_age_days"]:
        warnings.append(f"MAX_AGE_DAYS={names['MAX_AGE_DAYS']} but config.yml "
                        f"max_age_days={profile['max_age_days']}; config.yml used")
    if config.get("name") and config["name"] != profile["name"]:
        warnings.append(f"config.yml connector name {config['name']!r} != SOURCE_NAME")
    if any(ord(ch) > 127 for ch in yaml.safe_dump(profile)):
        raise ExtractError("non-ASCII text in profile")
    return profile


# --------------------------------------------------------------------------- #
# Per-source test data (for the ported tests)
# --------------------------------------------------------------------------- #

def _function(tree, name):
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise ExtractError(f"test_main.py has no {name}")


def _string_parts(node):
    """Leaves of a chain of string concatenations ("a" + x + "b")."""
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _string_parts(node.left) + _string_parts(node.right)
    return [node]


def extract_cases(slug, cdir):
    """Per-source test data from connectors/<slug>/test_main.py."""
    src = (cdir / "test_main.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    consts = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name):
            try:
                consts[node.targets[0].id] = ast.literal_eval(node.value)
            except ValueError:
                pass

    # _link(n): f"https://{HOST}/<link_path>{n}/"
    link = re.search(r'return f"https://\{HOST\}/(.*?)\{n\}/"', src)
    if not link:
        raise ExtractError("test_main.py _link() not in the template form")

    # SCOPE_CASES inside TestSiteScope.
    site_scope = next(n for n in ast.walk(tree)
                      if isinstance(n, ast.ClassDef) and n.name == "TestSiteScope")
    scope_cases = next(ast.literal_eval(n.value) for n in site_scope.body
                       if isinstance(n, ast.Assign) and n.targets[0].id == "SCOPE_CASES")

    # test_slug: assert _slug_from_url("<url>") == "<slug>" (first assert).
    slug_cases = []
    for node in ast.walk(_function(tree, "test_slug")):
        if (isinstance(node, ast.Compare) and isinstance(node.left, ast.Call)
                and isinstance(node.left.args[0], ast.Constant)
                and isinstance(node.comparators[0], ast.Constant)):
            slug_cases.append([node.left.args[0].value, node.comparators[0].value])

    # Content wrapper markup: page = ('<open>' + ... + '</close>').encode()
    fn = _function(tree, "test_tag_only_hide_selector")
    assign = next(n for n in fn.body if isinstance(n, ast.Assign))
    parts = _string_parts(assign.value.func.value)
    content_open, content_close = parts[0].value, parts[-1].value

    return {
        "host": consts["HOST"],
        "link_path": link.group(1),
        "sample_has_dates": consts["SAMPLE_HAS_DATES"],
        "sample_has_titles": consts["SAMPLE_HAS_TITLES"],
        "scope_cases": [list(c) for c in scope_cases],
        "slug_cases": slug_cases,
        "content_open": content_open,
        "content_close": content_close,
    }


# --------------------------------------------------------------------------- #
# Driver
# --------------------------------------------------------------------------- #

def generated_connectors(root):
    """Connector directories built from the shared feed template."""
    out = []
    for d in sorted(p for p in root.iterdir() if (p / "main.py").is_file()):
        text = (d / "main.py").read_text(encoding="utf-8", errors="replace")
        if "MAX_PAGE_PROBES" in text and "def _resolve_redirects" in text:
            out.append(d)
    return out


HEADER = """\
# Waypoint source registry: one profile per publisher, keyed by slug.
#
# Generated by scripts/extract_profiles.py from the 78 per-source connectors
# built from the shared feed template (see docs/WAYPOINT_SCOPE.md, "Source
# profile schema"). Until those connectors are retired (migration phase 6)
# regenerate rather than hand-edit, so the equivalence test keeps holding;
# after that this file is the source of truth.
#
# Mounted read-only into the container. Changing it needs only a restart.
# An entry that fails validation disables that source only.
"""


TEMPLATE_NAMES = set()


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--connectors", default=str(REPO / "connectors"))
    ap.add_argument("--out", default=str(REPO / "connectors" / "waypoint" / "sources.yml"))
    ap.add_argument("--fixtures", help="also write per-source test fixtures here")
    ap.add_argument("--check", action="store_true",
                    help="exit 1 if --out differs from what would be written")
    args = ap.parse_args()

    root = Path(args.connectors)
    dirs = generated_connectors(root)
    if not dirs:
        sys.exit(f"no generated connectors under {root}")

    # The template's top-level names: those every generated connector shares.
    global TEMPLATE_NAMES
    name_sets = []
    for d in dirs:
        tree = ast.parse((d / "main.py").read_text(encoding="utf-8"))
        name_sets.append(_top_level_names(tree) - {_connector_class(tree).name})
    TEMPLATE_NAMES = set.intersection(*name_sets)

    profiles, report, failed = {}, [], []
    for d in dirs:
        warnings = []
        try:
            profiles[d.name] = extract(d.name, d, warnings)
        except (ExtractError, StopIteration, KeyError) as exc:
            failed.append(f"{d.name}: {exc}")
            continue
        report.append((d.name, warnings))

    for slug, warnings in report:
        flag = "WARN" if warnings else "ok  "
        print(f"{flag} {slug}" + "".join(f"\n       - {w}" for w in warnings))
    if failed:
        print("\nNOT EXTRACTED:\n  " + "\n  ".join(failed), file=sys.stderr)
        sys.exit(1)

    body = yaml.safe_dump(
        {slug: {k: profiles[slug][k] for k in FIELDS} for slug in sorted(profiles)},
        sort_keys=False, default_flow_style=False, width=100, allow_unicode=False)
    text = HEADER + "\n" + body
    out = Path(args.out)
    if args.check:
        same = out.is_file() and out.read_text(encoding="utf-8") == text
        print(f"\n{out}: {'up to date' if same else 'DIFFERS'}")
        sys.exit(0 if same else 1)
    out.write_text(text, encoding="utf-8", newline="\n")
    print(f"\nwrote {len(profiles)} profiles "
          f"({sum(p['enabled'] for p in profiles.values())} enabled) to {out}")

    if args.fixtures:
        fx = Path(args.fixtures)
        cases = {}
        for d in dirs:
            cases[d.name] = extract_cases(d.name, d)
            dest = fx / d.name
            if dest.exists():
                shutil.rmtree(dest)
            shutil.copytree(d / "tests", dest)
        (fx / "cases.yml").write_text(
            "# Per-source test data, extracted from each generated connector's\n"
            "# test_main.py by scripts/extract_profiles.py --fixtures.\n"
            + yaml.safe_dump(cases, sort_keys=True, width=100, allow_unicode=False),
            encoding="utf-8", newline="\n")
        print(f"wrote fixtures for {len(cases)} sources to {fx}")


if __name__ == "__main__":
    main()
