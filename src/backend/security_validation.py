# src/backend/security_validation.py
"""
Shared input-validation helpers for anything that ends up on a scanner
command line (nmap / nuclei) or is used to build a filesystem path / DB
row for a scan target.

These are used by app.py (both the frontend and API-key scan endpoints)
and by container_scanner.py (the actual subprocess/Docker execution layer)
as defense in depth: validate at the API boundary AND again immediately
before building any command, so there is no path from user input to a
shell/subprocess call that skips validation.
"""
import re

# Any of these characters showing up in a target or option string is treated
# as an attempted injection, regardless of which allow-list regex it might
# otherwise satisfy.
_SHELL_METACHAR_RE = re.compile(r"""[];&|`$(){}<>\n\r'"]""")

_IP_RE = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
_CIDR_RE = re.compile(r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$')

# Multi-label hostname/domain, e.g. "example.com", "sub.example.co.uk"
_HOSTNAME_MULTI_RE = re.compile(
    r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'
    r'(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$'
)

# Single-label hostname, e.g. "localhost", "backend", "postgres" - these are
# legitimate internal service names on this very docker-compose network and
# must not be rejected just because they lack a dot.
_HOSTNAME_SINGLE_RE = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$')

# URL targets - host part may be a single- or multi-label hostname or an IP,
# optionally followed by a port and/or a path.
_URL_RE = re.compile(
    r'^https?://[a-zA-Z0-9]([a-zA-Z0-9.-]{0,253}[a-zA-Z0-9])?(:[0-9]{1,5})?(/.*)?$'
)


def validate_target(target):
    """Validate a scan target (IP, CIDR, hostname, or URL).

    Returns True only for well-formed targets that cannot be interpreted as
    extra command-line flags (rejects anything starting with '-') or shell
    metacharacters.
    """
    if not target or not isinstance(target, str):
        return False

    target = target.strip()
    if not target:
        return False

    # Never allow a target that could be parsed as a flag by nmap/nuclei.
    if target.startswith('-'):
        return False

    if _SHELL_METACHAR_RE.search(target):
        return False

    if _IP_RE.match(target):
        parts = target.split('.')
        return all(0 <= int(p) <= 255 for p in parts)

    if _CIDR_RE.match(target):
        ip_part, mask = target.split('/')
        parts = ip_part.split('.')
        return all(0 <= int(p) <= 255 for p in parts) and 0 <= int(mask) <= 32

    if _HOSTNAME_MULTI_RE.match(target):
        return True

    if _HOSTNAME_SINGLE_RE.match(target):
        return True

    if _URL_RE.match(target):
        return True

    return False


# ---------------------------------------------------------------------------
# nmap option validation
# ---------------------------------------------------------------------------

# Flags that take no argument.
_NMAP_BARE_FLAGS = {
    '-sV', '-sC', '-sS', '-sT', '-sU', '-sN', '-sF', '-sX', '-sA', '-sW', '-sM',
    '-O', '-A', '-Pn', '-PS', '-PA', '-PU', '-PE', '-PP', '-n', '-6', '-v', '-vv',
    '-d', '--open', '--reason', '--traceroute', '-f', '--unprivileged',
    '-T0', '-T1', '-T2', '-T3', '-T4', '-T5',
}

# Flags that consume exactly one following argument token.
_NMAP_ARG_FLAGS = {
    '-p', '--top-ports', '--min-rate', '--max-rate',
    '--version-intensity', '-e', '--script',
}

# Conservative pattern for the *argument* of an arg-flag above - alphanumerics,
# dots, dashes, commas and underscores only (covers port lists like
# "1-1000,8080", interface names, script names, small integers).
_NMAP_ARG_VALUE_RE = re.compile(r'^[a-zA-Z0-9._,\-]{1,100}$')


def validate_nmap_options(options):
    """Validate an nmap options string against an allow-list of flags.

    Rejects anything containing shell metacharacters and any token that
    isn't a recognized flag (or the argument to one of the flags that take
    a value).
    """
    if options is None:
        return False
    if not isinstance(options, str):
        return False
    if _SHELL_METACHAR_RE.search(options):
        return False

    tokens = options.split()
    if not tokens:
        # Empty options string is fine (nmap with no flags, just the target).
        return True

    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok in _NMAP_ARG_FLAGS:
            if i + 1 >= len(tokens) or not _NMAP_ARG_VALUE_RE.match(tokens[i + 1]):
                return False
            i += 2
            continue
        if tok in _NMAP_BARE_FLAGS:
            i += 1
            continue
        return False

    return True


# ---------------------------------------------------------------------------
# nuclei template-type validation
# ---------------------------------------------------------------------------

_NUCLEI_TEMPLATE_RE = re.compile(r'^[a-zA-Z0-9,_\-/]{1,100}$')


def validate_nuclei_template(template_type):
    """Validate the nuclei -t template/tag argument.

    Only alphanumerics, comma, underscore, hyphen and slash are allowed -
    enough to express tags like "cves" or "cves,exposed-panels" or a
    template subdirectory path, but nothing that reaches a shell.
    """
    if not template_type or not isinstance(template_type, str):
        return False
    if _SHELL_METACHAR_RE.search(template_type):
        return False
    return bool(_NUCLEI_TEMPLATE_RE.match(template_type))
