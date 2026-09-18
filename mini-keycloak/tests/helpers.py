from __future__ import annotations

from html import unescape
import re
from urllib.parse import parse_qs, urlparse


def form_action(response_text: str, path: str) -> str:
    actions = re.findall(
        r'<form[^>]+action=["\']([^"\']+)["\']', response_text, re.IGNORECASE
    )
    for action in actions:
        candidate = unescape(action)
        if path in urlparse(candidate).path:
            return candidate
    raise AssertionError(f"no form action contains {path!r}: {actions!r}")


def query_value(url: str, name: str) -> str:
    values = parse_qs(urlparse(url).query).get(name, [])
    if len(values) != 1:
        raise AssertionError(f"expected one {name!r} value in {url!r}")
    return values[0]
