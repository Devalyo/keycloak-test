"""Bounded UTF-8 JSON reads shared by the CLI and packaged bootstrap fixture."""

import json

from .validation import MAX_DOCUMENT_BYTES, RealmImportValidationError, check_document_structure


class RealmImportIOError(ValueError):
    """Fixed public diagnostics without file paths or document values."""


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise RealmImportIOError("Realm import JSON contains duplicate object keys")
        result[key] = value
    return result


def _reject_constant(value):
    raise RealmImportIOError("Realm import file must contain valid JSON")


def read_realm_document(source):
    """Read a pathlib Path or importlib resource, with one overflow sentinel byte.

    No more than 2 MiB of document content is decoded. The extra byte detects
    oversized inputs without an unbounded read or reliance on file metadata.
    """
    try:
        with source.open("rb") as stream:
            raw = stream.read(MAX_DOCUMENT_BYTES + 1)
        if len(raw) > MAX_DOCUMENT_BYTES:
            raise RealmImportIOError("Realm import file exceeds 2 MiB")
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object,
                              parse_constant=_reject_constant)
        if not isinstance(document, dict):
            raise RealmImportIOError("Realm import JSON must be an object")
        check_document_structure(document)
        return document
    except RealmImportIOError as exc:
        message = str(exc)
    except OSError:
        message = "Cannot read realm import file"
    except UnicodeError:
        message = "Realm import file must be UTF-8"
    except RealmImportValidationError:
        message = "Realm import JSON exceeds structural limits or contains invalid values"
    except (ValueError, RecursionError):
        message = "Realm import file must contain valid JSON"
    finally:
        raw = document = None
    # Do not retain decoder/OS exceptions with source content or paths.
    raise RealmImportIOError(message) from None
