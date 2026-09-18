"""Protect the documented realm import and key-management contract."""

from pathlib import Path


PROJECT = Path(__file__).parents[1]


def test_realm_operator_guide_covers_supported_contract_and_recovery():
    guide = " ".join((PROJECT / "README.md").read_text().split())
    # Concepts deliberately avoid snapshotting the complete prose.
    required_topics = {
        "example": ("[valid fixture](tests/fixtures/realm-import/valid-realm.json)", "realm-import"),
        "fields": ("Supported fields", "`realm`", "`clientId`", "`username`", "`passwordPolicy`", "`credentials`"),
        "updates": ("--update", "only supplied fields", "Unlisted entities", "Omitted passwords/secrets stay unchanged", "false", "empty lists/objects"),
        "no destructive replacement": ("no replace/delete mode", "do not delete entities"),
        "URI subset": ("absolute HTTP(S)", "matching remains exact", "Credentials in authority", "fragments", "wildcards", "trailing-dot DNS", "zero-padded ports", "IPv6 zone identifiers"),
        "limits": ("2 MiB", "depth 16", "50,000 values", "1,000 clients", "1,000 users", "256 entries", "64 entries", "duplicate keys"),
        "warnings": ("path-qualified warnings", "ignored", "Review all warnings"),
        "bootstrap": ("bootstrap-demo", "idempotent", "passwords/secrets (including deliberate absence)", "active key, sessions, and unrelated data"),
        "keys": ("realm-key-list", "realm-key-rotate", "active/retained", "retains older keys", "old tokens still verify", "No key deletion command"),
        "recovery": ("consistent database backup", "master secret", "Test restore", "not a master-secret migration"),
    }
    for topic, concepts in required_topics.items():
        for concept in concepts:
            assert concept in guide, f"Missing {topic} documentation: {concept}"
    assert (PROJECT / "tests/fixtures/realm-import/valid-realm.json").is_file()
