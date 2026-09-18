"""Evaluate the supported, already validated password-policy clauses."""


def password_satisfies_policy(password: str, clauses) -> bool:
    """Count Unicode characters; special characters are non-alphanumeric.

    Accept parsed clause mappings, never raw Keycloak policy strings. This
    evaluator neither retains passwords nor reports their values.
    """
    counts = {
        "length": len(password),
        "digits": sum(character.isdigit() for character in password),
        "lowerCase": sum(character.islower() for character in password),
        "upperCase": sum(character.isupper() for character in password),
        "specialChars": sum(not character.isalnum() for character in password),
    }
    return all(count >= clauses.get(name, 0) for name, count in counts.items())
