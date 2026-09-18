"""Client credential hashing, separate from user password policy."""

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError


class ClientSecretService:
    def __init__(self):
        self._hasher = PasswordHasher()

    def hash(self, raw: str) -> str:
        if not raw:
            raise ValueError('Client secret must not be empty')
        return self._hasher.hash(raw)

    def verify(self, encoded: str, raw: str) -> bool:
        try:
            return self._hasher.verify(encoded, raw)
        except (InvalidHashError, VerificationError):
            return False
