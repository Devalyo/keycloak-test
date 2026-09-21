from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError


class PasswordService:
    def __init__(self) -> None:
        self._hasher = PasswordHasher()

    def hash(self, raw: str) -> str:
        if not raw:
            raise ValueError("password must not be empty")
        return self._hasher.hash(raw)

    def verify(self, encoded: str, raw: str) -> bool:
        try:
            return self._hasher.verify(encoded, raw)
        except (InvalidHashError, VerificationError):
            return False
