"""Login form rendering and browser action URL construction."""

from dataclasses import dataclass, replace
from urllib.parse import quote, urlencode

from flask import render_template

from mini_keycloak.models import AuthenticationSession


@dataclass(frozen=True)
class LoginFormsProvider:
    realm_name: str
    authentication_session: AuthenticationSession
    session_code: str
    execution_id: str | None = None

    def for_execution(self, execution_id: str) -> "LoginFormsProvider":
        if not execution_id:
            raise ValueError("Invalid authentication request")
        return replace(self, execution_id=execution_id)

    def _base_parameters(self) -> dict[str, str]:
        return {
            "client_id": self.authentication_session.client.client_id,
            "tab_id": self.authentication_session.tab_id,
            "session_code": self.session_code,
        }

    def _action(self, path: str) -> str:
        if self.execution_id is None:
            raise ValueError("Invalid authentication request")
        parameters = self._base_parameters() | {"execution": self.execution_id}
        return (
            f"/realms/{quote(self.realm_name, safe='')}/login-actions/{path}?"
            f"{urlencode(parameters)}"
        )

    def create_login(self, message: str = "") -> str:
        base = f"/realms/{quote(self.realm_name, safe='')}/login-actions/"
        parameters = self._base_parameters()
        realm = self.authentication_session.realm
        return render_template(
            "login.html",
            display_name=realm.display_name or self.realm_name,
            message=message,
            action=base + "authenticate?" + urlencode(parameters | {"execution": "login"}),
            reset_url=base + "reset-credentials?" + urlencode(parameters),
            forgot_password_allowed=realm.forgot_password_allowed,
        )

    def create_password_reset(self, *, account: bool) -> str:
        return render_template(
            "reset-credentials.html",
            action=self._action("reset-credentials"),
            account=account,
        )

    def create_select_authenticator(self, *, account: bool) -> str:
        return self.create_password_reset(account=account)

    def create_update_password(self, message: str = "") -> str:
        return render_template(
            "update-password.html",
            action=self._action("required-action"),
            message=message,
        )
