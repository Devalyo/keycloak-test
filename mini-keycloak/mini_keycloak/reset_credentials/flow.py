"""Compatibility imports for configured authentication flows."""

from mini_keycloak.authentication import (
    AuthenticationProcessor, AuthenticatorContext, AuthenticatorRegistry,
    AuthenticatorResult, DefaultAuthenticationFlow, FlowOutcome, FlowStatus,
)
from mini_keycloak.authentication.constants import (
    AUTHENTICATION_SELECTOR_SCREEN_DISPLAYED,
    RESET_CREDENTIALS_CHOOSE_USER, RESET_CREDENTIAL_EMAIL, RESET_PASSWORD,
)

CHOOSE_USER_EXECUTION = RESET_CREDENTIALS_CHOOSE_USER
EMAIL_GATE_EXECUTION = RESET_CREDENTIAL_EMAIL
UPDATE_PASSWORD_EXECUTION = RESET_PASSWORD
ResetFlow = AuthenticationProcessor
FlowStateError = ValueError

__all__ = [
    'AuthenticationProcessor', 'AuthenticatorContext', 'AuthenticatorRegistry',
    'AuthenticatorResult', 'DefaultAuthenticationFlow', 'FlowOutcome', 'FlowStatus',
    'AUTHENTICATION_SELECTOR_SCREEN_DISPLAYED', 'RESET_CREDENTIALS_CHOOSE_USER',
    'RESET_CREDENTIAL_EMAIL', 'RESET_PASSWORD', 'CHOOSE_USER_EXECUTION',
    'EMAIL_GATE_EXECUTION', 'UPDATE_PASSWORD_EXECUTION', 'ResetFlow', 'FlowStateError',
]
