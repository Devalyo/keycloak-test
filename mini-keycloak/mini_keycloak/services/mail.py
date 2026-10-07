from email.message import EmailMessage
import smtplib
from urllib.parse import urlencode

from mini_keycloak.services.tokens import realm_issuer


def send_password_reset(realm, user, token: str, external_url: str) -> None:
    settings = realm.smtp_server or {}
    if not settings:
        return
    link = (realm_issuer(realm, external_url)
            + '/login-actions/action-token?'
            + urlencode({'key': token}))
    message = EmailMessage()
    message['From'] = settings['from']
    message['To'] = user.email
    message['Subject'] = 'Reset password'
    message.set_content('Open this link to continue resetting your password:\n' + link)
    with smtplib.SMTP(settings['host'], int(settings['port']), timeout=5) as smtp:
        smtp.send_message(message)
