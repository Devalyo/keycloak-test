from mini_keycloak.models import Client, Realm
from mini_keycloak.oidc.errors import InvalidClient
from mini_keycloak.repositories.identity import IdentityRepository
from mini_keycloak.security.client_secrets import ClientSecretService


class ClientService:
    def __init__(self, session):
        self.repository = IdentityRepository(session)
        self.secrets = ClientSecretService()

    def set_secret(self, client: Client, raw: str) -> None:
        if client.public_client:
            raise ValueError('Public clients cannot have secrets')
        client.secret_hash = self.secrets.hash(raw)

    def authenticate(self, realm: Realm, client_id: str, *,
                     secret: str | None = None, method: str = 'none') -> Client:
        client = self.repository.get_client(realm.id, client_id)
        if not realm.enabled or client is None or not client.enabled:
            raise InvalidClient()
        if client.public_client:
            if method != 'none' or secret is not None:
                raise InvalidClient()
        elif (method not in {'client_secret_basic', 'client_secret_post'}
              or not secret or not client.secret_hash
              or not self.secrets.verify(client.secret_hash, secret)):
            raise InvalidClient()
        return client
