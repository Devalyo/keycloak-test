"""Minimal process and database/signing-key readiness probes."""

import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Blueprint, current_app, jsonify
from sqlalchemy import and_, select

from mini_keycloak.extensions import db
from mini_keycloak.models import Realm, RealmKey
from mini_keycloak.security.key_encryption import decrypt_private_pem
from mini_keycloak.security.logging import log_failure


health = Blueprint('health', __name__, url_prefix='/health')


def _public_key_matches(key, private_key: rsa.RSAPrivateKey) -> bool:
    numbers = private_key.public_key().public_numbers()
    expected = {'kid': key.kid, 'kty': 'RSA', 'alg': 'RS256', 'use': 'sig'}
    for name, number in (('n', numbers.n), ('e', numbers.e)):
        raw = number.to_bytes((number.bit_length() + 7) // 8, 'big')
        expected[name] = base64.urlsafe_b64encode(raw).rstrip(b'=').decode('ascii')
    # Match the generated public-only shape and canonical base64url integers.
    # Extra private members can change how the stored-JWK verifier loads it.
    return key.public_jwk == expected


@health.get('/live')
def live():
    return jsonify(status='ok')


@health.get('/ready')
def ready():
    available = False
    try:
        with db.session.no_autoflush:
            db.session.execute(select(1))
            rows = db.session.execute(select(Realm.id, RealmKey).outerjoin(
                RealmKey, and_(RealmKey.realm_id == Realm.id, RealmKey.active.is_(True))
            ).where(Realm.enabled.is_(True)))
            seen = set()
            for realm_id, key in rows:
                if realm_id in seen or key is None or key.algorithm != 'RS256':
                    raise ValueError('Unavailable signing key')
                seen.add(realm_id)
                pem = decrypt_private_pem(key.encrypted_private_pem, current_app.config['OIDC_KEY_ENCRYPTION_SECRET'])
                private_key = serialization.load_pem_private_key(pem, password=None)
                if not isinstance(private_key, rsa.RSAPrivateKey) or not _public_key_matches(key, private_key):
                    raise ValueError('Unavailable signing key')
            available = True
    except Exception:
        # Neither exception text nor configuration/database values enter logs.
        pass
    finally:
        try:
            db.session.rollback()
        except Exception:
            available = False
        finally:
            try:
                db.session.remove()
            except Exception:
                available = False
    if not available:
        log_failure('health')
        return jsonify(status='unavailable'), 503
    return jsonify(status='ok')
