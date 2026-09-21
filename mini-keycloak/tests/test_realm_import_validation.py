from dataclasses import FrozenInstanceError, replace

import pytest

from mini_keycloak.extensions import db
from mini_keycloak.models import Realm, User


def test_user_import_fields_persist_with_independent_empty_attribute_defaults(db_app):
    with db_app.app_context():
        realm = Realm(name="profiles")
        db.session.add(realm)
        db.session.flush()
        first = User(realm_id=realm.id, username="alice", username_normalized="alice")
        second = User(realm_id=realm.id, username="bob", username_normalized="bob")
        db.session.add_all([first, second])
        db.session.flush()
        assert getattr(first, "attributes", None) == {}
        assert first.attributes is not second.attributes
        first.first_name = "Alice"
        first.last_name = "Example"
        first.attributes = {"department": ["engineering"]}
        db.session.commit()
        db.session.expire_all()
        assert (first.first_name, first.last_name, first.attributes) == (
            "Alice", "Example", {"department": ["engineering"]},
        )
        assert second.first_name is None
        assert second.last_name is None
        assert second.attributes == {}


@pytest.mark.parametrize("field,value", [
    ("first_name", 42), ("first_name", "a" * 256),
    ("last_name", "a" * 256), ("last_name", []),
    ("attributes", []), ("attributes", {"department": "engineering"}),
    ("attributes", {"x": [1]}), ("attributes", {"x": ["a" * 2049]}),
])
def test_user_profile_rejects_invalid_import_field_values(field, value):
    with pytest.raises(ValueError):
        User(**{field: value})


def validate(document, **kwargs):
    # Import inside the helper so a missing implementation fails these cases,
    # without preventing unrelated model/migration tests from running.
    from mini_keycloak.import_export.validation import validate_realm_import
    return validate_realm_import(document, **kwargs)


def errors(document, **kwargs):
    from mini_keycloak.import_export.validation import RealmImportValidationError
    with pytest.raises(RealmImportValidationError) as caught:
        validate(document, **kwargs)
    assert not hasattr(caught.value, "value")
    pairs = [(issue.path, issue.message) for issue in caught.value.errors]
    assert pairs == sorted(pairs)
    return caught.value, {path for path, _ in pairs}


def test_valid_document_maps_supported_fields_without_application_or_database():
    result = validate({
        "realm": " Example ", "displayName": "Example Realm", "enabled": False,
        "resetPasswordAllowed": False, "passwordPolicy": "length(8) and digits(1) and lowerCase(1) and upperCase(1) and specialChars(1)",
        "accessTokenLifespan": 300, "accessCodeLifespan": 60,
        "ssoSessionIdleTimeout": 1800, "ssoSessionMaxLifespan": 36000,
        "attributes": {"mini.keycloak.passwordGrantEnabled": "true"},
        "clients": [{
            "clientId": " Browser ", "name": "Example Browser", "enabled": False,
            "publicClient": False, "secret": "client-private-value",
            "redirectUris": ["https://app.example/callback?channel=web"],
            "webOrigins": ["https://app.example"], "standardFlowEnabled": False,
            "directAccessGrantsEnabled": True, "defaultClientScopes": ["openid", "profile"],
            "optionalClientScopes": ["email"],
            "attributes": {"pkce.code.challenge.method": "S256", "post.logout.redirect.uris": "https://app.example/out##http://localhost:9000/out"},
        }],
        "users": [{
            "username": " Alice ", "email": " ALICE@Example.test ", "enabled": False,
            "emailVerified": True, "firstName": "Alice", "lastName": "Example",
            "attributes": {"department": ["engineering"]},
            "credentials": [{"type": "password", "value": "user-private-value", "temporary": False}],
        }],
    })
    assert result.warnings == ()
    realm = result.value
    assert (realm.name, realm.name_normalized, realm.display_name) == ("Example", "example", "Example Realm")
    assert realm.enabled is False and realm.forgot_password_allowed is False
    assert realm.password_grant_enabled is True
    assert (realm.access_token_lifetime_seconds, realm.authorization_code_lifetime_seconds,
            realm.sso_idle_lifetime_seconds, realm.sso_max_lifetime_seconds) == (300, 60, 1800, 36000)
    assert realm.password_policy.raw.startswith("length(8)")
    assert dict(realm.password_policy.clauses) == {"length": 8, "digits": 1, "lowerCase": 1, "upperCase": 1, "specialChars": 1}
    client = realm.clients[0]
    assert (client.client_id, client.client_id_normalized, client.name) == ("Browser", "browser", "Example Browser")
    assert client.enabled is False and client.public_client is False
    assert client.secret == "client-private-value"
    assert client.redirect_uris == ("https://app.example/callback?channel=web",)
    assert client.web_origins == ("https://app.example",)
    assert client.standard_flow_enabled is False and client.direct_access_grants_enabled is True
    assert client.default_scopes == ("openid", "profile") and client.optional_scopes == ("email",)
    assert client.pkce_policy == "S256"
    assert client.post_logout_redirect_uris == ("https://app.example/out", "http://localhost:9000/out")
    user = realm.users[0]
    assert (user.username, user.username_normalized, user.email, user.email_normalized) == ("Alice", "alice", "ALICE@Example.test", "alice@example.test")
    assert user.enabled is False and user.email_verified is True
    assert (user.first_name, user.last_name, dict(user.attributes)) == ("Alice", "Example", {"department": ("engineering",)})
    assert user.credentials[0].value == "user-private-value"
    assert "client-private-value" not in repr(result)
    assert "user-private-value" not in repr(result)


def test_dtos_are_deeply_immutable_and_do_not_share_input_state():
    document = {"realm": "example", "users": [{"username": "alice", "attributes": {"team": ["one"]}}]}
    result = validate(document)
    document["users"][0]["attributes"]["team"].append("two")
    assert result.value.users[0].attributes["team"] == ("one",)
    with pytest.raises(FrozenInstanceError):
        result.value.enabled = False
    with pytest.raises(TypeError):
        result.value.users[0].attributes["team"] = ("two",)


def test_defaults_preserve_presence_and_explicit_empty_values():
    result = validate({"realm": "example", "clients": [{"clientId": "app"}], "users": [{"username": "alice"}]})
    realm = result.value
    assert realm.present_fields == frozenset({"realm", "clients", "users"})
    assert realm.enabled is True and realm.password_grant_enabled is False
    assert realm.clients[0].public_client is True
    assert realm.clients[0].pkce_policy == "S256"
    assert realm.clients[0].default_scopes == ("openid", "profile", "email")
    assert realm.users[0].credentials == ()
    explicit = validate({"realm": "example", "enabled": False, "users": [], "clients": [], "passwordPolicy": ""}).value
    assert explicit.enabled is False and explicit.users == ()
    assert explicit.present_fields == frozenset({"realm", "enabled", "users", "clients", "passwordPolicy"})


def test_optional_pkce_and_supported_web_origin_forms():
    client = validate({"realm": "example", "clients": [{
        "clientId": "app", "attributes": {"pkce.code.challenge.method": "optional"},
        "webOrigins": ["+", "http://localhost:9000", "https://[::1]:443"],
    }]}).value.clients[0]
    assert client.pkce_policy == "optional"
    assert client.web_origins == ("+", "http://localhost:9000", "https://[::1]:443")


def test_unknown_fields_and_policy_clauses_warn_with_stable_paths():
    result = validate({"realm": "example", "zeta": "private-unknown-value", "alpha": {},
        "passwordPolicy": "length(8) and hashIterations(210000)",
        "attributes": {"unsupported": "private-unknown-value"},
        "clients": [{"clientId": "app", "protocolMappers": [], "attributes": {"unknown": "private-unknown-value"}}],
        "users": [{"username": "alice", "realmRoles": ["member"]}],
    })
    assert [item.path for item in result.warnings] == [
        "$.alpha", "$.attributes.unsupported", "$.clients[0].attributes.unknown",
        "$.clients[0].protocolMappers", "$.passwordPolicy[1]", "$.users[0].realmRoles", "$.zeta",
    ]
    assert "private-unknown-value" not in repr(result.warnings)
    assert result.value.password_policy.raw == "length(8) and hashIterations(210000)"
    assert dict(result.value.password_policy.clauses) == {"length": 8}
    with pytest.raises(FrozenInstanceError):
        result.warnings[0].message = "changed"


@pytest.mark.parametrize("document,path", [
    ([], "$"), ({}, "$.realm"), ({"realm": None}, "$.realm"),
    ({"realm": True}, "$.realm"), ({"realm": " "}, "$.realm"),
    ({"realm": "../realm"}, "$.realm"), ({"realm": "a" * 256}, "$.realm"),
    ({"realm": "r", "enabled": "true"}, "$.enabled"),
    ({"realm": "r", "resetPasswordAllowed": 1}, "$.resetPasswordAllowed"),
    ({"realm": "r", "accessTokenLifespan": True}, "$.accessTokenLifespan"),
    ({"realm": "r", "accessCodeLifespan": 0}, "$.accessCodeLifespan"),
    ({"realm": "r", "ssoSessionIdleTimeout": -1}, "$.ssoSessionIdleTimeout"),
    ({"realm": "r", "ssoSessionMaxLifespan": 2**31}, "$.ssoSessionMaxLifespan"),
    ({"realm": "r", "clients": {}}, "$.clients"),
    ({"realm": "r", "users": None}, "$.users"),
    ({"realm": "r", "attributes": []}, "$.attributes"),
    ({"realm": "r", "attributes": {"mini.keycloak.passwordGrantEnabled": True}}, '$.attributes["mini.keycloak.passwordGrantEnabled"]'),
    ({"realm": "r", "attributes": {"mini.keycloak.passwordGrantEnabled": "yes"}}, '$.attributes["mini.keycloak.passwordGrantEnabled"]'),
])
def test_realm_scalar_structure_and_lifetime_validation(document, path):
    assert path in errors(document)[1]


@pytest.mark.parametrize("field,value,path", [
    ("clientId", [], "clientId"), ("publicClient", 0, "publicClient"),
    ("secret", "secret-sentinel", "secret"),
    ("redirectUris", "https://app.example/callback", "redirectUris"),
    ("redirectUris", [42], "redirectUris[0]"),
    ("redirectUris", ["/callback"], "redirectUris[0]"),
    ("redirectUris", ["https://app.example/*"], "redirectUris[0]"),
    ("redirectUris", ["https://user:password@app.example/callback"], "redirectUris[0]"),
    ("redirectUris", ["https://app.example/callback#fragment"], "redirectUris[0]"),
    ("redirectUris", ["javascript:alert(1)"], "redirectUris[0]"),
    ("redirectUris", ["https://app.example:bad/callback"], "redirectUris[0]"),
    ("webOrigins", ["*"], "webOrigins[0]"),
    ("webOrigins", ["https://app.example/path"], "webOrigins[0]"),
    ("defaultClientScopes", ["roles"], "defaultClientScopes[0]"),
    ("optionalClientScopes", ["offline_access"], "optionalClientScopes[0]"),
    ("attributes", {"pkce.code.challenge.method": "plain"}, 'attributes["pkce.code.challenge.method"]'),
    ("attributes", {"post.logout.redirect.uris": "https://app.example/out##/local"}, 'attributes["post.logout.redirect.uris"][1]'),
    ("attributes", {"post.logout.redirect.uris": []}, 'attributes["post.logout.redirect.uris"]'),
])
def test_client_validation(field, value, path):
    document = {"realm": "r", "clients": [{"clientId": "app", field: value}]}
    caught, paths = errors(document)
    assert f"$.clients[0].{path}" in paths
    assert "secret-sentinel" not in str(caught) + repr(caught)


def test_confidential_client_requires_secret_on_create_but_update_can_omit_it():
    document = {"realm": "r", "clients": [{"clientId": "app", "publicClient": False}]}
    assert "$.clients[0].secret" in errors(document)[1]
    client = validate(document, update=True).value.clients[0]
    assert client.secret is None and "secret" not in client.present_fields
    errors({"realm": "r", "clients": [{"clientId": "app", "publicClient": False, "secret": ""}]}, update=True)


@pytest.mark.parametrize("field,value,path", [
    ("username", " ", "username"), ("email", [], "email"),
    ("email", "bad-address", "email"), ("email", "a" * 321, "email"),
    ("emailVerified", "false", "emailVerified"), ("enabled", 1, "enabled"),
    ("firstName", "a" * 256, "firstName"), ("lastName", 42, "lastName"),
    ("attributes", {"team": "engineering"}, "attributes.team"),
    ("attributes", {"team": [False]}, "attributes.team[0]"),
    ("credentials", {}, "credentials"),
    ("credentials", [{"type": "otp", "value": "secret-sentinel"}], "credentials[0].type"),
    ("credentials", [{"type": "password", "value": "secret-sentinel", "temporary": True}], "credentials[0].temporary"),
    ("credentials", [{"type": "password", "value": "secret-sentinel", "temporary": 0}], "credentials[0].temporary"),
    ("credentials", [{"type": "password"}], "credentials[0].value"),
    ("credentials", [{"type": "password", "value": ""}], "credentials[0].value"),
    ("credentials", [{"type": "password", "value": "secret-sentinel", "credentialData": "opaque"}], "credentials[0].credentialData"),
    ("credentials", [{"type": "password", "value": "one"}, {"type": "password", "value": "two"}], "credentials"),
])
def test_user_and_credential_validation(field, value, path):
    caught, paths = errors({"realm": "r", "users": [{"username": "alice", field: value}]})
    assert f"$.users[0].{path}" in paths
    assert "secret-sentinel" not in str(caught) + repr(caught)


def test_normalized_duplicates_are_reported_for_clients_users_and_emails():
    _, paths = errors({"realm": "r", "clients": [{"clientId": "App"}, {"clientId": " app "}],
        "users": [{"username": "Straße", "email": "Alice@example.test"},
                  {"username": " STRASSE ", "email": " alice@EXAMPLE.test "}],
    })
    assert paths == {"$.clients[1].clientId", "$.users[1].username", "$.users[1].email"}


@pytest.mark.parametrize("policy", ["length(foo)", "digits(-1)", "length(0)", "upperCase(999999)",
    "length(8) and length(10)", "length(8) and", "broken clause", "length(8.0)"])
def test_malformed_or_invalid_known_password_policy_clauses_fail(policy):
    assert any(path.startswith("$.passwordPolicy") for path in errors({"realm": "r", "passwordPolicy": policy})[1])


def test_invalid_document_collects_all_independent_errors_in_stable_order():
    document = {"realm": "", "enabled": 1, "accessTokenLifespan": -1,
        "clients": [None, {"clientId": "app", "publicClient": False, "redirectUris": ["/bad"]}],
        "users": [{"username": "", "emailVerified": 1, "credentials": [{"type": "otp", "value": "secret-sentinel"}]}],
    }
    first, paths = errors(document)
    assert paths == {"$.realm", "$.enabled", "$.accessTokenLifespan", "$.clients[0]", "$.clients[1].secret",
        "$.clients[1].redirectUris[0]", "$.users[0].username", "$.users[0].emailVerified", "$.users[0].credentials[0].type"}
    reordered = dict(reversed(list(document.items())))
    assert str(first) == str(errors(reordered)[0])


@pytest.mark.parametrize("document", [
    {"realm": "r", "clients": [{"clientId": "app"}] * 1001},
    {"realm": "r", "users": [{"username": "alice"}] * 1001},
    {"realm": "r", "users": [{"username": "alice", "attributes": {str(i): ["v"] for i in range(65)}}]},
    {"realm": "r", "clients": [{"clientId": "app", "redirectUris": ["https://app.example/cb"] * 257}]},
    {"realm": "r", "passwordPolicy": "x" * 4097},
    {"realm": "r", "users": [{"username": "alice", "credentials": [{"type": "password", "value": "x" * 4097}]}]},
])
def test_entity_list_attribute_and_string_budgets(document):
    errors(document)


def test_unknown_nested_input_is_bounded_and_non_json_values_fail_safely():
    deep = {}
    for _ in range(100):
        deep = {"nested": deep}
    errors({"realm": "r", "unknown": deep})
    cyclic = []
    cyclic.append(cyclic)
    errors({"realm": "r", "unknown": cyclic})
    errors({"realm": "r", "unknown": object()})
    errors({"realm": "r", "unknown": float("nan")})
    errors({"realm": "r", "unknown": "x" * (2 * 1024 * 1024)})


@pytest.mark.parametrize("document,path", [
    ({"realm": "r", "users": [{"username": "ß" * 128}]}, "$.users[0].username"),
    ({"realm": "r", "clients": [{"clientId": "ß" * 128}]}, "$.clients[0].clientId"),
    ({"realm": "r", "users": [{"username": "alice", "email": "ß" * 160 + "@example.test"}]}, "$.users[0].email"),
])
def test_normalized_identifiers_must_fit_persistent_column_limits(document, path):
    assert path in errors(document)[1]


def test_update_can_rotate_secret_with_omitted_client_type_for_service_resolution():
    client = validate({"realm": "r", "clients": [{"clientId": "app", "secret": "new-private-secret"}]}, update=True).value.clients[0]
    assert client.secret == "new-private-secret"
    assert "publicClient" not in client.present_fields
    assert "new-private-secret" not in repr(client)


def test_nested_attribute_presence_allows_update_to_preserve_omitted_policy():
    client = validate({"realm": "r", "clients": [{"clientId": "app", "attributes": {"post.logout.redirect.uris": ""}}]}, update=True).value.clients[0]
    assert "attributes" in client.present_fields
    assert "pkce.code.challenge.method" not in client.attributes
    assert client.attributes["post.logout.redirect.uris"] == ""
    assert client.post_logout_redirect_uris == ()


@pytest.mark.parametrize("field", ["redirectUris", "webOrigins", "logout"])
@pytest.mark.parametrize("authority", [
    "exa%mple.test", "example.test%2f.other.test", "-example.test",
    "example-.test", "example..test", ".example.test", "example.test.",
    "exam_ple.test", "éxample.test", "example.test:", "example.test:00443",
    "example.test:65536", "example.test:-1", "example.test:+443",
    "user@example.test", "user:password@example.test", "[::1]garbage",
    "[::1]:", "[::1]:443:443", "[::1", "::1", "[v1.host]",
    "[fe80::1%25eth0]", "127.1", "0177.0.0.1", "0x7f000001",
    "2130706433", "256.1.1.1", "example.123", "example.0x10",
    "example.test\\other.test", "example.test\t", "example.test\n",
    "example.test\x7f", "example.test ",
])
def test_url_fields_reject_malformed_or_ambiguous_authorities(field, authority):
    client = {"clientId": "app"}
    uri = f"https://{authority}"
    if field == "logout":
        client["attributes"] = {"post.logout.redirect.uris": uri}
    else:
        client[field] = [uri]
    errors({"realm": "r", "clients": [client]})


@pytest.mark.parametrize("field", ["redirectUris", "logout"])
@pytest.mark.parametrize("suffix", [
    "/%", "/%0", "/%zz", "/ok?bad=%x0", "/<>", '/"', "/{x}",
    "/[x]", "/|", "/^", "/`", "/café", "/a\\b", "/a b",
    "/a\x00b", "/a\r\nb", "/a\u00a0b", "/cb#", "/cb#fragment",
    "/./cb", "/a/../cb", "/%2e/cb", "/a/.%2E/cb", "/a/%2e%2e/cb",
])
def test_redirect_and_logout_reject_invalid_uri_characters_and_dot_segments(field, suffix):
    client = {"clientId": "app"}
    uri = "https://example.test" + suffix
    if field == "logout":
        client["attributes"] = {"post.logout.redirect.uris": uri}
    else:
        client[field] = [uri]
    errors({"realm": "r", "clients": [client]})


@pytest.mark.parametrize("origin", [
    "https://example.test/", "https://example.test?", "https://example.test#",
    "https://example.test?x=y", "https://example.test/%20",
])
def test_origin_rejects_paths_and_empty_query_or_fragment_markers(origin):
    errors({"realm": "r", "clients": [{"clientId": "app", "webOrigins": [origin]}]})


@pytest.mark.parametrize("base", [
    "http://localhost", "http://localhost:9000", "http://127.0.0.1:80",
    "https://[::1]:443", "https://[2001:db8::1]:8443", "https://[::ffff:127.0.0.1]",
    "https://app.example", "https://APP.Example:443", "https://xn--bcher-kva.example",
])
def test_exact_url_spelling_is_preserved_for_supported_authorities(base):
    uri = base + "/a%20b/%E2%82%AC;part:@!$&'()+,=~?return=%2Fhome&v=one/two?three"
    client = validate({"realm": "r", "clients": [{
        "clientId": "app", "redirectUris": [uri], "webOrigins": [base, "+"],
        "attributes": {"post.logout.redirect.uris": uri},
    }]}).value.clients[0]
    assert client.redirect_uris == (uri,)
    assert client.post_logout_redirect_uris == (uri,)
    assert client.web_origins == (base, "+")


def test_warning_paths_distinguish_literal_keys_from_nested_fields():
    result = validate({
        "realm": "r", "extension one": "private-value", "extension two": "private-value",
        "attributes.team": "private-value", "attributes": {"team": "private-value"},
        "名": "private-value", "\\u540d": "private-value", 'a"b': "private-value",
        "users[0].extra": "private-value", "users": [{"username": "alice", "extra": 1}],
        "bidirectional\u202ename": "private-value",
    })
    paths = [warning.path for warning in result.warnings]
    assert paths == sorted([
        '$["extension one"]', '$["extension two"]', '$["attributes.team"]',
        '$.attributes.team', '$["\\u540d"]', '$["\\\\u540d"]', '$["a\\"b"]',
        '$["users[0].extra"]', '$.users[0].extra', '$["bidirectional\\u202ename"]',
    ])
    assert "private-value" not in repr(result.warnings)


def test_attribute_error_paths_preserve_each_distinct_field_and_list_index():
    _, paths = errors({"realm": "r", "users": [{"username": "alice", "attributes": {
        "extension one": 1, "extension two": 1, "名": 1,
        "team": [1], "team[0]": 1, "a.b": 1, 'a"b': 1,
    }}]})
    assert paths == {
        '$.users[0].attributes["extension one"]', '$.users[0].attributes["extension two"]',
        '$.users[0].attributes["\\u540d"]', '$.users[0].attributes.team[0]',
        '$.users[0].attributes["team[0]"]', '$.users[0].attributes["a.b"]',
        '$.users[0].attributes["a\\"b"]',
    }


def test_credential_unknown_field_errors_do_not_collapse_or_expose_values():
    caught, paths = errors({"realm": "r", "users": [{"username": "alice", "credentials": [{
        "type": "password", "value": "private-password", "extra one": "private-value",
        "extra two": "private-value", "nested.field": "private-value",
    }]}]})
    assert paths == {
        '$.users[0].credentials[0]["extra one"]',
        '$.users[0].credentials[0]["extra two"]',
        '$.users[0].credentials[0]["nested.field"]',
    }
    assert "private-value" not in str(caught)
    assert "private-password" not in str(caught)


def test_password_policy_constructor_copies_and_freezes_mapping():
    from mini_keycloak.import_export.schema import PasswordPolicyImport

    clauses = {"length": 8}
    policy = PasswordPolicyImport("length(8)", clauses)
    clauses["length"] = 12
    assert policy.clauses["length"] == 8
    with pytest.raises(TypeError):
        policy.clauses["length"] = 12


def test_password_credential_constructor_freezes_presence_and_hides_secret():
    from mini_keycloak.import_export.schema import PasswordCredentialImport

    presence = {"value"}
    credential = PasswordCredentialImport("private-password", presence)
    presence.add("temporary")
    assert credential.present_fields == frozenset({"value"})
    assert isinstance(credential.present_fields, frozenset)
    assert "private-password" not in repr(credential)


def test_user_constructor_copies_and_freezes_all_collections():
    from mini_keycloak.import_export.schema import PasswordCredentialImport

    seed = validate({"realm": "r", "users": [{"username": "alice"}]}).value.users[0]
    attributes = {"team": ["one"]}
    credential = PasswordCredentialImport("private-password", {"value"})
    credentials = [credential]
    presence = {"username", "attributes", "credentials"}
    # dataclasses.replace invokes the public constructor, including __post_init__.
    user = replace(seed, attributes=attributes, credentials=credentials, present_fields=presence)
    attributes["team"].append("two")
    attributes["other"] = []
    credentials.clear()
    presence.clear()
    assert dict(user.attributes) == {"team": ("one",)}
    assert user.credentials == (credential,)
    assert user.present_fields == frozenset({"username", "attributes", "credentials"})
    assert isinstance(user.present_fields, frozenset)
    with pytest.raises(TypeError):
        user.attributes["team"] = ()
    assert "private-password" not in repr(user)


def test_client_constructor_copies_and_freezes_all_collections_and_hides_secret():
    seed = validate({"realm": "r", "clients": [{"clientId": "app"}]}).value.clients[0]
    attributes = {"pkce.code.challenge.method": "S256"}
    presence = {"clientId"}
    collections = {
        "redirect_uris": ["https://app.example/cb"], "web_origins": ["https://app.example"],
        "default_scopes": ["openid"], "optional_scopes": ["email"],
        "post_logout_redirect_uris": ["https://app.example/out"],
    }
    client = replace(seed, attributes=attributes, present_fields=presence,
                     secret="private-client-secret", **collections)
    attributes.clear()
    presence.clear()
    for values in collections.values():
        values.clear()
    assert dict(client.attributes) == {"pkce.code.challenge.method": "S256"}
    assert client.present_fields == frozenset({"clientId"})
    assert isinstance(client.present_fields, frozenset)
    assert client.redirect_uris == ("https://app.example/cb",)
    assert client.web_origins == ("https://app.example",)
    assert client.default_scopes == ("openid",)
    assert client.optional_scopes == ("email",)
    assert client.post_logout_redirect_uris == ("https://app.example/out",)
    with pytest.raises(TypeError):
        client.attributes["pkce.code.challenge.method"] = "optional"
    assert "private-client-secret" not in repr(client)


def test_realm_constructor_copies_and_freezes_all_collections():
    seed = validate({"realm": "r", "clients": [{"clientId": "app"}],
                     "users": [{"username": "alice"}]}).value
    attributes = {"mini.keycloak.passwordGrantEnabled": "false"}
    clients, users, presence = list(seed.clients), list(seed.users), {"realm"}
    realm = replace(seed, attributes=attributes, clients=clients, users=users, present_fields=presence)
    attributes.clear()
    clients.clear()
    users.clear()
    presence.clear()
    assert dict(realm.attributes) == {"mini.keycloak.passwordGrantEnabled": "false"}
    assert realm.clients == seed.clients
    assert realm.users == seed.users
    assert realm.present_fields == frozenset({"realm"})
    assert isinstance(realm.present_fields, frozenset)
    with pytest.raises(TypeError):
        realm.attributes["mini.keycloak.passwordGrantEnabled"] = "true"


def test_validation_result_constructor_copies_and_freezes_warnings():
    from mini_keycloak.import_export.schema import ImportWarning, ValidationResult

    warning = ImportWarning("$.extra", "Unsupported field is ignored")
    warnings = [warning]
    result = ValidationResult(validate({"realm": "r"}).value, warnings)
    warnings.clear()
    assert result.warnings == (warning,)
