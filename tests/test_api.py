import importlib.util
import sys
import time
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

USER_ID = uuid.UUID("aabbccdd-0000-4000-8000-000000000001")


@pytest.fixture(scope="session")
def extension_module(isolated_server_runtime):
    extension_root = Path(__file__).resolve().parents[1] / "src"
    spec = importlib.util.spec_from_file_location(
        "node_lookup",
        extension_root / "_extension.py",
        submodule_search_locations=[str(extension_root)],
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["node_lookup"] = module
    spec.loader.exec_module(module)
    try:
        yield module
    finally:
        for module_name in tuple(sys.modules):
            if module_name == "node_lookup" or module_name.startswith("node_lookup."):
                sys.modules.pop(module_name, None)


def _make_user(models, session, username="alice"):
    now = time.time()
    user = models.User(
        id=USER_ID,
        username=username,
        nickname=username,
        avatar_id=None,
        last_login=None,
        created_time=now,
        status=0,
        secret_key="s" * 64,
        preference_dek_id=None,
    )
    session.add(user)
    session.flush()
    return user


def _handler(path: str):
    responses = []
    handler = SimpleNamespace(
        data={"path": path},
        user_id=USER_ID,
        conclude_request=lambda code, data, message: responses.append(
            {"code": code, "data": data}
        ),
    )
    return handler, responses


def _install_testing_session(monkeypatch, extension_module, session) -> None:
    from sqlalchemy.orm import sessionmaker

    monkeypatch.setattr(
        extension_module,
        "Session",
        sessionmaker(bind=session.get_bind()),
    )


def test_registers_action_capability_and_transport_contract(extension_module) -> None:
    from include.transport.request_handler import validate_request_handler_models

    handlers = extension_module.ext_register_handlers()
    assert set(handlers) == {"node_lookup.node.resolve"}
    handler_type = handlers["node_lookup.node.resolve"]

    assert extension_module.ext_register_extension_flags() == {"node_lookup"}
    assert handler_type.requires_auth is True
    assert handler_type.rate_limit_cost == 3
    validate_request_handler_models(handlers)
    assert handler_type.request_model.model_validate({"path": "/projects"}).path == (
        "/projects"
    )
    with pytest.raises(ValidationError):
        handler_type.request_model.model_validate(
            {"path": "/projects", "unexpected": True}
        )
    with pytest.raises(ValidationError):
        handler_type.request_model.model_validate({"path": "/" + "a" * 4096})
    with pytest.raises(ValidationError):
        handler_type.request_model.model_validate({"path": 1})


def test_success_returns_rooted_chain_and_audits_only_terminal_id(
    monkeypatch, extension_module, database_session
) -> None:
    models, session = database_session
    _make_user(models, session)
    root = session.get(models.Folder, "/")
    projects = models.Folder(id="projects-id", name="projects", parent=root)
    repository = models.Folder(
        id="repository-id",
        name="cfms_on_websocket",
        parent=projects,
    )
    session.add_all([projects, repository])
    session.commit()
    _install_testing_session(monkeypatch, extension_module, session)

    handler, responses = _handler("/projects/cfms_on_websocket")
    lookup = extension_module.RequestNodeLookupHandler()
    request = lookup.request_model.model_validate(handler.data)
    handler.data["path"] = "/different-raw-path"
    result = lookup.handle(handler, request)

    assert responses == [
        {
            "code": 200,
            "data": {"node_ids": ["/", "projects-id", "repository-id"]},
        }
    ]
    assert result.code == 200
    assert result.target == "repository-id"
    assert result.data is None
    assert result.user_id == USER_ID


def test_root_path_returns_only_the_root_id(
    monkeypatch, extension_module, database_session
) -> None:
    models, session = database_session
    _make_user(models, session)
    session.commit()
    _install_testing_session(monkeypatch, extension_module, session)

    handler, responses = _handler("/")
    lookup = extension_module.RequestNodeLookupHandler()
    result = lookup.handle(handler, lookup.request_model.model_validate(handler.data))

    assert responses[0]["data"] == {"node_ids": ["/"]}
    assert result.target == "/"


def test_hidden_and_missing_paths_have_identical_empty_responses(
    monkeypatch, extension_module, database_session
) -> None:
    from include.domains.access.authorization.access_rules import set_access_rules

    models, session = database_session
    _make_user(models, session)
    root = session.get(models.Folder, "/")
    hidden = models.Folder(id="hidden-id", name="hidden", parent=root)
    session.add(hidden)
    session.flush()
    set_access_rules(
        hidden,
        {
            "read": [
                {
                    "match": "all",
                    "match_groups": [
                        {
                            "rights": {
                                "match": "all",
                                "require": ["secret"],
                            }
                        }
                    ],
                }
            ]
        },
    )
    session.commit()
    _install_testing_session(monkeypatch, extension_module, session)

    hidden_handler, hidden_responses = _handler("/hidden")
    lookup = extension_module.RequestNodeLookupHandler()
    hidden_result = lookup.handle(
        hidden_handler, lookup.request_model.model_validate(hidden_handler.data)
    )
    missing_handler, missing_responses = _handler("/missing")
    missing_result = lookup.handle(
        missing_handler, lookup.request_model.model_validate(missing_handler.data)
    )

    expected = [{"code": 404, "data": {}}]
    assert hidden_responses == expected
    assert missing_responses == expected
    assert hidden_result.code == missing_result.code == 404
    assert hidden_result.target is None
    assert missing_result.target is None
    assert hidden_result.data is None
    assert missing_result.data is None
    assert hidden_result.user_id == missing_result.user_id == USER_ID


def test_invalid_path_is_rejected_without_database_lookup(
    monkeypatch, extension_module
) -> None:
    def _unexpected_session():
        raise AssertionError("invalid paths must not access the database")

    monkeypatch.setattr(extension_module, "Session", _unexpected_session)
    handler, responses = _handler("relative/path")

    lookup = extension_module.RequestNodeLookupHandler()
    result = lookup.handle(handler, lookup.request_model.model_validate(handler.data))

    assert responses == [{"code": 400, "data": {}}]
    assert result.code == 400
    assert result.target is None
    assert result.user_id == USER_ID


@pytest.fixture()
def routed_lookup(monkeypatch, extension_module, database_session):
    import orjson
    from sqlalchemy.orm import sessionmaker

    from include.domains.identity.tokens import Token, TokenPurpose
    from include.transport import router
    from include.transport.multiplexing import FrameType

    models, session = database_session
    user = _make_user(models, session)
    session.commit()
    _install_testing_session(monkeypatch, extension_module, session)
    monkeypatch.setattr(router, "Session", sessionmaker(bind=session.get_bind()))
    monkeypatch.setattr(
        router, "available_functions", extension_module.ext_register_handlers()
    )
    monkeypatch.setattr(
        router.LoginGuard,
        "evaluate_subnet_access",
        lambda _ip: SimpleNamespace(allowed=True),
    )
    rate_calls = []

    def allow_rate(action, cost, _ip, **kwargs):
        rate_calls.append((action, cost, kwargs))
        return SimpleNamespace(allowed=True)

    monkeypatch.setattr(router, "check_request_rate", allow_rate)
    monkeypatch.setattr(
        router.lockdown_state_manager,
        "get_state",
        lambda: SimpleNamespace(enabled=False),
    )
    monkeypatch.setattr(
        router.nonce_store, "validate_and_store", lambda _nonce, _timestamp: None
    )
    dispatched = []

    def before_request(*, request_handler, connection_handler):
        dispatched.append(connection_handler.user_id)

    monkeypatch.setattr(
        router,
        "pm",
        SimpleNamespace(
            hook=SimpleNamespace(
                ext_before_request=before_request,
                ext_post_request=lambda **_kwargs: None,
            )
        ),
    )
    audits = []
    monkeypatch.setattr(
        router,
        "log_audit",
        lambda action, code, **kwargs: audits.append(
            {"action": action, "code": code, **kwargs}
        ),
    )

    def send(data, *, token="GENERAL", action="node_lookup.node.resolve", **envelope):
        request = {
            "action": action,
            "data": data,
            "nonce": uuid.uuid4().hex,
            "timestamp": time.time(),
            **envelope,
        }
        if token == "invalid":
            request["token"] = "invalid-token"
        elif token is not None:
            request["token"] = Token.new(
                user.id, 60, user.secret_key, purpose=TokenPurpose[token]
            ).raw
        frames = []
        websocket = SimpleNamespace(
            remote_address=("192.0.2.10", 12345),
            request=SimpleNamespace(headers={}),
        )
        stream = SimpleNamespace(
            connection=SimpleNamespace(_ws=websocket),
            recv=lambda: SimpleNamespace(data=orjson.dumps(request)),
            send=lambda data, frame_type: frames.append((data, frame_type)),
        )
        router.handle_request(stream)
        assert len(frames) == 1
        payload, frame_type = frames[0]
        assert frame_type is FrameType.CONCLUSION
        return orjson.loads(payload)

    return SimpleNamespace(
        send=send,
        user=user,
        session=session,
        audits=audits,
        dispatched=dispatched,
        rate_calls=rate_calls,
    )


def test_router_dispatches_with_token_uuid_after_user_rename(routed_lookup) -> None:
    routed_lookup.user.username = "renamed-alice"
    routed_lookup.session.commit()

    response = routed_lookup.send({"path": "/"}, username="unrelated-account")

    assert response["code"] == 200, response
    assert response["data"] == {"node_ids": ["/"]}
    assert routed_lookup.dispatched == [USER_ID]
    assert len(routed_lookup.audits) == 1
    audit = routed_lookup.audits[0]
    assert audit["action"] == "node_lookup.node.resolve"
    assert audit["user_id"] == USER_ID
    assert audit["target"] == "/"
    assert audit["data"] is None
    action, cost, context = routed_lookup.rate_calls[0]
    assert action == "node_lookup.node.resolve"
    assert cost == 3
    assert context["user_id"] == USER_ID


@pytest.mark.parametrize(
    ("token", "expected_code"),
    [(None, 401), ("invalid", 401), ("ESCALATION", 403)],
)
def test_router_enforces_authentication_and_token_purpose(
    routed_lookup, token, expected_code
) -> None:
    response = routed_lookup.send({"path": "/"}, token=token)

    assert response["code"] == expected_code, response
    assert response["data"] == {}
    assert routed_lookup.dispatched == []
    if token == "ESCALATION":
        assert routed_lookup.audits[0]["user_id"] == USER_ID


@pytest.mark.parametrize(
    ("data", "error_type", "location"),
    [
        ({}, "missing", ["path"]),
        ({"path": None}, "string_type", ["path"]),
        ({"path": 1}, "string_type", ["path"]),
        ({"path": ""}, "string_too_short", ["path"]),
        ({"path": "/" + "a" * 4096}, "string_too_long", ["path"]),
        ({"path": "/", "extra": True}, "extra_forbidden", ["extra"]),
    ],
)
def test_router_rejects_invalid_data_before_dispatch(
    routed_lookup, data, error_type, location
) -> None:
    response = routed_lookup.send(data)

    assert response["code"] == 400, response
    assert [
        (error["type"], error["loc"]) for error in response["data"]["errors"]
    ] == [(error_type, location)]
    assert all("input" not in error for error in response["data"]["errors"])
    assert routed_lookup.dispatched == []


def test_router_does_not_register_legacy_action(routed_lookup) -> None:
    response = routed_lookup.send({"path": "/"}, action="node_lookup")

    assert response["code"] == 400, response
    assert response["data"] == {}
    assert routed_lookup.dispatched == []
