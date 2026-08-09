import importlib.util
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import jsonschema
import pytest


@pytest.fixture(scope="session")
def extension_module(isolated_server_runtime):
    extension_root = Path(__file__).resolve().parents[1]
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
        username=username,
        pass_hash="hash",
        passwd_last_modified=now,
        nickname=username,
        avatar_id=None,
        last_login=None,
        created_time=now,
        status=0,
        secret_key=f"{username}-secret",
        totp_secret=None,
        totp_enabled=False,
        totp_backup_codes=None,
        preference_dek_id=None,
    )
    session.add(user)
    session.flush()
    return user


def _handler(path: str):
    responses = []
    handler = SimpleNamespace(
        data={"path": path},
        username="alice",
        conclude_request=lambda code, data, message: responses.append(
            {"code": code, "data": data, "message": message}
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
    handlers = extension_module.ext_register_handlers()
    handler_type = handlers["node_lookup"]

    assert extension_module.ext_register_extension_flags() == {"node_lookup"}
    assert handler_type.require_auth is True
    assert handler_type.rate_limit_cost == 3
    jsonschema.validate({"path": "/projects"}, handler_type.schema)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(
            {"path": "/projects", "unexpected": True}, handler_type.schema
        )
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate({"path": "/" + "a" * 4096}, handler_type.schema)


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
    result = extension_module.RequestNodeLookupHandler().handle(handler)

    assert responses == [
        {
            "code": 200,
            "data": {"node_ids": ["/", "projects-id", "repository-id"]},
            "message": "Node path resolved successfully",
        }
    ]
    assert result.code == 200
    assert result.target == "repository-id"
    assert result.data is None
    assert result.username == "alice"


def test_root_path_returns_only_the_root_id(
    monkeypatch, extension_module, database_session
) -> None:
    models, session = database_session
    _make_user(models, session)
    session.commit()
    _install_testing_session(monkeypatch, extension_module, session)

    handler, responses = _handler("/")
    result = extension_module.RequestNodeLookupHandler().handle(handler)

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
    hidden_result = extension_module.RequestNodeLookupHandler().handle(hidden_handler)
    missing_handler, missing_responses = _handler("/missing")
    missing_result = extension_module.RequestNodeLookupHandler().handle(missing_handler)

    expected = [{"code": 404, "data": {}, "message": "Node path not found"}]
    assert hidden_responses == expected
    assert missing_responses == expected
    assert hidden_result.code == missing_result.code == 404
    assert hidden_result.target is None
    assert missing_result.target is None
    assert hidden_result.data is None
    assert missing_result.data is None


def test_invalid_path_is_rejected_without_database_lookup(
    monkeypatch, extension_module
) -> None:
    def _unexpected_session():
        raise AssertionError("invalid paths must not access the database")

    monkeypatch.setattr(extension_module, "Session", _unexpected_session)
    handler, responses = _handler("relative/path")

    result = extension_module.RequestNodeLookupHandler().handle(handler)

    assert responses == [{"code": 400, "data": {}, "message": "Invalid node path"}]
    assert result.code == 400
    assert result.target is None
