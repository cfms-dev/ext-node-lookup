import time

import pytest

from _path import parse_node_path


@pytest.fixture(autouse=True)
def _load_resolver_after_runtime_setup():
    global _build_path_query, resolve_authorized_node_ids

    from _resolver import _build_path_query, resolve_authorized_node_ids


def _make_user(models, session, *, username="alice", groups=()):
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
    for group_name in groups:
        if session.get(models.UserGroup, group_name) is None:
            session.add(
                models.UserGroup(
                    group_name=group_name,
                    group_display_name=group_name,
                )
            )
        user.groups.append(
            models.UserMembership(
                username=username,
                group_name=group_name,
                start_time=0.0,
                end_time=None,
            )
        )
    session.add(user)
    session.flush()
    return user


def _add_folder(models, session, node_id, name, parent, **kwargs):
    folder = models.Folder(id=node_id, name=name, parent=parent, **kwargs)
    session.add(folder)
    session.flush()
    return folder


def _add_document(models, session, node_id, title, parent, *, active=True):
    stored_file = models.File(
        id=f"file-{node_id}",
        path=f"{node_id}.bin",
        active=active,
        size=1,
    )
    document = models.Document(id=node_id, title=title, folder=parent)
    revision = models.DocumentRevision(
        id=f"revision-{node_id}",
        document=document,
        file=stored_file,
    )
    document.current_revision = revision
    session.add_all([stored_file, document, revision])
    session.flush()
    return document


def _deny_read(models, target, session, *, required_permission="hidden"):
    from include.domains.access.authorization.access_rules import set_access_rules

    set_access_rules(
        target,
        {
            "read": [
                {
                    "match": "all",
                    "match_groups": [
                        {
                            "rights": {
                                "match": "all",
                                "require": [required_permission],
                            }
                        }
                    ],
                }
            ]
        },
        inherit_parent=target.inherit,
    )
    session.flush()


def _grant_read(models, session, user, target, target_type):
    session.add(
        models.ObjectAccessEntry(
            entity_type="user",
            entity_identifier=user.username,
            target_type=target_type,
            target_identifier=target.id,
            access_type="read",
            start_time=0.0,
            end_time=None,
        )
    )
    session.flush()


def _block_read(models, session, user, *, target_type, target_id=None):
    entry = models.UserBlockEntry(
        username=user.username,
        timestamp=time.time(),
        not_before=0.0,
        not_after=-1,
        target_type=target_type,
        target_id=target_id,
    )
    entry.sub_entries.append(models.UserBlockSubEntry(block_type="read"))
    session.add(entry)
    session.flush()


def test_resolves_root_and_visible_directory_chain(database_session) -> None:
    models, session = database_session
    user = _make_user(models, session)
    root = session.get(models.Folder, "/")
    projects = _add_folder(models, session, "projects-id", "projects", root)
    _add_folder(models, session, "repo-id", "cfms_on_websocket", projects)

    assert resolve_authorized_node_ids(session, user, ()) == ("/",)
    assert resolve_authorized_node_ids(
        session, user, parse_node_path("/projects/cfms_on_websocket")
    ) == ("/", "projects-id", "repo-id")


def test_resolves_encoded_names_and_exact_parent_namespaces(database_session) -> None:
    models, session = database_session
    user = _make_user(models, session)
    root = session.get(models.Folder, "/")
    first = _add_folder(models, session, "first", "one/two", root)
    second = _add_folder(models, session, "second", "second", root)
    _add_folder(models, session, "first-leaf", "leaf%name", first)
    _add_folder(models, session, "second-leaf", "leaf%name", second)

    assert resolve_authorized_node_ids(
        session, user, parse_node_path("/one%2Ftwo/leaf%25name")
    ) == ("/", "first", "first-leaf")
    assert resolve_authorized_node_ids(
        session, user, parse_node_path("/second/leaf%25name")
    ) == ("/", "second", "second-leaf")


def test_sql_like_names_are_compared_as_literal_values(database_session) -> None:
    models, session = database_session
    user = _make_user(models, session)
    root = session.get(models.Folder, "/")
    _add_folder(models, session, "literal", "x' OR 1=1 --", root)
    _add_folder(models, session, "unrelated", "unrelated", root)

    assert resolve_authorized_node_ids(session, user, ("x' OR 1=1 --",)) == (
        "/",
        "literal",
    )


def test_terminal_document_requires_an_active_revision(database_session) -> None:
    models, session = database_session
    user = _make_user(models, session)
    root = session.get(models.Folder, "/")
    _add_document(models, session, "active-doc", "active", root)
    _add_document(models, session, "inactive-doc", "inactive", root, active=False)

    assert resolve_authorized_node_ids(session, user, ("active",)) == (
        "/",
        "active-doc",
    )
    assert resolve_authorized_node_ids(session, user, ("inactive",)) is None


def test_rejects_document_as_intermediate_and_deleted_nodes(database_session) -> None:
    models, session = database_session
    user = _make_user(models, session)
    root = session.get(models.Folder, "/")
    _add_document(models, session, "document", "document", root)
    deleted = _add_folder(models, session, "deleted", "deleted", root)
    deleted.status = models.EntityStatus.DELETED
    session.flush()

    assert resolve_authorized_node_ids(session, user, ("document", "child")) is None
    assert resolve_authorized_node_ids(session, user, ("deleted",)) is None
    assert resolve_authorized_node_ids(session, user, ("missing",)) is None


@pytest.mark.parametrize("hidden_level", ["root", "ancestor", "terminal"])
def test_denies_the_entire_chain_when_any_folder_is_hidden(
    database_session, hidden_level
) -> None:
    models, session = database_session
    user = _make_user(models, session)
    root = session.get(models.Folder, "/")
    ancestor = _add_folder(models, session, "ancestor", "ancestor", root)
    terminal = _add_folder(models, session, "terminal", "terminal", ancestor)
    targets = {"root": root, "ancestor": ancestor, "terminal": terminal}
    _deny_read(models, targets[hidden_level], session)

    assert resolve_authorized_node_ids(
        session, user, ("ancestor", "terminal")
    ) is None


def test_terminal_oae_does_not_reveal_a_hidden_ancestor(database_session) -> None:
    models, session = database_session
    user = _make_user(models, session)
    root = session.get(models.Folder, "/")
    ancestor = _add_folder(models, session, "ancestor", "ancestor", root)
    terminal = _add_folder(models, session, "terminal", "terminal", ancestor)
    _deny_read(models, ancestor, session)
    _grant_read(models, session, user, terminal, "directory")

    assert resolve_authorized_node_ids(
        session, user, ("ancestor", "terminal")
    ) is None


def test_terminal_document_oae_overrides_its_own_rule_only(database_session) -> None:
    models, session = database_session
    user = _make_user(models, session)
    root = session.get(models.Folder, "/")
    document = _add_document(models, session, "document", "document", root)
    _deny_read(models, document, session)
    _grant_read(models, session, user, document, "document")

    assert resolve_authorized_node_ids(session, user, ("document",)) == (
        "/",
        "document",
    )


@pytest.mark.parametrize(
    ("target_type", "target_id"),
    [("all", None), ("directory", "folder")],
)
def test_user_read_blocks_fail_closed(database_session, target_type, target_id) -> None:
    models, session = database_session
    user = _make_user(models, session)
    root = session.get(models.Folder, "/")
    _add_folder(models, session, "folder", "folder", root)
    _block_read(
        models,
        session,
        user,
        target_type=target_type,
        target_id=target_id,
    )

    assert resolve_authorized_node_ids(session, user, ("folder",)) is None


def test_group_oae_can_authorize_a_visible_terminal(database_session) -> None:
    models, session = database_session
    user = _make_user(models, session, groups=("readers",))
    root = session.get(models.Folder, "/")
    folder = _add_folder(models, session, "folder", "folder", root)
    _deny_read(models, folder, session)
    session.add(
        models.ObjectAccessEntry(
            entity_type="group",
            entity_identifier="readers",
            target_type="directory",
            target_identifier=folder.id,
            access_type="read",
            start_time=0.0,
            end_time=None,
        )
    )
    session.flush()

    assert resolve_authorized_node_ids(session, user, ("folder",)) == (
        "/",
        "folder",
    )


def test_non_inheriting_child_still_requires_visible_path_ancestors(
    database_session,
) -> None:
    models, session = database_session
    user = _make_user(models, session)
    root = session.get(models.Folder, "/")
    ancestor = _add_folder(models, session, "ancestor", "ancestor", root)
    _add_folder(
        models,
        session,
        "terminal",
        "terminal",
        ancestor,
        inherit=False,
    )
    _deny_read(models, ancestor, session)

    assert resolve_authorized_node_ids(
        session, user, ("ancestor", "terminal")
    ) is None


def test_authorization_queries_have_a_fixed_overhead_over_path_resolution(
    database_session,
) -> None:
    from sqlalchemy import event

    models, session = database_session
    user = _make_user(models, session)
    parent = session.get(models.Folder, "/")
    segments = []
    expected_ids = ["/"]
    for index in range(128):
        name = f"n{index}"
        node_id = f"node-{index}"
        parent = _add_folder(models, session, node_id, name, parent)
        segments.append(name)
        expected_ids.append(node_id)
    session.commit()
    session.expire_all()

    statement_count = 0

    def _count_statement(*_args) -> None:
        nonlocal statement_count
        statement_count += 1

    bind = session.get_bind()
    event.listen(bind, "before_cursor_execute", _count_statement)
    try:
        result = resolve_authorized_node_ids(session, user, tuple(segments))
    finally:
        event.remove(bind, "before_cursor_execute", _count_statement)

    assert result == tuple(expected_ids)
    assert statement_count <= 12, statement_count


@pytest.mark.parametrize("dialect_name", ["sqlite", "postgresql", "mysql"])
def test_recursive_path_query_compiles_for_supported_dialects(dialect_name) -> None:
    from sqlalchemy.dialects import mysql, postgresql, sqlite

    dialects = {
        "sqlite": sqlite.dialect(),
        "postgresql": postgresql.dialect(),
        "mysql": mysql.dialect(),
    }

    sql = str(
        _build_path_query(("projects", "repository")).compile(
            dialect=dialects[dialect_name]
        )
    )

    assert "WITH RECURSIVE" in sql.upper()
    assert "active_parent_id" in sql
    assert "node_lookup_child.name" in sql


def test_recursive_path_query_uses_active_parent_name_index(database_session) -> None:
    from sqlalchemy import text
    from sqlalchemy.dialects import sqlite

    _, session = database_session
    statement = _build_path_query(("projects", "repository")).compile(
        dialect=sqlite.dialect(),
        compile_kwargs={"literal_binds": True},
    )
    plan = session.execute(text(f"EXPLAIN QUERY PLAN {statement}")).all()

    assert any("active_parent_id=? AND name=?" in detail for *_, detail in plan), plan
