import datetime
import time

import pytest

from _path import parse_node_path


@pytest.fixture(autouse=True)
def _load_resolver_after_runtime_setup():
    global _build_path_query, resolve_authorized_node_ids

    from _resolver import _build_path_query, resolve_authorized_node_ids


def _make_user(
    models,
    session,
    *,
    username="alice",
    groups=(),
    permissions=(),
):
    now = time.time()
    user = models.User(
        username=username,
        nickname=username,
        avatar_id=None,
        last_login=None,
        created_time=now,
        status=0,
        secret_key=f"{username}-secret",
        preference_dek_id=None,
    )
    for permission in permissions:
        user.rights.append(
            models.UserPermission(
                user=user,
                permission=permission,
                granted=True,
                start_time=0.0,
                end_time=None,
            )
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
                group_name=group_name,
                start_time=0.0,
                end_time=None,
            )
        )
    session.add(user)
    session.flush()
    return user


def _grant_permission(models, session, user, permission: str) -> None:
    user.rights.append(
        models.UserPermission(
            user=user,
            permission=permission,
            granted=True,
            start_time=0.0,
            end_time=None,
        )
    )
    user.__dict__.pop("all_permissions", None)
    session.flush()


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


def _set_dacl(session, target, source: str, *, now_utc=None) -> None:
    from include.domains.access.authorization.storage import (
        compile_policy_source,
        persist_node_policy,
    )

    compiled = compile_policy_source(session, source, now_utc=now_utc)
    assert not compiled.errors, compiled.diagnostics
    assert compiled.policy is not None
    persist_node_policy(session, target, compiled.policy)
    session.flush()


def _set_bypass_traverse_option(session, enabled: bool) -> None:
    from include.config.options import (
        BYPASS_TRAVERSE_CHECKING_OPTION,
        read_option,
        write_options,
    )

    current = read_option(session, "access", BYPASS_TRAVERSE_CHECKING_OPTION)
    write_options(
        session,
        "access",
        {"bypass_traverse_checking": enabled},
        expected_revisions={"bypass_traverse_checking": current.revision},
    )
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


@pytest.mark.parametrize("active", [False, True], ids=["unpublished", "published"])
@pytest.mark.parametrize("linked", [False, True], ids=["fallback", "parent-chain"])
def test_document_revision_history_has_a_fixed_query_budget(
    database_session, active, linked
) -> None:
    from sqlalchemy import event

    models, session = database_session
    user = _make_user(models, session)
    root = session.get(models.Folder, "/")
    document = _add_document(
        models, session, "document", "document", root, active=active
    )
    parent = document.current_revision
    for index in range(128):
        stored_file = models.File(
            id=f"history-file-{index}",
            path=f"{index}.bin",
            active=active and not linked and index < 127,
        )
        revision = models.DocumentRevision(
            id=f"history-revision-{index}",
            document=document,
            file=stored_file,
            parent_revision=parent if linked else None,
        )
        session.add_all([stored_file, revision])
        parent = revision
    document.current_revision = parent
    session.commit()
    session.expire_all()

    statement_count = 0

    def _count_statement(*_args) -> None:
        nonlocal statement_count
        statement_count += 1

    bind = session.get_bind()
    event.listen(bind, "before_cursor_execute", _count_statement)
    try:
        result = resolve_authorized_node_ids(session, user, ("document",))
    finally:
        event.remove(bind, "before_cursor_execute", _count_statement)

    assert result == (("/", "document") if active else None)
    assert statement_count <= 12, statement_count


def test_hidden_document_does_not_load_revision_history(database_session) -> None:
    from sqlalchemy import event

    models, session = database_session
    user = _make_user(models, session)
    root = session.get(models.Folder, "/")
    document = _add_document(models, session, "document", "document", root)
    _set_dacl(session, document, "inherit off;")
    session.commit()
    session.expire_all()
    statements = []

    def _capture_statement(_connection, _cursor, statement, *_args) -> None:
        statements.append(statement.lower())

    bind = session.get_bind()
    event.listen(bind, "before_cursor_execute", _capture_statement)
    try:
        result = resolve_authorized_node_ids(session, user, ("document",))
    finally:
        event.remove(bind, "before_cursor_execute", _capture_statement)

    assert result is None
    assert not any("from document_revisions" in sql for sql in statements), statements


def test_document_without_revisions_is_not_found(database_session) -> None:
    models, session = database_session
    user = _make_user(models, session)
    root = session.get(models.Folder, "/")
    session.add(models.Document(id="document", title="document", folder=root))
    session.flush()

    assert resolve_authorized_node_ids(session, user, ("document",)) is None


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


def test_deleted_names_do_not_shadow_live_nodes_or_allow_traversal(
    database_session,
) -> None:
    models, session = database_session
    user = _make_user(models, session)
    root = session.get(models.Folder, "/")
    deleted = _add_folder(models, session, "deleted", "shared", root)
    deleted.status = models.EntityStatus.DELETED
    session.flush()
    _add_folder(models, session, "hidden-child", "child", deleted)
    _add_folder(models, session, "live", "shared", root)

    assert resolve_authorized_node_ids(session, user, ("shared",)) == ("/", "live")
    assert resolve_authorized_node_ids(session, user, ("shared", "child")) is None


def test_direct_uuid_grant_survives_user_rename(database_session) -> None:
    models, session = database_session
    user = _make_user(models, session)
    root = session.get(models.Folder, "/")
    folder = _add_folder(models, session, "folder", "folder", root)
    _set_dacl(
        session,
        folder,
        f'inherit off; allow [PRESET_READ] to user("{user.id}");',
    )
    session.commit()
    original_id = user.id

    user.username = "renamed-alice"
    session.commit()
    session.expire_all()

    assert user.id == original_id
    assert resolve_authorized_node_ids(session, user, ("folder",)) == ("/", "folder")


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
    _set_dacl(session, targets[hidden_level], "inherit off;")

    assert resolve_authorized_node_ids(
        session, user, ("ancestor", "terminal")
    ) is None


def test_terminal_allow_does_not_reveal_a_hidden_ancestor(database_session) -> None:
    models, session = database_session
    user = _make_user(models, session)
    root = session.get(models.Folder, "/")
    ancestor = _add_folder(models, session, "ancestor", "ancestor", root)
    terminal = _add_folder(models, session, "terminal", "terminal", ancestor)
    _set_dacl(session, ancestor, "inherit off;")
    _set_dacl(
        session,
        terminal,
        f'inherit off; allow [PRESET_READ] to user("{user.id}");',
    )

    assert resolve_authorized_node_ids(
        session, user, ("ancestor", "terminal")
    ) is None


def test_terminal_document_dacl_overrides_its_own_inherit_off(database_session) -> None:
    models, session = database_session
    user = _make_user(models, session)
    root = session.get(models.Folder, "/")
    document = _add_document(models, session, "document", "document", root)
    _set_dacl(
        session,
        document,
        f'inherit off; allow [READ_METADATA] to user("{user.id}");',
    )

    assert resolve_authorized_node_ids(session, user, ("document",)) == (
        "/",
        "document",
    )


def test_explicit_deny_overrides_inherited_allow(database_session) -> None:
    models, session = database_session
    user = _make_user(models, session)
    root = session.get(models.Folder, "/")
    folder = _add_folder(models, session, "folder", "folder", root)
    child = _add_folder(models, session, "child", "child", folder)

    _set_dacl(
        session,
        folder,
        f'deny [LIST_DIRECTORY, READ_METADATA] on self to user("{user.id}");',
    )
    assert resolve_authorized_node_ids(session, user, ("folder",)) is None
    # Inherited TRAVERSE from `/` still permits reaching visible child.
    assert resolve_authorized_node_ids(session, user, ("folder", "child")) == (
        "/",
        "folder",
        "child",
    )

    _set_dacl(session, folder, f'deny [TRAVERSE] to user("{user.id}");')
    assert resolve_authorized_node_ids(session, user, ("folder", "child")) is None


def test_group_dacl_can_authorize_a_visible_terminal(database_session) -> None:
    models, session = database_session
    user = _make_user(models, session, groups=("readers",))
    root = session.get(models.Folder, "/")
    folder = _add_folder(models, session, "folder", "folder", root)
    _set_dacl(
        session,
        folder,
        'inherit off; allow [LIST_DIRECTORY] to group("readers");',
    )

    assert resolve_authorized_node_ids(session, user, ("folder",)) == (
        "/",
        "folder",
    )


def test_group_dacl_does_not_match_a_user_uuid(database_session) -> None:
    models, session = database_session
    user = _make_user(models, session, username="shared-name")
    session.add(
        models.UserGroup(
            group_name=str(user.id),
            group_display_name="same identifier as the user",
        )
    )
    root = session.get(models.Folder, "/")
    folder = _add_folder(models, session, "folder", "folder", root)
    _set_dacl(
        session,
        folder,
        f'inherit off; allow [PRESET_READ] to group("{user.id}");',
    )

    assert resolve_authorized_node_ids(session, user, ("folder",)) is None


def test_user_dacl_does_not_match_a_group_with_the_same_identifier(
    database_session,
) -> None:
    models, session = database_session
    other_user = _make_user(models, session, username="shared-name")
    user = _make_user(models, session, username="alice", groups=(str(other_user.id),))
    root = session.get(models.Folder, "/")
    folder = _add_folder(models, session, "folder", "folder", root)
    _set_dacl(
        session,
        folder,
        f'inherit off; allow [PRESET_READ] to user("{other_user.id}");',
    )

    assert resolve_authorized_node_ids(session, user, ("folder",)) is None


def test_perm_dacl_keeps_principal_namespaces_separate(database_session) -> None:
    from include.domains.access.permissions import Permissions

    models, session = database_session
    user = _make_user(models, session, groups=(Permissions.SEARCH.value,))
    root = session.get(models.Folder, "/")
    folder = _add_folder(models, session, "folder", "folder", root)
    _set_dacl(
        session,
        folder,
        f'inherit off; allow [PRESET_READ] when perm("{Permissions.SEARCH.value}");',
    )

    # Holding a group named "search" must not satisfy perm("search").
    assert resolve_authorized_node_ids(session, user, ("folder",)) is None

    _grant_permission(models, session, user, Permissions.SEARCH)
    assert resolve_authorized_node_ids(session, user, ("folder",)) == (
        "/",
        "folder",
    )


@pytest.mark.parametrize(
    ("membership_start", "membership_end"),
    [(time.time() + 3600, None), (0.0, time.time() - 3600)],
    ids=["future", "expired"],
)
def test_group_dacl_requires_an_active_membership(
    database_session, membership_start, membership_end
) -> None:
    models, session = database_session
    user = _make_user(models, session, username="alice")
    session.add(
        models.UserGroup(
            group_name="readers",
            group_display_name="readers",
        )
    )
    membership = models.UserMembership(
        user_id=user.id,
        group_name="readers",
        start_time=membership_start,
        end_time=None,
    )
    user.groups.append(membership)
    membership.end_time = membership_end
    root = session.get(models.Folder, "/")
    folder = _add_folder(models, session, "folder", "folder", root)
    _set_dacl(
        session,
        folder,
        'inherit off; allow [PRESET_READ] to group("readers");',
    )

    assert resolve_authorized_node_ids(session, user, ("folder",)) is None


def test_cacl_rule_validity_windows_are_enforced(database_session) -> None:
    models, session = database_session
    user = _make_user(models, session)
    root = session.get(models.Folder, "/")
    now = datetime.datetime.now(datetime.UTC)

    future_start = (now + datetime.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    past_start = (now - datetime.timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
    past_end = (now - datetime.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    active_end = (now + datetime.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")

    future_folder = _add_folder(models, session, "future", "future", root)
    _set_dacl(
        session,
        future_folder,
        f'inherit off; allow [PRESET_READ] to any from "{future_start}";',
        now_utc=now,
    )
    expired_folder = _add_folder(models, session, "expired", "expired", root)
    _set_dacl(
        session,
        expired_folder,
        f'inherit off; allow [PRESET_READ] to any from "{past_start}" until "{past_end}";',
        now_utc=now - datetime.timedelta(hours=3),
    )
    active_folder = _add_folder(models, session, "active", "active", root)
    _set_dacl(
        session,
        active_folder,
        f'inherit off; allow [PRESET_READ] to any from "{past_start}" until "{active_end}";',
        now_utc=now,
    )

    assert resolve_authorized_node_ids(session, user, ("future",)) is None
    assert resolve_authorized_node_ids(session, user, ("expired",)) is None
    assert resolve_authorized_node_ids(session, user, ("active",)) == (
        "/",
        "active",
    )


def test_cacl_scopes_filter_directories_vs_documents(database_session) -> None:
    models, session = database_session
    user = _make_user(models, session)
    root = session.get(models.Folder, "/")
    scoped = _add_folder(models, session, "scoped", "scoped", root)
    _set_dacl(
        session,
        scoped,
        (
            "inherit off;\n"
            "allow [TRAVERSE] on self to any;\n"
            "allow [READ_CONTENT] on docs to any;\n"
        ),
    )
    _add_folder(models, session, "sub", "sub", scoped)
    _add_document(models, session, "doc", "doc", scoped)

    assert resolve_authorized_node_ids(session, user, ("scoped",)) is None
    assert resolve_authorized_node_ids(session, user, ("scoped", "sub")) is None
    assert resolve_authorized_node_ids(session, user, ("scoped", "doc")) == (
        "/",
        "scoped",
        "doc",
    )


def test_traverse_only_ancestor_allows_visible_child_but_not_ancestor(
    database_session,
) -> None:
    models, session = database_session
    user = _make_user(models, session)
    root = session.get(models.Folder, "/")
    ancestor = _add_folder(models, session, "ancestor", "ancestor", root)
    _set_dacl(session, ancestor, "inherit off; allow [TRAVERSE] to any;")
    child = _add_folder(models, session, "child", "child", ancestor)
    _set_dacl(session, child, "inherit off; allow [LIST_DIRECTORY] to any;")

    assert resolve_authorized_node_ids(session, user, ("ancestor",)) is None
    assert resolve_authorized_node_ids(session, user, ("ancestor", "child")) == (
        "/",
        "ancestor",
        "child",
    )


def test_list_directory_without_traverse_blocks_descendants(database_session) -> None:
    models, session = database_session
    user = _make_user(models, session)
    root = session.get(models.Folder, "/")
    ancestor = _add_folder(models, session, "ancestor", "ancestor", root)
    _set_dacl(session, ancestor, "inherit off; allow [LIST_DIRECTORY] to any;")
    child = _add_folder(models, session, "child", "child", ancestor)
    _set_dacl(session, child, "inherit off; allow [LIST_DIRECTORY] to any;")

    assert resolve_authorized_node_ids(session, user, ("ancestor",)) == (
        "/",
        "ancestor",
    )
    assert resolve_authorized_node_ids(session, user, ("ancestor", "child")) is None


def test_bypass_traverse_checking_permission_and_option(database_session) -> None:
    from include.domains.access.permissions import Permissions

    models, session = database_session
    user = _make_user(models, session)
    root = session.get(models.Folder, "/")
    ancestor = _add_folder(models, session, "ancestor", "ancestor", root)
    _set_dacl(session, ancestor, "inherit off;")
    terminal = _add_folder(models, session, "terminal", "terminal", ancestor)
    _set_dacl(session, terminal, "inherit off; allow [READ_METADATA] to any;")

    assert resolve_authorized_node_ids(session, user, ("ancestor", "terminal")) is None

    # Database option enables traverse bypass globally while keeping ancestor invisible.
    _set_bypass_traverse_option(session, True)
    assert resolve_authorized_node_ids(session, user, ("ancestor",)) is None
    assert resolve_authorized_node_ids(session, user, ("ancestor", "terminal")) == (
        "/",
        "ancestor",
        "terminal",
    )

    _set_bypass_traverse_option(session, False)
    assert resolve_authorized_node_ids(session, user, ("ancestor", "terminal")) is None

    # Per-user BYPASS_TRAVERSE_CHECKING permission grants the same bypass.
    _grant_permission(models, session, user, Permissions.BYPASS_TRAVERSE_CHECKING)
    assert resolve_authorized_node_ids(session, user, ("ancestor",)) is None
    assert resolve_authorized_node_ids(session, user, ("ancestor", "terminal")) == (
        "/",
        "ancestor",
        "terminal",
    )


def test_bypass_dacl_resolves_hidden_live_nodes_but_rejects_deleted_and_unpublished(
    database_session,
) -> None:
    from include.domains.access.permissions import Permissions

    models, session = database_session
    admin = _make_user(
        models,
        session,
        username="admin",
        permissions=(Permissions.BYPASS_DACL,),
    )
    root = session.get(models.Folder, "/")
    _set_dacl(session, root, "inherit off;")
    hidden = _add_folder(models, session, "hidden", "hidden", root)
    _set_dacl(session, hidden, "inherit off; deny [TRAVERSE, LIST_DIRECTORY] to any;")
    _add_document(models, session, "doc", "doc", hidden, active=True)
    _add_document(models, session, "draft", "draft", hidden, active=False)
    deleted = _add_folder(models, session, "deleted", "deleted", hidden)
    deleted.status = models.EntityStatus.DELETED
    session.flush()

    assert resolve_authorized_node_ids(session, admin, ("hidden", "doc")) == (
        "/",
        "hidden",
        "doc",
    )
    assert resolve_authorized_node_ids(session, admin, ("hidden", "draft")) is None
    assert resolve_authorized_node_ids(session, admin, ("hidden", "deleted")) is None


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
    assert "node_lookup_child.parent_id" in sql
    assert "node_lookup_child.active_name" in sql


def test_recursive_path_query_uses_active_parent_name_index(database_session) -> None:
    from sqlalchemy import text
    from sqlalchemy.dialects import sqlite

    _, session = database_session
    statement = _build_path_query(("projects", "repository")).compile(
        dialect=sqlite.dialect(),
        compile_kwargs={"literal_binds": True},
    )
    plan = session.execute(text(f"EXPLAIN QUERY PLAN {statement}")).all()

    assert any("parent_id=? AND active_name=?" in detail for *_, detail in plan), plan
