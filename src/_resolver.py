"""Database-backed, permission-safe node path resolution."""

import time
from collections.abc import Sequence

from sqlalchemy import case, literal, select
from sqlalchemy.orm import Session as OrmSession

from include.config.constants import ROOT_DIRECTORY_ID
from include.database.models.documents import (
    Document,
    DocumentRevision,
    EntityStatus,
    Folder,
    Node,
    NodeType,
)
from include.database.models.files import File
from include.database.models.identity import User
from include.domains.access.authorization.compiled_rules import (
    TargetType,
    compiled_rules_allow_from_map,
    fetch_compiled_access_rules_for_targets,
)
from include.domains.access.authorization.grants import (
    batch_prefetch_granted_ids,
    prefetch_user_blocks,
)

__all__ = ["resolve_authorized_node_ids"]


def _build_path_query(segments: Sequence[str]):
    nodes = Node.__table__
    path = (
        select(
            nodes.c.id.label("id"),
            nodes.c.type.label("type"),
            literal(0).label("depth"),
        )
        .where(
            nodes.c.id == ROOT_DIRECTORY_ID,
            nodes.c.type == NodeType.DIRECTORY.value,
            nodes.c.status != EntityStatus.DELETED,
        )
        .cte("node_lookup_path", recursive=True)
    )
    child = nodes.alias("node_lookup_child")
    expected_name = case(
        *((path.c.depth == depth, segment) for depth, segment in enumerate(segments)),
        else_=None,
    )
    path = path.union_all(
        select(
            child.c.id,
            child.c.type,
            (path.c.depth + 1).label("depth"),
        )
        .select_from(
            path.join(
                child,
                child.c.parent_id == path.c.id,
            )
        )
        .where(
            path.c.type == NodeType.DIRECTORY.value,
            path.c.depth < len(segments),
            child.c.active_name == expected_name,
        )
    )
    return (
        select(Node, path.c.depth)
        .select_from(path.join(nodes, nodes.c.id == path.c.id))
        .order_by(path.c.depth)
    )


def _resolve_chain(
    session: OrmSession, segments: Sequence[str]
) -> list[Folder | Document] | None:
    if not segments:
        root = session.get(Folder, ROOT_DIRECTORY_ID)
        if root is None or root.status == EntityStatus.DELETED:
            return None
        return [root]

    rows = session.execute(_build_path_query(segments)).all()
    expected_depths = list(range(len(segments) + 1))
    if [depth for _, depth in rows] != expected_depths:
        return None

    chain = [node for node, _ in rows]
    if len({node.id for node in chain}) != len(chain):
        return None
    if not all(isinstance(node, Folder) for node in chain[:-1]):
        return None

    return chain


def _target_type(node: Folder | Document) -> TargetType:
    return "document" if isinstance(node, Document) else "directory"


def _chain_is_readable(
    session: OrmSession,
    user: User,
    chain: Sequence[Folder | Document],
) -> bool:
    now = time.time()
    is_globally_blocked, blocked_ids = prefetch_user_blocks(
        session,
        user,
        "read",
        now,
    )
    if is_globally_blocked:
        return False

    targets = [(_target_type(node), node.id) for node in chain]
    compiled_rules = fetch_compiled_access_rules_for_targets(
        session,
        targets,
        access_type="read",
    )

    granted_ids_by_type: dict[TargetType, set[str]] = {}
    for target_type in ("directory", "document"):
        target_ids = [
            target_id
            for this_type, target_id in targets
            if this_type == target_type
        ]
        if target_ids:
            granted_ids_by_type[target_type] = batch_prefetch_granted_ids(
                session,
                user,
                target_ids,
                target_type,
                "read",
                now,
            )

    for node in chain:
        if node.id in blocked_ids:
            return False
        target_type = _target_type(node)
        if node.id in granted_ids_by_type.get(target_type, set()):
            continue
        if not compiled_rules_allow_from_map(
            compiled_rules,
            target_type=target_type,
            target_id=node.id,
            user=user,
            access_type="read",
        ):
            return False
    return True


def resolve_authorized_node_ids(
    session: OrmSession,
    user: User,
    segments: Sequence[str],
) -> tuple[str, ...] | None:
    """Return the complete readable ID chain, or ``None`` without a prefix."""
    chain = _resolve_chain(session, segments)
    if chain is None:
        return None

    if not _chain_is_readable(session, user, chain):
        return None

    terminal = chain[-1]
    if isinstance(terminal, Document):
        # Check existence without walking or materializing the revision history.
        active_revision = (
            select(DocumentRevision.id)
            .join(File, DocumentRevision.file_id == File.id)
            .where(DocumentRevision.document_id == terminal.id, File.active.is_(True))
            .exists()
        )
        if not session.scalar(select(active_revision)):
            return None

    return tuple(node.id for node in chain)
