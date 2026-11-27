"""Database-backed, permission-safe node path resolution."""

import datetime
from collections.abc import Sequence

from cacl_compiler import CompiledPolicy

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
from include.domains.access.authorization.engine import (
    NamespaceNode,
    evaluate_effective_masks,
    is_effective_mask_visible,
)
from include.domains.access.authorization.evaluation import (
    has_bypass_dacl,
    node_to_object_state,
    node_to_object_type,
    should_check_ancestor_traverse,
    user_to_subject,
)
from include.domains.access.authorization.storage import load_node_policies

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


def _chain_is_authorized(
    session: OrmSession,
    user: User,
    chain: Sequence[Folder | Document],
) -> bool:
    if has_bypass_dacl(user):
        return True

    now = datetime.datetime.now(datetime.UTC)
    preloaded_inherit = {node.id: bool(node.inherit) for node in chain}
    policies = load_node_policies(
        session,
        [node.id for node in chain],
        preloaded_inherit=preloaded_inherit,
        active_at_utc=now,
        canonicalize=False,
    )
    path = [
        NamespaceNode(
            node_id=node.id,
            name=node.name,
            object_type=node_to_object_type(node),
            state=node_to_object_state(node),
            policy=policies.get(
                node.id, CompiledPolicy(inherit=bool(node.inherit), rules=())
            ),
        )
        for node in chain
    ]
    masks = evaluate_effective_masks(
        user_to_subject(user),
        path,
        eval_time_utc=now,
        check_ancestor_traverse=should_check_ancestor_traverse(session, user),
    )
    return masks.allowed_traverse and is_effective_mask_visible(
        path[-1].object_type, masks.effective_mask
    )


def resolve_authorized_node_ids(
    session: OrmSession,
    user: User,
    segments: Sequence[str],
) -> tuple[str, ...] | None:
    """Return the complete readable ID chain, or ``None`` without a prefix."""
    chain = _resolve_chain(session, segments)
    if chain is None:
        return None

    if not _chain_is_authorized(session, user, chain):
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
