"""Database-backed, permission-safe node path resolution."""

import time
from collections.abc import Sequence

from sqlalchemy.orm import Session as OrmSession

from include.config.constants import ROOT_DIRECTORY_ID
from include.database.models.documents import Document, EntityStatus, Folder, Node
from include.database.models.identity import User
from include.domains.access.authorization.compiled_rules import (
    compiled_rules_allow_from_map,
    fetch_compiled_access_rules_for_targets,
)
from include.domains.access.authorization.evaluation import (
    load_folder_access_evaluation_context,
)
from include.domains.access.authorization.grants import batch_prefetch_granted_ids

__all__ = ["resolve_authorized_node_ids"]


def _resolve_chain(
    session: OrmSession, segments: Sequence[str]
) -> list[Folder | Document] | None:
    root = session.get(Folder, ROOT_DIRECTORY_ID)
    if root is None or root.status == EntityStatus.DELETED:
        return None

    chain: list[Folder | Document] = [root]
    visited_ids = {root.id}
    parent: Folder = root
    for index, segment in enumerate(segments):
        node = (
            session.query(Node)
            .filter(
                Node.parent_id == parent.id,
                Node.name == segment,
                Node.status != EntityStatus.DELETED,
            )
            .one_or_none()
        )
        if node is None:
            return None
        if node.id in visited_ids:
            return None
        visited_ids.add(node.id)

        is_terminal = index == len(segments) - 1
        if not is_terminal and not isinstance(node, Folder):
            return None
        if is_terminal and isinstance(node, Document) and not node.active:
            return None

        chain.append(node)
        if isinstance(node, Folder):
            parent = node

    return chain


def _document_is_readable(
    session: OrmSession,
    user: User,
    document: Document,
    *,
    is_globally_blocked: bool,
    blocked_ids: set[str],
) -> bool:
    if is_globally_blocked or document.id in blocked_ids:
        return False

    now = time.time()
    granted_ids = batch_prefetch_granted_ids(
        session,
        user,
        [document.id],
        "document",
        "read",
        now,
    )
    if document.id in granted_ids:
        return True

    rules = fetch_compiled_access_rules_for_targets(
        session,
        (("document", document.id),),
        access_type="read",
    )
    return compiled_rules_allow_from_map(
        rules,
        target_type="document",
        target_id=document.id,
        user=user,
        access_type="read",
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

    folders = [node for node in chain if isinstance(node, Folder)]
    access_context = load_folder_access_evaluation_context(
        session,
        folders,
        user,
        "read",
    )
    if any(not access_context.allows(folder) for folder in folders):
        return None

    terminal = chain[-1]
    if isinstance(terminal, Document) and not _document_is_readable(
        session,
        user,
        terminal,
        is_globally_blocked=access_context.is_globally_blocked,
        blocked_ids=access_context.blocked_ids,
    ):
        return None

    return tuple(node.id for node in chain)
