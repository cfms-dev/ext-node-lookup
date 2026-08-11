"""CFMS node lookup extension entrypoint."""

from include.database.models.identity import User
from include.database.session import Session
from include.extensions.manager import hookimpl
from include.transport.connection import ConnectionHandler
from include.transport.request_handler import RequestHandler, Result

from ._path import MAX_PATH_LENGTH, NodePathError, parse_node_path
from ._resolver import resolve_authorized_node_ids


class RequestNodeLookupHandler(RequestHandler):
    schema = {
        "type": "object",
        "properties": {
            "path": {
                "type": "string",
                "minLength": 1,
                "maxLength": MAX_PATH_LENGTH,
            }
        },
        "required": ["path"],
        "additionalProperties": False,
    }
    require_auth = True
    rate_limit_cost = 3

    def handle(self, handler: ConnectionHandler) -> Result:
        try:
            segments = parse_node_path(handler.data["path"])
        except NodePathError:
            handler.conclude_request(400, {}, "Invalid node path")
            return Result(code=400, target=None, username=handler.username)

        with Session() as session:
            user = User.get_existing(session, handler.username)
            node_ids = resolve_authorized_node_ids(session, user, segments)

        if node_ids is None:
            handler.conclude_request(404, {}, "Node path not found")
            return Result(code=404, target=None, username=handler.username)

        response_data = {"node_ids": list(node_ids)}
        handler.conclude_request(
            200,
            response_data,
            "Node path resolved successfully",
        )
        return Result(code=200, target=node_ids[-1], username=handler.username)


@hookimpl
def ext_register_handlers() -> dict[str, type[RequestHandler]]:
    return {"node_lookup": RequestNodeLookupHandler}


@hookimpl
def ext_register_extension_flags() -> set[str]:
    return {"node_lookup"}
