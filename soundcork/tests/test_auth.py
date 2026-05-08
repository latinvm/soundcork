"""Tests for the optional HTTP Basic auth shim.

Builds tiny FastAPI apps that mount a stand-in router with the same
``basic_auth_dependencies`` used by main.py, so we test the auth
behaviour without bringing up speaker discovery.
"""

from base64 import b64encode

from fastapi import APIRouter, FastAPI, Request
from fastapi.testclient import TestClient
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import Response as StarletteResponse

from soundcork.auth import basic_auth_dependencies
from soundcork.config import Settings
from soundcork.unhandled_exception_handler import NotFoundHandler


def _make_app(settings: Settings) -> FastAPI:
    """Build an app with one protected route and one unprotected route."""
    app = FastAPI()

    protected = APIRouter()

    @protected.get("/admin/ping")
    def admin_ping() -> dict:
        return {"ok": True}

    @protected.get("/mgmt/ping")
    def mgmt_ping() -> dict:
        return {"ok": True}

    speaker = APIRouter()

    @speaker.get("/marge/ping")
    def marge_ping() -> dict:
        return {"ok": True}

    app.include_router(protected, dependencies=basic_auth_dependencies(settings))
    app.include_router(speaker)

    # Mirror main.py: a global StarletteHTTPException handler that
    # rebuilds the response. Earlier versions dropped exc.headers,
    # which silently stripped the WWW-Authenticate challenge from 401s
    # and broke the browser Basic-auth login dialog.
    handler = NotFoundHandler(settings.unhandled_log_dir)

    @app.exception_handler(StarletteHTTPException)
    async def unhandled_requests(
        request: Request, exc: StarletteHTTPException
    ) -> StarletteResponse:
        return await handler.dump_unhandled_requests(request, exc)

    return app


def _basic_header(user: str, password: str) -> dict:
    token = b64encode(f"{user}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


def test_auth_disabled_passes_through() -> None:
    settings = Settings(admin_basic_auth_user="", admin_basic_auth_password="")
    client = TestClient(_make_app(settings))

    assert client.get("/admin/ping").status_code == 200
    assert client.get("/mgmt/ping").status_code == 200
    assert client.get("/marge/ping").status_code == 200


def test_auth_disabled_when_only_user_set() -> None:
    settings = Settings(admin_basic_auth_user="alice", admin_basic_auth_password="")
    client = TestClient(_make_app(settings))

    assert client.get("/admin/ping").status_code == 200


def test_auth_enabled_rejects_no_credentials() -> None:
    settings = Settings(
        admin_basic_auth_user="alice", admin_basic_auth_password="hunter2"
    )
    client = TestClient(_make_app(settings))

    response = client.get("/admin/ping")
    assert response.status_code == 401
    assert response.headers.get("www-authenticate", "").lower().startswith("basic")


def test_auth_enabled_rejects_wrong_credentials() -> None:
    settings = Settings(
        admin_basic_auth_user="alice", admin_basic_auth_password="hunter2"
    )
    client = TestClient(_make_app(settings))

    assert (
        client.get("/admin/ping", headers=_basic_header("alice", "wrong")).status_code
        == 401
    )
    assert (
        client.get("/admin/ping", headers=_basic_header("bob", "hunter2")).status_code
        == 401
    )


def test_auth_enabled_accepts_correct_credentials() -> None:
    settings = Settings(
        admin_basic_auth_user="alice", admin_basic_auth_password="hunter2"
    )
    client = TestClient(_make_app(settings))

    response = client.get("/admin/ping", headers=_basic_header("alice", "hunter2"))
    assert response.status_code == 200
    assert response.json() == {"ok": True}

    response = client.get("/mgmt/ping", headers=_basic_header("alice", "hunter2"))
    assert response.status_code == 200


def test_401_preserves_www_authenticate_through_global_handler() -> None:
    # Regression: the global StarletteHTTPException handler used to
    # rebuild the response without exc.headers, so browsers got a 401
    # with no challenge and never showed the login dialog.
    settings = Settings(
        admin_basic_auth_user="alice", admin_basic_auth_password="hunter2"
    )
    client = TestClient(_make_app(settings))

    response = client.get("/admin/ping")
    assert response.status_code == 401
    assert response.headers.get("www-authenticate", "").lower().startswith("basic")


def test_auth_enabled_does_not_protect_speaker_routes() -> None:
    settings = Settings(
        admin_basic_auth_user="alice", admin_basic_auth_password="hunter2"
    )
    client = TestClient(_make_app(settings))

    # speaker-facing routes are not on the protected router, so they
    # still answer without credentials when auth is enabled.
    assert client.get("/marge/ping").status_code == 200
