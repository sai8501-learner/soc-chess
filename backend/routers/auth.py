import logging
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field, field_validator

from backend.config import settings
from backend.services.auth_service import AuthError, auth_service

logger = logging.getLogger("socchess.auth_router")


router = APIRouter(prefix="/api/auth", tags=["Authentication"])


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=256)


class BootstrapRequest(BaseModel):
    username: str = Field(min_length=3, max_length=100, pattern=r"^[A-Za-z0-9_.-]+$")
    password: str = Field(min_length=12, max_length=256)
    email: str = Field(min_length=5, max_length=255)

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        if "@" not in value or value.startswith("@") or value.endswith("@"):
            raise ValueError("A valid email address is required")
        return value.lower()


class RegisterRequest(BootstrapRequest):
    pass


def _is_loopback(request: Request) -> bool:
    return request.client is not None and request.client.host in {"127.0.0.1", "::1", "testclient"}


def _session_response(user: dict) -> dict:
    return {
        "access_token": auth_service.create_access_token(user),
        "token_type": "bearer",
        "user": user,
    }


@router.get("/status")
def get_auth_status():
    configured = auth_service.is_configured
    try:
        bootstrap_required = settings.AUTH_ENABLED and configured and not auth_service.has_users()
    except Exception:
        bootstrap_required = False
    return {
        "enabled": settings.AUTH_ENABLED,
        "configured": configured,
        "bootstrap_required": bootstrap_required,
    }


@router.post("/bootstrap")
def bootstrap_admin(payload: BootstrapRequest, request: Request):
    if not settings.AUTH_ENABLED:
        raise HTTPException(status_code=400, detail="Authentication is disabled")
    if not _is_loopback(request):
        raise HTTPException(status_code=403, detail="Initial setup is available only from the local host")
    try:
        return _session_response(
            auth_service.create_initial_admin(payload.username, payload.email, payload.password)
        )
    except AuthError as error:
        raise HTTPException(status_code=409, detail=str(error)) from error
    except Exception as error:
        logger.exception(f"Bootstrap admin error: {error}")
        raise HTTPException(status_code=503, detail="Database error during setup. Ensure MySQL is running.") from error


@router.post("/register")
def register(payload: RegisterRequest):
    if not settings.AUTH_ENABLED:
        raise HTTPException(status_code=400, detail="Authentication is disabled")
    try:
        return _session_response(
            auth_service.create_user(payload.username, payload.email, payload.password)
        )
    except AuthError as error:
        raise HTTPException(status_code=409, detail=str(error)) from error
    except Exception as error:
        logger.exception(f"User registration error: {error}")
        raise HTTPException(status_code=503, detail="Database error during registration. Ensure MySQL is running.") from error


@router.post("/login")
def login(payload: LoginRequest):
    if not settings.AUTH_ENABLED:
        raise HTTPException(status_code=400, detail="Authentication is disabled")
    try:
        user = auth_service.authenticate(payload.username, payload.password)
        if not user:
            raise HTTPException(status_code=401, detail="Invalid username or password")
        return _session_response(user)
    except HTTPException:
        raise
    except AuthError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    except Exception as error:
        logger.exception(f"Unexpected login error: {error}")
        raise HTTPException(status_code=503, detail="Database connection failed. Ensure WampServer (MySQL) is running.") from error



@router.get("/me")
def get_current_user(request: Request):
    user = getattr(request.state, "user", None)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    return user
