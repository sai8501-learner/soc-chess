import base64
import hashlib
import hmac
import json
import logging
import secrets
import time
from typing import Any, Dict, Optional

from backend.config import settings
from backend.database import execute, query_one

logger = logging.getLogger("socchess.auth")


class AuthError(Exception):
    pass


class AuthService:
    _algorithm = "HS256"
    _password_iterations = 600_000

    @staticmethod
    def _encode(value: bytes) -> str:
        return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")

    @staticmethod
    def _decode(value: str) -> bytes:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))

    @property
    def is_configured(self) -> bool:
        return (
            len(settings.JWT_SECRET) >= 32
            and settings.JWT_SECRET != "soc_chess_jwt_secret_default_key"
        )

    @staticmethod
    def _public_user(record: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "id": int(record["id"]),
            "username": record["username"],
            "email": record["email"],
            "role": str(record["role"]).upper(),
        }

    def hash_password(self, password: str) -> str:
        if len(password) < 12:
            raise AuthError("Password must contain at least 12 characters")

        salt = secrets.token_bytes(16)
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, self._password_iterations
        )
        return "$".join(
            [
                "pbkdf2_sha256",
                str(self._password_iterations),
                self._encode(salt),
                self._encode(digest),
            ]
        )

    def verify_password(self, password: str, password_hash: str) -> bool:
        try:
            algorithm, iterations, encoded_salt, expected_digest = password_hash.split("$", 3)
            if algorithm != "pbkdf2_sha256":
                return False
            digest = hashlib.pbkdf2_hmac(
                "sha256",
                password.encode("utf-8"),
                self._decode(encoded_salt),
                int(iterations),
            )
            return hmac.compare_digest(self._encode(digest), expected_digest)
        except (TypeError, ValueError):
            return False

    def has_users(self) -> bool:
        try:
            row = query_one("SELECT COUNT(*) AS total FROM users")
            return bool(row and row["total"])
        except Exception as e:
            logger.warning(f"Error checking users in database: {e}")
            return False

    def create_initial_admin(self, username: str, email: str, password: str) -> Dict[str, Any]:
        if self.has_users():
            raise AuthError("An account already exists; use the login endpoint")

        return self._create_user(username, email, password, "ADMIN")

    def create_user(self, username: str, email: str, password: str) -> Dict[str, Any]:
        return self._create_user(username, email, password, "ANALYST")

    def _create_user(self, username: str, email: str, password: str, role: str) -> Dict[str, Any]:
        password_hash = self.hash_password(password)
        try:
            user_id = execute(
                "INSERT INTO users (username, email, password_hash, role, is_active) "
                "VALUES (%s, %s, %s, %s, %s)",
                (username, email, password_hash, role, True),
            )
        except Exception as error:
            logger.warning(f"Failed to create user in DB: {error}")
            raise AuthError("Username or email is already registered or database is unavailable") from error

        return {"id": int(user_id), "username": username, "email": email, "role": role}

    def authenticate(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        try:
            record = query_one(
                "SELECT id, username, email, password_hash, role, is_active FROM users WHERE username = %s",
                (username,),
            )
        except Exception as error:
            logger.error(f"Database error during authentication: {error}")
            raise AuthError("Database connection failed. Please ensure MySQL/WampServer is running.") from error

        if not record or not record.get("is_active"):
            return None
        if not self.verify_password(password, record.get("password_hash", "")):
            return None
        return self._public_user(record)

    def create_access_token(self, user: Dict[str, Any]) -> str:
        if not self.is_configured:
            raise AuthError("JWT_SECRET must be at least 32 characters")

        now = int(time.time())
        payload = {
            "sub": str(user["id"]),
            "username": user["username"],
            "role": user["role"],
            "iat": now,
            "exp": now + settings.ACCESS_TOKEN_TTL_MINUTES * 60,
        }
        header = {"alg": self._algorithm, "typ": "JWT"}
        encoded_header = self._encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
        encoded_payload = self._encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        message = f"{encoded_header}.{encoded_payload}".encode("ascii")
        signature = hmac.new(settings.JWT_SECRET.encode("utf-8"), message, hashlib.sha256).digest()
        return f"{encoded_header}.{encoded_payload}.{self._encode(signature)}"

    def get_authenticated_user(self, token: str) -> Dict[str, Any]:
        if not self.is_configured:
            raise AuthError("JWT authentication is not configured")

        try:
            encoded_header, encoded_payload, encoded_signature = token.split(".")
            message = f"{encoded_header}.{encoded_payload}".encode("ascii")
            expected_signature = hmac.new(
                settings.JWT_SECRET.encode("utf-8"), message, hashlib.sha256
            ).digest()
            if not hmac.compare_digest(self._decode(encoded_signature), expected_signature):
                raise AuthError("Invalid access token")

            header = json.loads(self._decode(encoded_header))
            payload = json.loads(self._decode(encoded_payload))
            if header.get("alg") != self._algorithm or int(payload["exp"]) <= int(time.time()):
                raise AuthError("Access token has expired")
            user_id = int(payload["sub"])
        except (KeyError, TypeError, ValueError, json.JSONDecodeError, UnicodeDecodeError):
            raise AuthError("Invalid access token")

        record = query_one(
            "SELECT id, username, email, role, is_active FROM users WHERE id = %s",
            (user_id,),
        )
        if not record or not record["is_active"]:
            raise AuthError("Account is unavailable")
        return self._public_user(record)


auth_service = AuthService()
