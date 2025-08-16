"""
Token Validation Middleware for Resource Server

This module provides token validation functionality for protecting
resource server endpoints with OAuth 2.1 Bearer tokens.
"""

from fastapi import HTTPException, Header, Request
from typing import Optional, Dict, Any
import re
import sys
import os

# Add the src directory to the path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from src.shared.logging_utils import OAuthLogger

# Initialize logger
logger = OAuthLogger("RESOURCE-SERVER")

# Token validation patterns
BEARER_TOKEN_PATTERN = re.compile(r'^Bearer\s+([A-Za-z0-9\-._~+/]+=*)$')
TOKEN_MIN_LENGTH = 10
TOKEN_MAX_LENGTH = 512


class TokenValidationError(Exception):
    """Custom exception for token validation errors."""

    def __init__(self, error_code: str, description: str, status_code: int = 401):
        self.error_code = error_code
        self.description = description
        self.status_code = status_code
        super().__init__(description)


def parse_authorization_header(authorization: Optional[str]) -> str:
    """
    Parse and validate the Authorization header format.

    Args:
        authorization: Raw Authorization header value

    Returns:
        str: Extracted token

    Raises:
        TokenValidationError: If header is missing or malformed
    """
    if not authorization:
        raise TokenValidationError(
            "missing_authorization_header",
            "Authorization header is required for protected resources"
        )

    # Check Bearer token format using regex
    match = BEARER_TOKEN_PATTERN.match(authorization)
    if not match:
        raise TokenValidationError(
            "invalid_authorization_format",
            "Authorization header must be in format: 'Bearer <token>'"
        )

    token = match.group(1)

    # Validate token format and length
    if len(token) < TOKEN_MIN_LENGTH:
        raise TokenValidationError(
            "invalid_token_format",
            f"Token must be at least {TOKEN_MIN_LENGTH} characters long"
        )

    if len(token) > TOKEN_MAX_LENGTH:
        raise TokenValidationError(
            "invalid_token_format",
            f"Token must not exceed {TOKEN_MAX_LENGTH} characters"
        )

    return token


def validate_token_format(token: str) -> bool:
    """
    Validate the token format and structure.

    Args:
        token: The access token to validate

    Returns:
        bool: True if token format is valid
    """
    # Basic format validation
    if not token or not isinstance(token, str):
        return False

    # Check for suspicious characters or patterns
    if any(char in token for char in [' ', '\n', '\r', '\t']):
        return False

    # In a real implementation, you might check:
    # - JWT signature validation
    # - Token expiration
    # - Token revocation status
    # - Scope validation

    return True


def log_token_validation_attempt(
    request: Request,
    token: Optional[str] = None,
    success: bool = False,
    error: Optional[str] = None
) -> None:
    """
    Log detailed information about token validation attempts.

    Args:
        request: FastAPI request object
        token: The token being validated (will be truncated in logs)
        success: Whether validation was successful
        error: Error message if validation failed
    """
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")

    log_data = {
        "method": request.method,
        "path": str(request.url.path),
        "client_ip": client_ip,
        "user_agent": user_agent[:50] + "..." if len(user_agent) > 50 else user_agent,
        "timestamp": request.headers.get("x-timestamp"),
    }

    if token:
        log_data["token_prefix"] = token[:10] + "..." if len(token) > 10 else token
        log_data["token_length"] = len(token)

    if success:
        log_data.update({
            "validation_result": "success",
            "user_id": "validated-user",  # In real implementation, extract from token
            "client_id": "demo-client",   # In real implementation, extract from token
            "scope": "read"               # In real implementation, extract from token
        })

        logger.log_oauth_message(
            "RESOURCE-SERVER", "RESOURCE-SERVER",
            "Token Validation Success",
            log_data
        )
    else:
        log_data.update({
            "validation_result": "failure",
            "error": error or "unknown_error"
        })

        logger.log_oauth_message(
            "RESOURCE-SERVER", "CLIENT",
            "Token Validation Failed",
            log_data
        )


async def validate_bearer_token(
    request: Request,
    authorization: Optional[str] = Header(None)
) -> Dict[str, Any]:
    """
    FastAPI dependency function to validate Bearer tokens.

    This function serves as middleware to validate OAuth 2.1 Bearer tokens
    for protected resource endpoints.

    Args:
        request: FastAPI request object for logging
        authorization: Authorization header value

    Returns:
        Dict[str, Any]: Token validation result with user/client info

    Raises:
        HTTPException: If token validation fails
    """
    try:
        # Log the validation attempt
        logger.log_oauth_message(
            "CLIENT", "RESOURCE-SERVER",
            "Token Validation Request",
            {
                "method": request.method,
                "path": str(request.url.path),
                "authorization_header_present": authorization is not None,
                "client_ip": request.client.host if request.client else "unknown"
            }
        )

        # Parse Authorization header
        token = parse_authorization_header(authorization)

        # Validate token format
        if not validate_token_format(token):
            raise TokenValidationError(
                "invalid_token_format",
                "Token format is invalid"
            )

        # In a real implementation, you would:
        # 1. Look up the token in your database/cache
        # 2. Check if the token is expired
        # 3. Verify the token signature (if JWT)
        # 4. Check if the token has been revoked
        # 5. Validate the required scopes for this resource

        # For demo purposes, accept any properly formatted token
        token_info = {
            "token": token,
            "user_id": "validated-user",
            "client_id": "demo-client",
            "scope": ["read"],
            "expires_at": None,  # In real implementation, check expiration
            "issued_at": None    # In real implementation, track issue time
        }

        # Log successful validation
        log_token_validation_attempt(request, token, success=True)

        return token_info

    except TokenValidationError as e:
        # Log failed validation
        log_token_validation_attempt(request, error=e.description)

        # Return appropriate HTTP error
        raise HTTPException(
            status_code=e.status_code,
            detail=e.description,
            headers={"WWW-Authenticate": "Bearer"}
        )

    except Exception as e:
        # Log unexpected errors
        log_token_validation_attempt(request, error=f"Unexpected error: {str(e)}")

        # Return generic error to avoid information leakage
        raise HTTPException(
            status_code=500,
            detail="Internal server error during token validation"
        )


def require_scope(required_scope: str):
    """
    Decorator factory for requiring specific OAuth scopes.

    Args:
        required_scope: The scope required to access the resource

    Returns:
        Dependency function that validates the required scope
    """
    def scope_validator(token_info: Dict[str, Any] = None) -> Dict[str, Any]:
        if not token_info:
            raise HTTPException(
                status_code=401,
                detail="Token validation required"
            )

        user_scopes = token_info.get("scope", [])
        if required_scope not in user_scopes:
            logger.log_oauth_message(
                "RESOURCE-SERVER", "CLIENT",
                "Insufficient Scope",
                {
                    "required_scope": required_scope,
                    "user_scopes": user_scopes,
                    "user_id": token_info.get("user_id"),
                    "client_id": token_info.get("client_id")
                }
            )

            raise HTTPException(
                status_code=403,
                detail=f"Insufficient scope. Required: {required_scope}",
                headers={"WWW-Authenticate": f'Bearer scope="{required_scope}"'}
            )

        return token_info

    return scope_validator