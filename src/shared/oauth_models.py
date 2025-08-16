"""
OAuth 2.1 Pydantic models for request/response validation.

This module defines the core data models used throughout the OAuth 2.1 flow,
including authorization requests, token requests, and responses with comprehensive
validation rules.
"""

from pydantic import BaseModel, HttpUrl, Field, validator
from typing import Optional, Literal
from enum import Enum


class PKCEMethod(str, Enum):
    """PKCE code challenge methods as defined in RFC 7636."""
    S256 = "S256"


class GrantType(str, Enum):
    """OAuth 2.1 grant types."""
    AUTHORIZATION_CODE = "authorization_code"


class ResponseType(str, Enum):
    """OAuth 2.1 response types."""
    CODE = "code"


class TokenType(str, Enum):
    """OAuth token types."""
    BEARER = "Bearer"


class AuthorizationRequest(BaseModel):
    """
    OAuth 2.1 authorization request model.

    Validates all required parameters for the authorization endpoint
    including mandatory PKCE parameters.
    """
    client_id: str = Field(..., min_length=1, description="OAuth client identifier")
    redirect_uri: HttpUrl = Field(..., description="Client redirect URI")
    scope: str = Field(..., min_length=1, description="Requested scope")
    state: str = Field(..., min_length=1, description="CSRF protection state parameter")
    code_challenge: str = Field(
        ...,
        min_length=43,
        max_length=128,
        description="PKCE code challenge"
    )
    code_challenge_method: PKCEMethod = Field(
        ...,
        description="PKCE challenge method (must be S256)"
    )
    response_type: ResponseType = Field(
        default=ResponseType.CODE,
        description="OAuth response type (must be 'code')"
    )

    @validator('code_challenge')
    def validate_code_challenge(cls, v):
        """Validate PKCE code challenge format."""
        if not v.replace('-', '').replace('_', '').isalnum():
            raise ValueError("Code challenge must be base64url encoded")
        return v

    class Config:
        """Pydantic model configuration."""
        use_enum_values = True
        validate_assignment = True


class TokenRequest(BaseModel):
    """
    OAuth 2.1 token request model.

    Validates token exchange requests including PKCE verifier.
    """
    grant_type: GrantType = Field(..., description="OAuth grant type")
    code: str = Field(..., min_length=1, description="Authorization code")
    redirect_uri: HttpUrl = Field(..., description="Client redirect URI")
    client_id: str = Field(..., min_length=1, description="OAuth client identifier")
    code_verifier: str = Field(
        ...,
        min_length=43,
        max_length=128,
        description="PKCE code verifier"
    )

    @validator('code_verifier')
    def validate_code_verifier(cls, v):
        """Validate PKCE code verifier format."""
        if not v.replace('-', '').replace('_', '').isalnum():
            raise ValueError("Code verifier must be base64url encoded")
        return v

    class Config:
        """Pydantic model configuration."""
        use_enum_values = True
        validate_assignment = True


class TokenResponse(BaseModel):
    """
    OAuth 2.1 token response model.

    Standard token response with access token and metadata.
    """
    access_token: str = Field(..., min_length=1, description="OAuth access token")
    token_type: TokenType = Field(
        default=TokenType.BEARER,
        description="Token type (Bearer)"
    )
    expires_in: int = Field(
        default=3600,
        ge=1,
        description="Token lifetime in seconds"
    )
    scope: str = Field(..., description="Granted scope")
    refresh_token: Optional[str] = Field(
        default=None,
        description="Refresh token (optional)"
    )

    class Config:
        """Pydantic model configuration."""
        use_enum_values = True
        validate_assignment = True


class OAuthError(BaseModel):
    """
    OAuth 2.1 error response model.

    Standard error response format as defined in RFC 6749.
    """
    error: str = Field(..., description="Error code")
    error_description: Optional[str] = Field(
        default=None,
        description="Human-readable error description"
    )
    error_uri: Optional[HttpUrl] = Field(
        default=None,
        description="URI with error information"
    )
    state: Optional[str] = Field(
        default=None,
        description="State parameter from request"
    )

    class Config:
        """Pydantic model configuration."""
        validate_assignment = True


class UserInfo(BaseModel):
    """
    User information model for protected resources.
    """
    sub: str = Field(..., description="Subject identifier")
    username: str = Field(..., min_length=1, description="Username")
    email: Optional[str] = Field(default=None, description="Email address")

    class Config:
        """Pydantic model configuration."""
        validate_assignment = True