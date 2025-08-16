"""
Unit tests for OAuth 2.1 Pydantic models.

Tests validation, serialization, and error handling for all OAuth
request and response models to ensure proper data validation.
"""

import pytest
from pydantic import ValidationError
from src.shared.oauth_models import (
    AuthorizationRequest,
    TokenRequest,
    TokenResponse,
    OAuthError,
    UserInfo,
    PKCEMethod,
    GrantType,
    ResponseType,
    TokenType
)


class TestPKCEMethod:
    """Test cases for PKCEMethod enum."""

    def test_s256_method_value(self):
        """Test that S256 method has correct value."""
        assert PKCEMethod.S256 == "S256"
        assert PKCEMethod.S256.value == "S256"


class TestGrantType:
    """Test cases for GrantType enum."""

    def test_authorization_code_value(self):
        """Test that authorization_code grant type has correct value."""
        assert GrantType.AUTHORIZATION_CODE == "authorization_code"
        assert GrantType.AUTHORIZATION_CODE.value == "authorization_code"


class TestResponseType:
    """Test cases for ResponseType enum."""

    def test_code_response_type_value(self):
        """Test that code response type has correct value."""
        assert ResponseType.CODE == "code"
        assert ResponseType.CODE.value == "code"


class TestTokenType:
    """Test cases for TokenType enum."""

    def test_bearer_token_type_value(self):
        """Test that Bearer token type has correct value."""
        assert TokenType.BEARER == "Bearer"
        assert TokenType.BEARER.value == "Bearer"


class TestAuthorizationRequest:
    """Test cases for AuthorizationRequest model."""

    def test_valid_authorization_request(self):
        """Test creation of valid authorization request."""
        request_data = {
            "client_id": "demo-client",
            "redirect_uri": "http://localhost:8080/callback",
            "scope": "read write",
            "state": "random-state-123",
            "code_challenge": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            "code_challenge_method": "S256",
            "response_type": "code"
        }

        request = AuthorizationRequest(**request_data)

        assert request.client_id == "demo-client"
        assert str(request.redirect_uri) == "http://localhost:8080/callback"
        assert request.scope == "read write"
        assert request.state == "random-state-123"
        assert request.code_challenge == "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        assert request.code_challenge_method == PKCEMethod.S256
        assert request.response_type == ResponseType.CODE

    def test_authorization_request_defaults(self):
        """Test that authorization request uses correct defaults."""
        request_data = {
            "client_id": "demo-client",
            "redirect_uri": "http://localhost:8080/callback",
            "scope": "read",
            "state": "state-123",
            "code_challenge": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            "code_challenge_method": "S256"
        }

        request = AuthorizationRequest(**request_data)
        assert request.response_type == ResponseType.CODE

    def test_authorization_request_missing_required_fields(self):
        """Test validation errors for missing required fields."""
        # Missing client_id
        with pytest.raises(ValidationError) as exc_info:
            AuthorizationRequest(
                redirect_uri="http://localhost:8080/callback",
                scope="read",
                state="state-123",
                code_challenge="dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
                code_challenge_method="S256"
            )
        assert "client_id" in str(exc_info.value)

        # Missing redirect_uri
        with pytest.raises(ValidationError) as exc_info:
            AuthorizationRequest(
                client_id="demo-client",
                scope="read",
                state="state-123",
                code_challenge="dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
                code_challenge_method="S256"
            )
        assert "redirect_uri" in str(exc_info.value)

    def test_authorization_request_invalid_client_id(self):
        """Test validation of client_id field."""
        request_data = {
            "client_id": "",  # Empty client_id
            "redirect_uri": "http://localhost:8080/callback",
            "scope": "read",
            "state": "state-123",
            "code_challenge": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            "code_challenge_method": "S256"
        }

        with pytest.raises(ValidationError) as exc_info:
            AuthorizationRequest(**request_data)
        assert "client_id" in str(exc_info.value)

    def test_authorization_request_invalid_redirect_uri(self):
        """Test validation of redirect_uri field."""
        request_data = {
            "client_id": "demo-client",
            "redirect_uri": "not-a-valid-uri",
            "scope": "read",
            "state": "state-123",
            "code_challenge": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            "code_challenge_method": "S256"
        }

        with pytest.raises(ValidationError) as exc_info:
            AuthorizationRequest(**request_data)
        assert "redirect_uri" in str(exc_info.value)

    def test_authorization_request_invalid_code_challenge(self):
        """Test validation of code_challenge field."""
        request_data = {
            "client_id": "demo-client",
            "redirect_uri": "http://localhost:8080/callback",
            "scope": "read",
            "state": "state-123",
            "code_challenge": "short",  # Too short
            "code_challenge_method": "S256"
        }

        with pytest.raises(ValidationError) as exc_info:
            AuthorizationRequest(**request_data)
        assert "code_challenge" in str(exc_info.value)

    def test_authorization_request_invalid_code_challenge_method(self):
        """Test validation of code_challenge_method field."""
        request_data = {
            "client_id": "demo-client",
            "redirect_uri": "http://localhost:8080/callback",
            "scope": "read",
            "state": "state-123",
            "code_challenge": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            "code_challenge_method": "plain"  # Invalid method
        }

        with pytest.raises(ValidationError) as exc_info:
            AuthorizationRequest(**request_data)
        assert "code_challenge_method" in str(exc_info.value)


class TestTokenRequest:
    """Test cases for TokenRequest model."""

    def test_valid_token_request(self):
        """Test creation of valid token request."""
        request_data = {
            "grant_type": "authorization_code",
            "code": "auth-code-123",
            "redirect_uri": "http://localhost:8080/callback",
            "client_id": "demo-client",
            "code_verifier": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        }

        request = TokenRequest(**request_data)

        assert request.grant_type == GrantType.AUTHORIZATION_CODE
        assert request.code == "auth-code-123"
        assert str(request.redirect_uri) == "http://localhost:8080/callback"
        assert request.client_id == "demo-client"
        assert request.code_verifier == "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

    def test_token_request_missing_required_fields(self):
        """Test validation errors for missing required fields."""
        # Missing grant_type
        with pytest.raises(ValidationError) as exc_info:
            TokenRequest(
                code="auth-code-123",
                redirect_uri="http://localhost:8080/callback",
                client_id="demo-client",
                code_verifier="dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
            )
        assert "grant_type" in str(exc_info.value)

    def test_token_request_invalid_code_verifier(self):
        """Test validation of code_verifier field."""
        request_data = {
            "grant_type": "authorization_code",
            "code": "auth-code-123",
            "redirect_uri": "http://localhost:8080/callback",
            "client_id": "demo-client",
            "code_verifier": "short"  # Too short
        }

        with pytest.raises(ValidationError) as exc_info:
            TokenRequest(**request_data)
        assert "code_verifier" in str(exc_info.value)


class TestTokenResponse:
    """Test cases for TokenResponse model."""

    def test_valid_token_response(self):
        """Test creation of valid token response."""
        response_data = {
            "access_token": "access-token-123",
            "scope": "read write"
        }

        response = TokenResponse(**response_data)

        assert response.access_token == "access-token-123"
        assert response.token_type == TokenType.BEARER
        assert response.expires_in == 3600
        assert response.scope == "read write"
        assert response.refresh_token is None

    def test_token_response_with_refresh_token(self):
        """Test token response with refresh token."""
        response_data = {
            "access_token": "access-token-123",
            "scope": "read",
            "refresh_token": "refresh-token-456",
            "expires_in": 7200
        }

        response = TokenResponse(**response_data)

        assert response.access_token == "access-token-123"
        assert response.refresh_token == "refresh-token-456"
        assert response.expires_in == 7200

    def test_token_response_invalid_expires_in(self):
        """Test validation of expires_in field."""
        response_data = {
            "access_token": "access-token-123",
            "scope": "read",
            "expires_in": 0  # Must be >= 1
        }

        with pytest.raises(ValidationError) as exc_info:
            TokenResponse(**response_data)
        assert "expires_in" in str(exc_info.value)


class TestOAuthError:
    """Test cases for OAuthError model."""

    def test_valid_oauth_error(self):
        """Test creation of valid OAuth error."""
        error_data = {
            "error": "invalid_request",
            "error_description": "Missing required parameter",
            "state": "state-123"
        }

        error = OAuthError(**error_data)

        assert error.error == "invalid_request"
        assert error.error_description == "Missing required parameter"
        assert error.state == "state-123"
        assert error.error_uri is None

    def test_oauth_error_minimal(self):
        """Test OAuth error with only required fields."""
        error = OAuthError(error="invalid_grant")

        assert error.error == "invalid_grant"
        assert error.error_description is None
        assert error.error_uri is None
        assert error.state is None


class TestUserInfo:
    """Test cases for UserInfo model."""

    def test_valid_user_info(self):
        """Test creation of valid user info."""
        user_data = {
            "sub": "user-123",
            "username": "alice",
            "email": "alice@example.com"
        }

        user_info = UserInfo(**user_data)

        assert user_info.sub == "user-123"
        assert user_info.username == "alice"
        assert user_info.email == "alice@example.com"

    def test_user_info_without_email(self):
        """Test user info without optional email field."""
        user_data = {
            "sub": "user-123",
            "username": "bob"
        }

        user_info = UserInfo(**user_data)

        assert user_info.sub == "user-123"
        assert user_info.username == "bob"
        assert user_info.email is None

    def test_user_info_invalid_username(self):
        """Test validation of username field."""
        user_data = {
            "sub": "user-123",
            "username": ""  # Empty username
        }

        with pytest.raises(ValidationError) as exc_info:
            UserInfo(**user_data)
        assert "username" in str(exc_info.value)


class TestModelSerialization:
    """Test cases for model serialization and deserialization."""

    def test_authorization_request_serialization(self):
        """Test AuthorizationRequest serialization to dict."""
        request = AuthorizationRequest(
            client_id="demo-client",
            redirect_uri="http://localhost:8080/callback",
            scope="read",
            state="state-123",
            code_challenge="dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            code_challenge_method="S256"
        )

        data = request.dict()

        assert data["client_id"] == "demo-client"
        assert data["redirect_uri"] == "http://localhost:8080/callback"
        assert data["code_challenge_method"] == "S256"
        assert data["response_type"] == "code"

    def test_token_response_json_serialization(self):
        """Test TokenResponse JSON serialization."""
        response = TokenResponse(
            access_token="access-token-123",
            scope="read"
        )

        json_data = response.json()
        assert "access_token" in json_data
        assert "token_type" in json_data
        assert "expires_in" in json_data

    def test_oauth_error_serialization(self):
        """Test OAuthError serialization."""
        error = OAuthError(
            error="invalid_request",
            error_description="Missing parameter"
        )

        data = error.dict(exclude_none=True)
        assert "error" in data
        assert "error_description" in data
        assert "error_uri" not in data  # Should be excluded since it's None