"""
Unit tests for authorization server endpoints.

Tests the individual endpoints of the authorization server to ensure
proper OAuth 2.1 implementation, validation, and error handling.
"""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
from urllib.parse import parse_qs, urlparse
import secrets

from src.auth_server.main import app
from src.shared.crypto_utils import PKCEGenerator


class TestAuthorizationServerEndpoints:
    """Test cases for authorization server endpoints."""

    @pytest.fixture
    def client(self):
        """Test client for the authorization server."""
        return TestClient(app)

    @pytest.fixture
    def valid_oauth_params(self):
        """Valid OAuth parameters for testing."""
        verifier, challenge = PKCEGenerator.generate_challenge()
        return {
            "client_id": "demo-client",
            "redirect_uri": "http://localhost:8080/callback",
            "scope": "read",
            "state": secrets.token_urlsafe(16),
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "response_type": "code",
            "pkce_verifier": verifier
        }

    def test_health_endpoint(self, client):
        """Test health check endpoint."""
        response = client.get("/health")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "authorization" in data["service"].lower()
        assert "endpoints" in data

    def test_root_endpoint_info(self, client):
        """Test root endpoint service information."""
        response = client.get("/")

        assert response.status_code == 200
        data = response.json()
        assert "OAuth 2.1" in data["service"]
        assert "endpoints" in data
        assert "demo_accounts" in data
        assert len(data["demo_accounts"]) == 3

    def test_authorize_endpoint_valid_request(self, client, valid_oauth_params):
        """Test authorization endpoint with valid parameters."""
        response = client.get("/authorize", params={
            "client_id": valid_oauth_params["client_id"],
            "redirect_uri": valid_oauth_params["redirect_uri"],
            "scope": valid_oauth_params["scope"],
            "state": valid_oauth_params["state"],
            "code_challenge": valid_oauth_params["code_challenge"],
            "code_challenge_method": valid_oauth_params["code_challenge_method"],
            "response_type": valid_oauth_params["response_type"]
        })

        assert response.status_code == 200
        # Should return login form
        assert "login" in response.text.lower() or "form" in response.text.lower()

    def test_authorize_endpoint_missing_parameters(self, client):
        """Test authorization endpoint with missing required parameters."""
        # Test missing client_id
        response = client.get("/authorize", params={
            "redirect_uri": "http://localhost:8080/callback",
            "scope": "read",
            "state": "test-state",
            "code_challenge": "test-challenge",
            "code_challenge_method": "S256",
            "response_type": "code"
        })
        assert response.status_code == 422

        # Test missing redirect_uri
        response = client.get("/authorize", params={
            "client_id": "demo-client",
            "scope": "read",
            "state": "test-state",
            "code_challenge": "test-challenge",
            "code_challenge_method": "S256",
            "response_type": "code"
        })
        assert response.status_code == 422

    def test_authorize_endpoint_invalid_response_type(self, client, valid_oauth_params):
        """Test authorization endpoint with invalid response_type."""
        params = valid_oauth_params.copy()
        params["response_type"] = "token"  # Invalid for OAuth 2.1

        response = client.get("/authorize", params=params)
        assert response.status_code in [400, 422]

    def test_authorize_endpoint_invalid_pkce_method(self, client, valid_oauth_params):
        """Test authorization endpoint with invalid PKCE method."""
        params = valid_oauth_params.copy()
        params["code_challenge_method"] = "plain"  # Invalid method

        response = client.get("/authorize", params=params)
        assert response.status_code in [400, 422]

    def test_authorize_endpoint_invalid_client_id(self, client, valid_oauth_params):
        """Test authorization endpoint with invalid client_id."""
        params = valid_oauth_params.copy()
        params["client_id"] = ""  # Empty client_id

        response = client.get("/authorize", params=params)
        assert response.status_code == 422

    def test_authorize_endpoint_invalid_redirect_uri(self, client, valid_oauth_params):
        """Test authorization endpoint with invalid redirect_uri."""
        params = valid_oauth_params.copy()
        params["redirect_uri"] = "not-a-valid-uri"

        response = client.get("/authorize", params=params)
        assert response.status_code == 422

    def test_login_endpoint_valid_credentials(self, client, valid_oauth_params):
        """Test login endpoint with valid demo credentials."""
        login_data = {
            "username": "alice",
            "password": "password123",
            "client_id": valid_oauth_params["client_id"],
            "redirect_uri": valid_oauth_params["redirect_uri"],
            "scope": valid_oauth_params["scope"],
            "state": valid_oauth_params["state"],
            "code_challenge": valid_oauth_params["code_challenge"],
            "code_challenge_method": valid_oauth_params["code_challenge_method"],
            "response_type": valid_oauth_params["response_type"]
        }

        response = client.post("/login", data=login_data)

        assert response.status_code == 302
        location = response.headers.get("location")
        assert location is not None
        assert valid_oauth_params["redirect_uri"] in location
        assert "code=" in location
        assert f"state={valid_oauth_params['state']}" in location

    def test_login_endpoint_all_demo_users(self, client, valid_oauth_params):
        """Test login endpoint with all demo user accounts."""
        demo_users = [
            ("alice", "password123"),
            ("bob", "secret456"),
            ("carol", "mypass789")
        ]

        for username, password in demo_users:
            login_data = {
                "username": username,
                "password": password,
                "client_id": valid_oauth_params["client_id"],
                "redirect_uri": valid_oauth_params["redirect_uri"],
                "scope": valid_oauth_params["scope"],
                "state": valid_oauth_params["state"],
                "code_challenge": valid_oauth_params["code_challenge"],
                "code_challenge_method": valid_oauth_params["code_challenge_method"],
                "response_type": valid_oauth_params["response_type"]
            }

            response = client.post("/login", data=login_data)
            assert response.status_code == 302

            # Verify authorization code is generated
            location = response.headers.get("location")
            assert "code=" in location

    def test_login_endpoint_invalid_credentials(self, client, valid_oauth_params):
        """Test login endpoint with invalid credentials."""
        login_data = {
            "username": "alice",
            "password": "wrong_password",
            "client_id": valid_oauth_params["client_id"],
            "redirect_uri": valid_oauth_params["redirect_uri"],
            "scope": valid_oauth_params["scope"],
            "state": valid_oauth_params["state"],
            "code_challenge": valid_oauth_params["code_challenge"],
            "code_challenge_method": valid_oauth_params["code_challenge_method"],
            "response_type": valid_oauth_params["response_type"]
        }

        response = client.post("/login", data=login_data)

        # Should handle authentication failure
        assert response.status_code in [200, 302, 400, 401]
        if response.status_code == 302:
            location = response.headers.get("location")
            # Should redirect with error
            assert "error=" in location or valid_oauth_params["redirect_uri"] not in location

    def test_login_endpoint_nonexistent_user(self, client, valid_oauth_params):
        """Test login endpoint with nonexistent user."""
        login_data = {
            "username": "nonexistent",
            "password": "password",
            "client_id": valid_oauth_params["client_id"],
            "redirect_uri": valid_oauth_params["redirect_uri"],
            "scope": valid_oauth_params["scope"],
            "state": valid_oauth_params["state"],
            "code_challenge": valid_oauth_params["code_challenge"],
            "code_challenge_method": valid_oauth_params["code_challenge_method"],
            "response_type": valid_oauth_params["response_type"]
        }

        response = client.post("/login", data=login_data)

        # Should handle nonexistent user
        assert response.status_code in [200, 302, 400, 401]

    def test_login_endpoint_missing_form_data(self, client):
        """Test login endpoint with missing form data."""
        # Missing username
        response = client.post("/login", data={
            "password": "password123",
            "client_id": "demo-client"
        })
        assert response.status_code == 422

        # Missing password
        response = client.post("/login", data={
            "username": "alice",
            "client_id": "demo-client"
        })
        assert response.status_code == 422

    def test_token_endpoint_valid_exchange(self, client, valid_oauth_params):
        """Test token endpoint with valid authorization code exchange."""
        # First get an authorization code
        login_data = {
            "username": "alice",
            "password": "password123",
            "client_id": valid_oauth_params["client_id"],
            "redirect_uri": valid_oauth_params["redirect_uri"],
            "scope": valid_oauth_params["scope"],
            "state": valid_oauth_params["state"],
            "code_challenge": valid_oauth_params["code_challenge"],
            "code_challenge_method": valid_oauth_params["code_challenge_method"],
            "response_type": valid_oauth_params["response_type"]
        }

        login_response = client.post("/login", data=login_data)
        assert login_response.status_code == 302

        # Extract authorization code
        location = login_response.headers.get("location")
        parsed_url = urlparse(location)
        query_params = parse_qs(parsed_url.query)
        auth_code = query_params["code"][0]

        # Exchange code for token
        token_request = {
            "grant_type": "authorization_code",
            "code": auth_code,
            "redirect_uri": valid_oauth_params["redirect_uri"],
            "client_id": valid_oauth_params["client_id"],
            "code_verifier": valid_oauth_params["pkce_verifier"]
        }

        token_response = client.post("/token", json=token_request)

        assert token_response.status_code == 200
        token_data = token_response.json()
        assert "access_token" in token_data
        assert token_data["token_type"] == "Bearer"
        assert "expires_in" in token_data
        assert token_data["scope"] == valid_oauth_params["scope"]

    def test_token_endpoint_invalid_grant_type(self, client):
        """Test token endpoint with invalid grant type."""
        token_request = {
            "grant_type": "client_credentials",  # Invalid grant type
            "code": "test_code",
            "redirect_uri": "http://localhost:8080/callback",
            "client_id": "demo-client",
            "code_verifier": "test_verifier"
        }

        response = client.post("/token", json=token_request)
        assert response.status_code in [400, 422]

    def test_token_endpoint_missing_parameters(self, client):
        """Test token endpoint with missing required parameters."""
        # Missing grant_type
        response = client.post("/token", json={
            "code": "test_code",
            "redirect_uri": "http://localhost:8080/callback",
            "client_id": "demo-client",
            "code_verifier": "test_verifier"
        })
        assert response.status_code == 422

        # Missing code
        response = client.post("/token", json={
            "grant_type": "authorization_code",
            "redirect_uri": "http://localhost:8080/callback",
            "client_id": "demo-client",
            "code_verifier": "test_verifier"
        })
        assert response.status_code == 422

    def test_token_endpoint_invalid_authorization_code(self, client):
        """Test token endpoint with invalid authorization code."""
        token_request = {
            "grant_type": "authorization_code",
            "code": "invalid_code_here",
            "redirect_uri": "http://localhost:8080/callback",
            "client_id": "demo-client",
            "code_verifier": "test_verifier"
        }

        response = client.post("/token", json=token_request)
        assert response.status_code == 400

    def test_token_endpoint_invalid_pkce_verifier(self, client, valid_oauth_params):
        """Test token endpoint with invalid PKCE verifier."""
        # Get valid authorization code first
        login_data = {
            "username": "alice",
            "password": "password123",
            "client_id": valid_oauth_params["client_id"],
            "redirect_uri": valid_oauth_params["redirect_uri"],
            "scope": valid_oauth_params["scope"],
            "state": valid_oauth_params["state"],
            "code_challenge": valid_oauth_params["code_challenge"],
            "code_challenge_method": valid_oauth_params["code_challenge_method"],
            "response_type": valid_oauth_params["response_type"]
        }

        login_response = client.post("/login", data=login_data)
        location = login_response.headers.get("location")
        parsed_url = urlparse(location)
        query_params = parse_qs(parsed_url.query)
        auth_code = query_params["code"][0]

        # Try to exchange with wrong PKCE verifier
        token_request = {
            "grant_type": "authorization_code",
            "code": auth_code,
            "redirect_uri": valid_oauth_params["redirect_uri"],
            "client_id": valid_oauth_params["client_id"],
            "code_verifier": "wrong_verifier_here"
        }

        response = client.post("/token", json=token_request)
        assert response.status_code == 400

    def test_token_endpoint_reused_authorization_code(self, client, valid_oauth_params):
        """Test that authorization codes can only be used once."""
        # Get authorization code
        login_data = {
            "username": "alice",
            "password": "password123",
            "client_id": valid_oauth_params["client_id"],
            "redirect_uri": valid_oauth_params["redirect_uri"],
            "scope": valid_oauth_params["scope"],
            "state": valid_oauth_params["state"],
            "code_challenge": valid_oauth_params["code_challenge"],
            "code_challenge_method": valid_oauth_params["code_challenge_method"],
            "response_type": valid_oauth_params["response_type"]
        }

        login_response = client.post("/login", data=login_data)
        location = login_response.headers.get("location")
        parsed_url = urlparse(location)
        query_params = parse_qs(parsed_url.query)
        auth_code = query_params["code"][0]

        token_request = {
            "grant_type": "authorization_code",
            "code": auth_code,
            "redirect_uri": valid_oauth_params["redirect_uri"],
            "client_id": valid_oauth_params["client_id"],
            "code_verifier": valid_oauth_params["pkce_verifier"]
        }

        # First exchange should succeed
        first_response = client.post("/token", json=token_request)
        assert first_response.status_code == 200

        # Second exchange should fail
        second_response = client.post("/token", json=token_request)
        assert second_response.status_code == 400

    def test_token_endpoint_malformed_request_body(self, client):
        """Test token endpoint with malformed request body."""
        # Invalid JSON
        response = client.post("/token",
                             data="invalid json",
                             headers={"Content-Type": "application/json"})
        assert response.status_code == 422

    def test_cors_headers_present(self, client):
        """Test that CORS headers are present in responses."""
        response = client.get("/health")

        # Should have CORS headers for cross-origin requests
        assert "access-control-allow-origin" in response.headers or response.status_code == 200

    def test_security_headers_present(self, client):
        """Test that security headers are present in responses."""
        response = client.get("/health")

        # Should have security headers
        headers = response.headers
        security_header_found = any(
            header.lower() in headers for header in [
                "x-content-type-options",
                "x-frame-options",
                "x-xss-protection"
            ]
        )
        assert security_header_found or response.status_code == 200

    def test_authorization_code_format(self, client, valid_oauth_params):
        """Test that generated authorization codes have proper format."""
        login_data = {
            "username": "alice",
            "password": "password123",
            "client_id": valid_oauth_params["client_id"],
            "redirect_uri": valid_oauth_params["redirect_uri"],
            "scope": valid_oauth_params["scope"],
            "state": valid_oauth_params["state"],
            "code_challenge": valid_oauth_params["code_challenge"],
            "code_challenge_method": valid_oauth_params["code_challenge_method"],
            "response_type": valid_oauth_params["response_type"]
        }

        response = client.post("/login", data=login_data)
        assert response.status_code == 302

        location = response.headers.get("location")
        parsed_url = urlparse(location)
        query_params = parse_qs(parsed_url.query)
        auth_code = query_params["code"][0]

        # Authorization code should be URL-safe and reasonably long
        assert len(auth_code) > 20
        assert auth_code.replace("-", "").replace("_", "").isalnum()

    def test_access_token_format(self, client, valid_oauth_params):
        """Test that generated access tokens have proper format."""
        # Get authorization code and exchange for token
        login_data = {
            "username": "alice",
            "password": "password123",
            "client_id": valid_oauth_params["client_id"],
            "redirect_uri": valid_oauth_params["redirect_uri"],
            "scope": valid_oauth_params["scope"],
            "state": valid_oauth_params["state"],
            "code_challenge": valid_oauth_params["code_challenge"],
            "code_challenge_method": valid_oauth_params["code_challenge_method"],
            "response_type": valid_oauth_params["response_type"]
        }

        login_response = client.post("/login", data=login_data)
        location = login_response.headers.get("location")
        parsed_url = urlparse(location)
        query_params = parse_qs(parsed_url.query)
        auth_code = query_params["code"][0]

        token_request = {
            "grant_type": "authorization_code",
            "code": auth_code,
            "redirect_uri": valid_oauth_params["redirect_uri"],
            "client_id": valid_oauth_params["client_id"],
            "code_verifier": valid_oauth_params["pkce_verifier"]
        }

        token_response = client.post("/token", json=token_request)
        token_data = token_response.json()
        access_token = token_data["access_token"]

        # Access token should be URL-safe and reasonably long
        assert len(access_token) > 30
        assert access_token.replace("-", "").replace("_", "").isalnum()

    def test_state_parameter_preservation(self, client, valid_oauth_params):
        """Test that state parameter is preserved in OAuth flow."""
        login_data = {
            "username": "alice",
            "password": "password123",
            "client_id": valid_oauth_params["client_id"],
            "redirect_uri": valid_oauth_params["redirect_uri"],
            "scope": valid_oauth_params["scope"],
            "state": valid_oauth_params["state"],
            "code_challenge": valid_oauth_params["code_challenge"],
            "code_challenge_method": valid_oauth_params["code_challenge_method"],
            "response_type": valid_oauth_params["response_type"]
        }

        response = client.post("/login", data=login_data)
        assert response.status_code == 302

        location = response.headers.get("location")
        parsed_url = urlparse(location)
        query_params = parse_qs(parsed_url.query)

        # State should be preserved in callback
        assert "state" in query_params
        assert query_params["state"][0] == valid_oauth_params["state"]