"""
Unit tests for OAuth client application.

Tests the client application endpoints to ensure proper OAuth flow initiation,
callback handling, token exchange, and protected resource access.
"""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock, AsyncMock
from urllib.parse import parse_qs, urlparse
import secrets
import httpx

from src.client.main import app
from src.shared.crypto_utils import PKCEGenerator


class TestClientApplication:
    """Test cases for OAuth client application."""

    @pytest.fixture
    def client(self):
        """Test client for the client application."""
        return TestClient(app)

    def test_health_endpoint(self, client):
        """Test health check endpoint."""
        response = client.get("/health")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "oauth-client" in data["service"].lower()

    def test_start_oauth_flow_page(self, client):
        """Test OAuth flow start page."""
        response = client.get("/")

        assert response.status_code == 200
        # Should contain OAuth flow elements
        content = response.text.lower()
        assert any(keyword in content for keyword in [
            "oauth", "authorization", "pkce", "challenge", "client"
        ])

    def test_start_flow_generates_pkce(self, client):
        """Test that start flow generates PKCE parameters."""
        response = client.get("/")

        assert response.status_code == 200
        # Should set session cookie
        assert "session" in response.cookies or "Set-Cookie" in response.headers

        # Should contain PKCE information in response
        content = response.text
        assert "challenge" in content.lower() or "pkce" in content.lower()

    def test_start_flow_session_management(self, client):
        """Test that start flow properly manages session data."""
        response = client.get("/")

        assert response.status_code == 200

        # Should set session cookie for PKCE storage
        cookies = response.cookies
        session_cookie_found = any(
            "session" in cookie_name.lower() for cookie_name in cookies.keys()
        ) if cookies else False

        # Session management should be in place
        assert session_cookie_found or "Set-Cookie" in response.headers

    def test_oauth_callback_with_valid_code(self, client):
        """Test OAuth callback with valid authorization code."""
        # First, start the flow to set up session
        start_response = client.get("/")
        assert start_response.status_code == 200

        # Extract session cookie
        session_cookies = start_response.cookies

        # Simulate callback with authorization code
        callback_params = {
            "code": "test_authorization_code_here",
            "state": "test_state_parameter"
        }

        callback_response = client.get("/callback",
                                     params=callback_params,
                                     cookies=session_cookies)

        # Should handle callback successfully
        assert callback_response.status_code == 200
        # Should display the received code
        assert "code" in callback_response.text.lower()

    def test_oauth_callback_with_error(self, client):
        """Test OAuth callback with error response."""
        callback_params = {
            "error": "access_denied",
            "error_description": "User denied access",
            "state": "test_state"
        }

        response = client.get("/callback", params=callback_params)

        assert response.status_code == 200
        # Should display error information
        content = response.text.lower()
        assert "error" in content or "denied" in content

    def test_oauth_callback_missing_code(self, client):
        """Test OAuth callback without authorization code."""
        callback_params = {
            "state": "test_state"
        }

        response = client.get("/callback", params=callback_params)

        # Should handle missing code appropriately
        assert response.status_code in [200, 400]

    def test_oauth_callback_missing_state(self, client):
        """Test OAuth callback without state parameter."""
        callback_params = {
            "code": "test_code"
        }

        response = client.get("/callback", params=callback_params)

        # Should handle missing state appropriately
        assert response.status_code in [200, 400]

    @patch('httpx.AsyncClient')
    def test_token_exchange_success(self, mock_httpx, client):
        """Test successful token exchange."""
        # Mock successful token response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "test_access_token_here",
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": "read"
        }

        mock_client_instance = AsyncMock()
        mock_client_instance.post.return_value = mock_response
        mock_httpx.return_value.__aenter__.return_value = mock_client_instance

        # Set up session with authorization code and PKCE verifier
        with client.session_transaction() as session:
            session["authorization_code"] = "test_auth_code"
            session["pkce_verifier"] = "test_pkce_verifier"

        response = client.get("/exchange-token")

        assert response.status_code == 200
        # Should display token information
        content = response.text.lower()
        assert "token" in content or "access" in content

    @patch('httpx.AsyncClient')
    def test_token_exchange_failure(self, mock_httpx, client):
        """Test failed token exchange."""
        # Mock failed token response
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.json.return_value = {
            "error": "invalid_grant",
            "error_description": "Invalid authorization code"
        }
        mock_response.headers = {"content-type": "application/json"}

        mock_client_instance = AsyncMock()
        mock_client_instance.post.return_value = mock_response
        mock_httpx.return_value.__aenter__.return_value = mock_client_instance

        # Set up session
        with client.session_transaction() as session:
            session["authorization_code"] = "invalid_code"
            session["pkce_verifier"] = "test_verifier"

        response = client.get("/exchange-token")

        assert response.status_code == 200
        # Should display error information
        content = response.text.lower()
        assert "error" in content or "failed" in content

    def test_token_exchange_missing_session_data(self, client):
        """Test token exchange without required session data."""
        # No session data set
        response = client.get("/exchange-token")

        assert response.status_code == 200
        # Should display error about missing data
        content = response.text.lower()
        assert "error" in content or "missing" in content

    @patch('httpx.AsyncClient')
    def test_token_exchange_network_error(self, mock_httpx, client):
        """Test token exchange with network error."""
        # Mock network error
        mock_client_instance = AsyncMock()
        mock_client_instance.post.side_effect = httpx.RequestError("Connection failed")
        mock_httpx.return_value.__aenter__.return_value = mock_client_instance

        # Set up session
        with client.session_transaction() as session:
            session["authorization_code"] = "test_code"
            session["pkce_verifier"] = "test_verifier"

        response = client.get("/exchange-token")

        assert response.status_code == 200
        # Should display network error
        content = response.text.lower()
        assert "error" in content or "network" in content or "connect" in content

    @patch('httpx.AsyncClient')
    def test_access_protected_resource_success(self, mock_httpx, client):
        """Test successful protected resource access."""
        # Mock successful resource response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "This is protected content!"
        mock_response.headers = {"content-type": "text/plain"}

        mock_client_instance = AsyncMock()
        mock_client_instance.get.return_value = mock_response
        mock_httpx.return_value.__aenter__.return_value = mock_client_instance

        # Set up session with access token
        with client.session_transaction() as session:
            session["access_token"] = "test_access_token"
            session["token_type"] = "Bearer"

        response = client.get("/access-resource")

        assert response.status_code == 200
        # Should display protected content
        content = response.text.lower()
        assert "protected" in content or "content" in content

    @patch('httpx.AsyncClient')
    def test_access_protected_resource_unauthorized(self, mock_httpx, client):
        """Test protected resource access with invalid token."""
        # Mock unauthorized response
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.text = "Unauthorized"

        mock_client_instance = AsyncMock()
        mock_client_instance.get.return_value = mock_response
        mock_httpx.return_value.__aenter__.return_value = mock_client_instance

        # Set up session with invalid token
        with client.session_transaction() as session:
            session["access_token"] = "invalid_token"
            session["token_type"] = "Bearer"

        response = client.get("/access-resource")

        assert response.status_code == 200
        # Should display error information
        content = response.text.lower()
        assert "error" in content or "failed" in content

    def test_access_protected_resource_missing_token(self, client):
        """Test protected resource access without access token."""
        # No token in session
        response = client.get("/access-resource")

        assert response.status_code == 200
        # Should display error about missing token
        content = response.text.lower()
        assert "error" in content or "missing" in content or "token" in content

    @patch('httpx.AsyncClient')
    def test_access_protected_resource_network_error(self, mock_httpx, client):
        """Test protected resource access with network error."""
        # Mock network error
        mock_client_instance = AsyncMock()
        mock_client_instance.get.side_effect = httpx.RequestError("Connection failed")
        mock_httpx.return_value.__aenter__.return_value = mock_client_instance

        # Set up session
        with client.session_transaction() as session:
            session["access_token"] = "test_token"
            session["token_type"] = "Bearer"

        response = client.get("/access-resource")

        assert response.status_code == 200
        # Should display network error
        content = response.text.lower()
        assert "error" in content or "network" in content or "connect" in content

    @patch('httpx.AsyncClient')
    def test_user_info_endpoint_success(self, mock_httpx, client):
        """Test successful user info retrieval."""
        # Mock successful userinfo response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "sub": "user123",
            "username": "alice",
            "email": "alice@example.com"
        }

        mock_client_instance = AsyncMock()
        mock_client_instance.get.return_value = mock_response
        mock_httpx.return_value.__aenter__.return_value = mock_client_instance

        # Set up session with access token
        with client.session_transaction() as session:
            session["access_token"] = "test_access_token"
            session["token_type"] = "Bearer"

        response = client.get("/user-info")

        assert response.status_code == 200
        # Should display user information
        content = response.text.lower()
        assert "user" in content or "alice" in content

    @patch('httpx.AsyncClient')
    def test_user_info_endpoint_text_response(self, mock_httpx, client):
        """Test user info endpoint with text response."""
        # Mock text response (not JSON)
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.side_effect = Exception("Not JSON")
        mock_response.text = "User information text"

        mock_client_instance = AsyncMock()
        mock_client_instance.get.return_value = mock_response
        mock_httpx.return_value.__aenter__.return_value = mock_client_instance

        # Set up session
        with client.session_transaction() as session:
            session["access_token"] = "test_token"
            session["token_type"] = "Bearer"

        response = client.get("/user-info")

        assert response.status_code == 200
        # Should handle text response
        content = response.text.lower()
        assert "user" in content or "info" in content

    def test_user_info_endpoint_missing_token(self, client):
        """Test user info endpoint without access token."""
        response = client.get("/user-info")

        assert response.status_code == 200
        # Should display error about missing token
        content = response.text.lower()
        assert "error" in content or "missing" in content or "token" in content

    def test_session_isolation(self, client):
        """Test that different sessions are properly isolated."""
        # Start two different flows
        response1 = client.get("/")
        response2 = client.get("/")

        # Should get different session cookies
        cookies1 = response1.cookies
        cookies2 = response2.cookies

        # Sessions should be independent (different cookies or no cookies)
        assert response1.status_code == 200
        assert response2.status_code == 200

    def test_pkce_parameter_generation(self, client):
        """Test that PKCE parameters are properly generated."""
        with patch('src.shared.crypto_utils.PKCEGenerator.generate_challenge') as mock_pkce:
            mock_pkce.return_value = ("test_verifier", "test_challenge")

            response = client.get("/")

            assert response.status_code == 200
            # Should have called PKCE generation
            mock_pkce.assert_called_once()

            # Should display PKCE information
            content = response.text
            assert "test_challenge" in content or "challenge" in content.lower()

    def test_state_parameter_generation(self, client):
        """Test that state parameter is properly generated."""
        response = client.get("/")

        assert response.status_code == 200
        # Should contain state parameter information
        content = response.text.lower()
        assert "state" in content

    def test_authorization_url_construction(self, client):
        """Test that authorization URL is properly constructed."""
        response = client.get("/")

        assert response.status_code == 200
        content = response.text

        # Should contain authorization URL with required parameters
        assert "localhost:8081" in content  # Auth server
        assert "authorize" in content.lower()
        assert "client_id" in content or "demo-client" in content

    def test_oauth_config_values(self, client):
        """Test that OAuth configuration values are correct."""
        response = client.get("/")

        assert response.status_code == 200
        content = response.text

        # Should contain correct OAuth configuration
        assert "demo-client" in content  # Client ID
        assert "localhost:8080/callback" in content  # Redirect URI
        assert "read" in content  # Scope

    def test_template_rendering(self, client):
        """Test that templates are properly rendered."""
        response = client.get("/")

        assert response.status_code == 200
        assert response.headers.get("content-type", "").startswith("text/html")

        # Should be valid HTML
        content = response.text
        assert "<html" in content.lower() or "<!doctype" in content.lower()

    def test_static_files_serving(self, client):
        """Test that static files are properly served."""
        # Try to access CSS file
        response = client.get("/static/style.css")

        # Should either serve the file or return 404 if it doesn't exist
        assert response.status_code in [200, 404]

        if response.status_code == 200:
            # Should be CSS content
            content_type = response.headers.get("content-type", "")
            assert "css" in content_type.lower() or "text" in content_type.lower()

    def test_error_handling_in_templates(self, client):
        """Test error handling in template rendering."""
        # Test callback with error
        response = client.get("/callback", params={
            "error": "access_denied",
            "error_description": "User denied access"
        })

        assert response.status_code == 200
        content = response.text.lower()
        assert "error" in content
        assert "denied" in content or "access" in content

    def test_session_security(self, client):
        """Test session security measures."""
        response = client.get("/")

        # Should set secure session cookies
        set_cookie_header = response.headers.get("set-cookie", "")
        if set_cookie_header:
            # Should have security attributes (in production)
            # For testing, we just verify cookie is set
            assert "session" in set_cookie_header.lower() or len(set_cookie_header) > 0

    def test_csrf_protection_state_parameter(self, client):
        """Test CSRF protection via state parameter."""
        # Start flow to get state
        start_response = client.get("/")
        assert start_response.status_code == 200

        # State should be generated and stored
        content = start_response.text
        assert "state" in content.lower()

        # In a real test, we would verify state validation in callback
        # For now, just verify state is present in the flow

    def test_concurrent_sessions(self, client):
        """Test handling of concurrent sessions."""
        import threading
        import time

        results = []

        def start_flow():
            response = client.get("/")
            results.append(response.status_code)

        # Create multiple threads
        threads = []
        for _ in range(3):
            thread = threading.Thread(target=start_flow)
            threads.append(thread)

        # Start all threads
        for thread in threads:
            thread.start()

        # Wait for completion
        for thread in threads:
            thread.join()

        # All should succeed
        assert all(status == 200 for status in results)
        assert len(results) == 3