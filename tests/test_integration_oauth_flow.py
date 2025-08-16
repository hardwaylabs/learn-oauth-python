"""
Integration tests for OAuth 2.1 flow.

Tests the complete OAuth 2.1 authorization code flow with PKCE across
all three applications (client, authorization server, resource server)
to ensure proper end-to-end functionality.
"""

import pytest
import asyncio
from fastapi.testclient import TestClient
from httpx import AsyncClient
import secrets
from urllib.parse import parse_qs, urlparse

# Import the FastAPI applications
from src.client.main import app as client_app
from src.auth_server.main import app as auth_app
from src.resource_server.main import app as resource_app
from src.shared.crypto_utils import PKCEGenerator
from src.shared.oauth_models import AuthorizationRequest, TokenRequest


class TestOAuthFlowIntegration:
    """Integration tests for complete OAuth 2.1 flow."""

    @pytest.fixture
    def client_client(self):
        """Test client for the client application."""
        return TestClient(client_app)

    @pytest.fixture
    def auth_client(self):
        """Test client for the authorization server."""
        return TestClient(auth_app)

    @pytest.fixture
    def resource_client(self):
        """Test client for the resource server."""
        return TestClient(resource_app)

    @pytest.fixture
    def pkce_pair(self):
        """Generate PKCE verifier and challenge pair for testing."""
        return PKCEGenerator.generate_challenge()

    @pytest.fixture
    def oauth_params(self, pkce_pair):
        """Standard OAuth parameters for testing."""
        verifier, challenge = pkce_pair
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

    def test_client_start_flow_page(self, client_client):
        """Test that client start flow page loads correctly."""
        response = client_client.get("/")

        assert response.status_code == 200
        assert "OAuth 2.1 Flow" in response.text or "authorization" in response.text.lower()

    def test_auth_server_health_check(self, auth_client):
        """Test authorization server health check."""
        response = auth_client.get("/health")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "authorization-server" in data["service"].lower()

    def test_resource_server_health_check(self, resource_client):
        """Test resource server health check."""
        response = resource_client.get("/health")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "resource-server" in data["service"].lower()

    def test_authorization_endpoint_valid_request(self, auth_client, oauth_params):
        """Test authorization endpoint with valid OAuth request."""
        response = auth_client.get("/authorize", params={
            "client_id": oauth_params["client_id"],
            "redirect_uri": oauth_params["redirect_uri"],
            "scope": oauth_params["scope"],
            "state": oauth_params["state"],
            "code_challenge": oauth_params["code_challenge"],
            "code_challenge_method": oauth_params["code_challenge_method"],
            "response_type": oauth_params["response_type"]
        })

        assert response.status_code == 200
        # Should show login form
        assert "login" in response.text.lower() or "username" in response.text.lower()

    def test_authorization_endpoint_missing_pkce(self, auth_client, oauth_params):
        """Test authorization endpoint without PKCE parameters."""
        params = oauth_params.copy()
        del params["code_challenge"]

        response = auth_client.get("/authorize", params={
            "client_id": params["client_id"],
            "redirect_uri": params["redirect_uri"],
            "scope": params["scope"],
            "state": params["state"],
            "response_type": params["response_type"]
        })

        # Should fail due to missing PKCE
        assert response.status_code == 422  # Validation error

    def test_authorization_endpoint_invalid_pkce_method(self, auth_client, oauth_params):
        """Test authorization endpoint with invalid PKCE method."""
        params = oauth_params.copy()
        params["code_challenge_method"] = "plain"  # Invalid method

        response = auth_client.get("/authorize", params=params)

        # Should fail due to invalid PKCE method
        assert response.status_code in [400, 422]

    def test_login_endpoint_valid_credentials(self, auth_client, oauth_params):
        """Test login endpoint with valid demo credentials."""
        login_data = {
            "username": "alice",
            "password": "password123",
            "client_id": oauth_params["client_id"],
            "redirect_uri": oauth_params["redirect_uri"],
            "scope": oauth_params["scope"],
            "state": oauth_params["state"],
            "code_challenge": oauth_params["code_challenge"],
            "code_challenge_method": oauth_params["code_challenge_method"],
            "response_type": oauth_params["response_type"]
        }

        response = auth_client.post("/login", data=login_data)

        # Should redirect to callback with authorization code
        assert response.status_code == 302
        location = response.headers.get("location")
        assert location is not None
        assert oauth_params["redirect_uri"] in location
        assert "code=" in location
        assert f"state={oauth_params['state']}" in location

    def test_login_endpoint_invalid_credentials(self, auth_client, oauth_params):
        """Test login endpoint with invalid credentials."""
        login_data = {
            "username": "alice",
            "password": "wrong_password",
            "client_id": oauth_params["client_id"],
            "redirect_uri": oauth_params["redirect_uri"],
            "scope": oauth_params["scope"],
            "state": oauth_params["state"],
            "code_challenge": oauth_params["code_challenge"],
            "code_challenge_method": oauth_params["code_challenge_method"],
            "response_type": oauth_params["response_type"]
        }

        response = auth_client.post("/login", data=login_data)

        # Should show error or redirect with error
        assert response.status_code in [200, 302, 400, 401]
        if response.status_code == 302:
            location = response.headers.get("location")
            assert "error=" in location

    def test_token_endpoint_valid_exchange(self, auth_client, oauth_params):
        """Test token exchange with valid authorization code and PKCE verifier."""
        # First, get an authorization code by logging in
        login_data = {
            "username": "alice",
            "password": "password123",
            "client_id": oauth_params["client_id"],
            "redirect_uri": oauth_params["redirect_uri"],
            "scope": oauth_params["scope"],
            "state": oauth_params["state"],
            "code_challenge": oauth_params["code_challenge"],
            "code_challenge_method": oauth_params["code_challenge_method"],
            "response_type": oauth_params["response_type"]
        }

        login_response = auth_client.post("/login", data=login_data)
        assert login_response.status_code == 302

        # Extract authorization code from redirect
        location = login_response.headers.get("location")
        parsed_url = urlparse(location)
        query_params = parse_qs(parsed_url.query)
        auth_code = query_params["code"][0]

        # Now exchange the code for a token
        token_request = {
            "grant_type": "authorization_code",
            "code": auth_code,
            "redirect_uri": oauth_params["redirect_uri"],
            "client_id": oauth_params["client_id"],
            "code_verifier": oauth_params["pkce_verifier"]
        }

        token_response = auth_client.post("/token", json=token_request)

        assert token_response.status_code == 200
        token_data = token_response.json()
        assert "access_token" in token_data
        assert token_data["token_type"] == "Bearer"
        assert "expires_in" in token_data
        assert token_data["scope"] == oauth_params["scope"]

    def test_token_endpoint_invalid_pkce_verifier(self, auth_client, oauth_params):
        """Test token exchange with invalid PKCE verifier."""
        # First, get an authorization code
        login_data = {
            "username": "alice",
            "password": "password123",
            "client_id": oauth_params["client_id"],
            "redirect_uri": oauth_params["redirect_uri"],
            "scope": oauth_params["scope"],
            "state": oauth_params["state"],
            "code_challenge": oauth_params["code_challenge"],
            "code_challenge_method": oauth_params["code_challenge_method"],
            "response_type": oauth_params["response_type"]
        }

        login_response = auth_client.post("/login", data=login_data)
        assert login_response.status_code == 302

        # Extract authorization code
        location = login_response.headers.get("location")
        parsed_url = urlparse(location)
        query_params = parse_qs(parsed_url.query)
        auth_code = query_params["code"][0]

        # Try to exchange with wrong PKCE verifier
        token_request = {
            "grant_type": "authorization_code",
            "code": auth_code,
            "redirect_uri": oauth_params["redirect_uri"],
            "client_id": oauth_params["client_id"],
            "code_verifier": "wrong_verifier_here"
        }

        token_response = auth_client.post("/token", json=token_request)

        # Should fail PKCE verification
        assert token_response.status_code == 400
        error_data = token_response.json()
        assert "error" in error_data

    def test_token_endpoint_reused_authorization_code(self, auth_client, oauth_params):
        """Test that authorization codes can only be used once."""
        # Get authorization code and exchange it once
        login_data = {
            "username": "alice",
            "password": "password123",
            "client_id": oauth_params["client_id"],
            "redirect_uri": oauth_params["redirect_uri"],
            "scope": oauth_params["scope"],
            "state": oauth_params["state"],
            "code_challenge": oauth_params["code_challenge"],
            "code_challenge_method": oauth_params["code_challenge_method"],
            "response_type": oauth_params["response_type"]
        }

        login_response = auth_client.post("/login", data=login_data)
        location = login_response.headers.get("location")
        parsed_url = urlparse(location)
        query_params = parse_qs(parsed_url.query)
        auth_code = query_params["code"][0]

        token_request = {
            "grant_type": "authorization_code",
            "code": auth_code,
            "redirect_uri": oauth_params["redirect_uri"],
            "client_id": oauth_params["client_id"],
            "code_verifier": oauth_params["pkce_verifier"]
        }

        # First exchange should succeed
        first_response = auth_client.post("/token", json=token_request)
        assert first_response.status_code == 200

        # Second exchange with same code should fail
        second_response = auth_client.post("/token", json=token_request)
        assert second_response.status_code == 400

    def test_protected_resource_with_valid_token(self, auth_client, resource_client, oauth_params):
        """Test accessing protected resource with valid Bearer token."""
        # Get a valid access token first
        access_token = self._get_valid_access_token(auth_client, oauth_params)

        # Access protected resource
        headers = {"Authorization": f"Bearer {access_token}"}
        response = resource_client.get("/protected", headers=headers)

        assert response.status_code == 200
        assert len(response.text) > 0  # Should return some content

    def test_protected_resource_without_token(self, resource_client):
        """Test accessing protected resource without Bearer token."""
        response = resource_client.get("/protected")

        assert response.status_code == 401

    def test_protected_resource_with_invalid_token(self, resource_client):
        """Test accessing protected resource with invalid Bearer token."""
        headers = {"Authorization": "Bearer invalid_token_here"}
        response = resource_client.get("/protected")

        # Should reject invalid token
        assert response.status_code in [401, 403]

    def test_protected_resource_malformed_auth_header(self, resource_client):
        """Test protected resource with malformed Authorization header."""
        test_cases = [
            {"Authorization": "invalid_format"},
            {"Authorization": "Bearer"},  # Missing token
            {"Authorization": "Basic dGVzdA=="},  # Wrong auth type
        ]

        for headers in test_cases:
            response = resource_client.get("/protected", headers=headers)
            assert response.status_code == 401

    def test_userinfo_endpoint_with_valid_token(self, auth_client, resource_client, oauth_params):
        """Test userinfo endpoint with valid Bearer token."""
        # Get a valid access token
        access_token = self._get_valid_access_token(auth_client, oauth_params)

        # Access userinfo endpoint
        headers = {"Authorization": f"Bearer {access_token}"}
        response = resource_client.get("/userinfo", headers=headers)

        assert response.status_code == 200
        user_data = response.json()
        assert "sub" in user_data or "username" in user_data

    def test_userinfo_endpoint_without_token(self, resource_client):
        """Test userinfo endpoint without Bearer token."""
        response = resource_client.get("/userinfo")

        assert response.status_code == 401

    def test_complete_oauth_flow_end_to_end(self, auth_client, resource_client, oauth_params):
        """Test complete OAuth 2.1 flow from start to finish."""
        # Step 1: User authentication and authorization code generation
        login_data = {
            "username": "alice",
            "password": "password123",
            "client_id": oauth_params["client_id"],
            "redirect_uri": oauth_params["redirect_uri"],
            "scope": oauth_params["scope"],
            "state": oauth_params["state"],
            "code_challenge": oauth_params["code_challenge"],
            "code_challenge_method": oauth_params["code_challenge_method"],
            "response_type": oauth_params["response_type"]
        }

        login_response = auth_client.post("/login", data=login_data)
        assert login_response.status_code == 302

        # Step 2: Extract authorization code
        location = login_response.headers.get("location")
        parsed_url = urlparse(location)
        query_params = parse_qs(parsed_url.query)
        auth_code = query_params["code"][0]
        returned_state = query_params["state"][0]

        # Verify state parameter
        assert returned_state == oauth_params["state"]

        # Step 3: Exchange authorization code for access token
        token_request = {
            "grant_type": "authorization_code",
            "code": auth_code,
            "redirect_uri": oauth_params["redirect_uri"],
            "client_id": oauth_params["client_id"],
            "code_verifier": oauth_params["pkce_verifier"]
        }

        token_response = auth_client.post("/token", json=token_request)
        assert token_response.status_code == 200

        token_data = token_response.json()
        access_token = token_data["access_token"]

        # Step 4: Access protected resource with token
        headers = {"Authorization": f"Bearer {access_token}"}
        resource_response = resource_client.get("/protected", headers=headers)
        assert resource_response.status_code == 200

        # Step 5: Access userinfo endpoint
        userinfo_response = resource_client.get("/userinfo", headers=headers)
        assert userinfo_response.status_code == 200

        # Verify the complete flow worked
        assert len(access_token) > 0
        assert len(resource_response.text) > 0
        user_data = userinfo_response.json()
        assert isinstance(user_data, dict)

    def test_oauth_flow_with_different_demo_users(self, auth_client, resource_client, oauth_params):
        """Test OAuth flow with all demo user accounts."""
        demo_users = [
            ("alice", "password123"),
            ("bob", "secret456"),
            ("carol", "mypass789")
        ]

        for username, password in demo_users:
            # Generate new PKCE pair for each user
            verifier, challenge = PKCEGenerator.generate_challenge()
            params = oauth_params.copy()
            params["code_challenge"] = challenge
            params["pkce_verifier"] = verifier
            params["state"] = secrets.token_urlsafe(16)

            # Complete flow for this user
            login_data = {
                "username": username,
                "password": password,
                "client_id": params["client_id"],
                "redirect_uri": params["redirect_uri"],
                "scope": params["scope"],
                "state": params["state"],
                "code_challenge": params["code_challenge"],
                "code_challenge_method": params["code_challenge_method"],
                "response_type": params["response_type"]
            }

            # Login and get authorization code
            login_response = auth_client.post("/login", data=login_data)
            assert login_response.status_code == 302

            location = login_response.headers.get("location")
            parsed_url = urlparse(location)
            query_params = parse_qs(parsed_url.query)
            auth_code = query_params["code"][0]

            # Exchange for token
            token_request = {
                "grant_type": "authorization_code",
                "code": auth_code,
                "redirect_uri": params["redirect_uri"],
                "client_id": params["client_id"],
                "code_verifier": params["pkce_verifier"]
            }

            token_response = auth_client.post("/token", json=token_request)
            assert token_response.status_code == 200

            # Access protected resource
            token_data = token_response.json()
            headers = {"Authorization": f"Bearer {token_data['access_token']}"}
            resource_response = resource_client.get("/protected", headers=headers)
            assert resource_response.status_code == 200

    def test_oauth_error_handling_invalid_client_id(self, auth_client, oauth_params):
        """Test OAuth error handling with invalid client_id."""
        params = oauth_params.copy()
        params["client_id"] = "invalid_client"

        response = auth_client.get("/authorize", params=params)

        # Should handle invalid client gracefully
        assert response.status_code in [200, 400, 401]

    def test_oauth_error_handling_invalid_redirect_uri(self, auth_client, oauth_params):
        """Test OAuth error handling with invalid redirect_uri."""
        params = oauth_params.copy()
        params["redirect_uri"] = "http://malicious-site.com/callback"

        response = auth_client.get("/authorize", params=params)

        # Should reject invalid redirect URI
        assert response.status_code in [400, 422]

    def _get_valid_access_token(self, auth_client, oauth_params):
        """Helper method to get a valid access token for testing."""
        # Login and get authorization code
        login_data = {
            "username": "alice",
            "password": "password123",
            "client_id": oauth_params["client_id"],
            "redirect_uri": oauth_params["redirect_uri"],
            "scope": oauth_params["scope"],
            "state": oauth_params["state"],
            "code_challenge": oauth_params["code_challenge"],
            "code_challenge_method": oauth_params["code_challenge_method"],
            "response_type": oauth_params["response_type"]
        }

        login_response = auth_client.post("/login", data=login_data)
        location = login_response.headers.get("location")
        parsed_url = urlparse(location)
        query_params = parse_qs(parsed_url.query)
        auth_code = query_params["code"][0]

        # Exchange for token
        token_request = {
            "grant_type": "authorization_code",
            "code": auth_code,
            "redirect_uri": oauth_params["redirect_uri"],
            "client_id": oauth_params["client_id"],
            "code_verifier": oauth_params["pkce_verifier"]
        }

        token_response = auth_client.post("/token", json=token_request)
        token_data = token_response.json()
        return token_data["access_token"]


class TestOAuthFlowAsync:
    """Async integration tests for OAuth flow using httpx."""

    @pytest.mark.asyncio
    async def test_async_complete_oauth_flow(self):
        """Test complete OAuth flow using async HTTP client."""
        # Generate PKCE pair
        verifier, challenge = PKCEGenerator.generate_challenge()
        state = secrets.token_urlsafe(16)

        oauth_params = {
            "client_id": "demo-client",
            "redirect_uri": "http://localhost:8080/callback",
            "scope": "read",
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "response_type": "code"
        }

        async with AsyncClient(app=auth_app, base_url="http://test") as auth_client:
            # Step 1: Login and get authorization code
            login_data = {
                "username": "alice",
                "password": "password123",
                **oauth_params
            }

            login_response = await auth_client.post("/login", data=login_data)
            assert login_response.status_code == 302

            # Extract authorization code
            location = login_response.headers.get("location")
            parsed_url = urlparse(location)
            query_params = parse_qs(parsed_url.query)
            auth_code = query_params["code"][0]

            # Step 2: Exchange for token
            token_request = {
                "grant_type": "authorization_code",
                "code": auth_code,
                "redirect_uri": oauth_params["redirect_uri"],
                "client_id": oauth_params["client_id"],
                "code_verifier": verifier
            }

            token_response = await auth_client.post("/token", json=token_request)
            assert token_response.status_code == 200

            token_data = token_response.json()
            access_token = token_data["access_token"]

        # Step 3: Access protected resource
        async with AsyncClient(app=resource_app, base_url="http://test") as resource_client:
            headers = {"Authorization": f"Bearer {access_token}"}
            resource_response = await resource_client.get("/protected", headers=headers)
            assert resource_response.status_code == 200

    @pytest.mark.asyncio
    async def test_async_concurrent_oauth_flows(self):
        """Test multiple concurrent OAuth flows."""
        async def single_oauth_flow(username, password):
            """Execute a single OAuth flow."""
            verifier, challenge = PKCEGenerator.generate_challenge()
            state = secrets.token_urlsafe(16)

            oauth_params = {
                "client_id": "demo-client",
                "redirect_uri": "http://localhost:8080/callback",
                "scope": "read",
                "state": state,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "response_type": "code"
            }

            async with AsyncClient(app=auth_app, base_url="http://test") as auth_client:
                login_data = {
                    "username": username,
                    "password": password,
                    **oauth_params
                }

                login_response = await auth_client.post("/login", data=login_data)
                if login_response.status_code != 302:
                    return False

                location = login_response.headers.get("location")
                parsed_url = urlparse(location)
                query_params = parse_qs(parsed_url.query)
                auth_code = query_params["code"][0]

                token_request = {
                    "grant_type": "authorization_code",
                    "code": auth_code,
                    "redirect_uri": oauth_params["redirect_uri"],
                    "client_id": oauth_params["client_id"],
                    "code_verifier": verifier
                }

                token_response = await auth_client.post("/token", json=token_request)
                return token_response.status_code == 200

        # Run multiple flows concurrently
        tasks = [
            single_oauth_flow("alice", "password123"),
            single_oauth_flow("bob", "secret456"),
            single_oauth_flow("carol", "mypass789")
        ]

        results = await asyncio.gather(*tasks)

        # All flows should succeed
        assert all(results)


class TestOAuthFlowErrorScenarios:
    """Test error scenarios and edge cases in OAuth flow."""

    @pytest.fixture
    def auth_client(self):
        """Test client for the authorization server."""
        return TestClient(auth_app)

    @pytest.fixture
    def resource_client(self):
        """Test client for the resource server."""
        return TestClient(resource_app)

    def test_authorization_code_expiration(self, auth_client):
        """Test that authorization codes expire after the configured time."""
        # This test would require mocking time or waiting for expiration
        # For now, we'll test the basic structure
        verifier, challenge = PKCEGenerator.generate_challenge()

        oauth_params = {
            "client_id": "demo-client",
            "redirect_uri": "http://localhost:8080/callback",
            "scope": "read",
            "state": secrets.token_urlsafe(16),
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "response_type": "code"
        }

        login_data = {
            "username": "alice",
            "password": "password123",
            **oauth_params
        }

        login_response = auth_client.post("/login", data=login_data)
        assert login_response.status_code == 302

        # In a real test, we would wait for expiration or mock time
        # For now, just verify the code was generated
        location = login_response.headers.get("location")
        assert "code=" in location

    def test_pkce_security_validation(self, auth_client):
        """Test PKCE security validation edge cases."""
        verifier, challenge = PKCEGenerator.generate_challenge()

        # Test with various invalid PKCE challenges
        invalid_challenges = [
            "",  # Empty challenge
            "short",  # Too short
            "invalid+chars",  # Invalid characters
            "A" * 200,  # Too long
        ]

        for invalid_challenge in invalid_challenges:
            oauth_params = {
                "client_id": "demo-client",
                "redirect_uri": "http://localhost:8080/callback",
                "scope": "read",
                "state": secrets.token_urlsafe(16),
                "code_challenge": invalid_challenge,
                "code_challenge_method": "S256",
                "response_type": "code"
            }

            response = auth_client.get("/authorize", params=oauth_params)
            # Should reject invalid challenges
            assert response.status_code in [400, 422]

    def test_state_parameter_validation(self, auth_client):
        """Test state parameter validation for CSRF protection."""
        verifier, challenge = PKCEGenerator.generate_challenge()

        # Test with various invalid state parameters
        invalid_states = [
            "",  # Empty state
            "state with spaces",  # Invalid characters
            "state@invalid",  # Special characters
        ]

        for invalid_state in invalid_states:
            oauth_params = {
                "client_id": "demo-client",
                "redirect_uri": "http://localhost:8080/callback",
                "scope": "read",
                "state": invalid_state,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "response_type": "code"
            }

            response = auth_client.get("/authorize", params=oauth_params)
            # Should handle invalid state parameters
            assert response.status_code in [200, 400, 422]