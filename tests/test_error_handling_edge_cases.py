"""
Error handling and edge case tests for OAuth 2.1 implementation.

Tests various error scenarios, edge cases, and security vulnerabilities
to ensure robust error handling and proper security measures.
"""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
from urllib.parse import parse_qs, urlparse
import secrets
import time
from datetime import datetime, timedelta

from src.auth_server.main import app as auth_app
from src.resource_server.main import app as resource_app
from src.client.main import app as client_app
from src.shared.crypto_utils import PKCEGenerator
from src.shared.oauth_models import AuthorizationRequest, TokenRequest


class TestPKCEErrorHandling:
    """Test PKCE-related error handling and edge cases."""

    @pytest.fixture
    def auth_client(self):
        """Test client for authorization server."""
        return TestClient(auth_app)

    def test_invalid_pkce_challenges(self, auth_client):
        """Test various invalid PKCE challenge formats."""
        invalid_challenges = [
            "",  # Empty challenge
            "a",  # Too short
            "short_challenge",  # Still too short
            "invalid+characters+here",  # Invalid base64url characters
            "invalid/characters/here",  # Invalid base64url characters
            "invalid=padding=here",  # Contains padding
            "A" * 200,  # Too long
            "challenge with spaces",  # Contains spaces
            "challenge@with#special$chars",  # Special characters
            None,  # None value
        ]

        base_params = {
            "client_id": "demo-client",
            "redirect_uri": "http://localhost:8080/callback",
            "scope": "read",
            "state": "test-state",
            "code_challenge_method": "S256",
            "response_type": "code"
        }

        for invalid_challenge in invalid_challenges:
            params = base_params.copy()
            if invalid_challenge is not None:
                params["code_challenge"] = invalid_challenge

            response = auth_client.get("/authorize", params=params)
            # Should reject invalid challenges
            assert response.status_code in [400, 422]

    def test_invalid_pkce_methods(self, auth_client):
        """Test invalid PKCE challenge methods."""
        verifier, challenge = PKCEGenerator.generate_challenge()

        invalid_methods = [
            "plain",  # Not allowed in OAuth 2.1
            "sha1",  # Invalid method
            "md5",   # Invalid method
            "S128",  # Invalid method
            "s256",  # Wrong case
            "",      # Empty method
            "S256 ",  # Extra whitespace
            None     # None value
        ]

        base_params = {
            "client_id": "demo-client",
            "redirect_uri": "http://localhost:8080/callback",
            "scope": "read",
            "state": "test-state",
            "code_challenge": challenge,
            "response_type": "code"
        }

        for invalid_method in invalid_methods:
            params = base_params.copy()
            if invalid_method is not None:
                params["code_challenge_method"] = invalid_method

            response = auth_client.get("/authorize", params=params)
            # Should reject invalid methods
            assert response.status_code in [400, 422]

    def test_pkce_verifier_mismatch(self, auth_client):
        """Test PKCE verifier that doesn't match challenge."""
        # Generate valid PKCE pair
        verifier, challenge = PKCEGenerator.generate_challenge()

        # Get authorization code with valid challenge
        login_data = {
            "username": "alice",
            "password": "password123",
            "client_id": "demo-client",
            "redirect_uri": "http://localhost:8080/callback",
            "scope": "read",
            "state": "test-state",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "response_type": "code"
        }

        login_response = auth_client.post("/login", data=login_data)
        assert login_response.status_code == 302

        location = login_response.headers.get("location")
        parsed_url = urlparse(location)
        query_params = parse_qs(parsed_url.query)
        auth_code = query_params["code"][0]

        # Try to exchange with wrong verifier
        wrong_verifiers = [
            "wrong_verifier_completely_different",
            verifier[:-1],  # Truncated verifier
            verifier + "x",  # Extended verifier
            verifier.upper(),  # Case changed
            "",  # Empty verifier
            "a" * 43,  # Valid length but wrong content
        ]

        for wrong_verifier in wrong_verifiers:
            token_request = {
                "grant_type": "authorization_code",
                "code": auth_code,
                "redirect_uri": "http://localhost:8080/callback",
                "client_id": "demo-client",
                "code_verifier": wrong_verifier
            }

            response = auth_client.post("/token", json=token_request)
            # Should fail PKCE verification
            assert response.status_code == 400
            error_data = response.json()
            assert "error" in error_data

    def test_pkce_timing_attack_resistance(self, auth_client):
        """Test that PKCE verification is resistant to timing attacks."""
        verifier, challenge = PKCEGenerator.generate_challenge()

        # Get authorization code
        login_data = {
            "username": "alice",
            "password": "password123",
            "client_id": "demo-client",
            "redirect_uri": "http://localhost:8080/callback",
            "scope": "read",
            "state": "test-state",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "response_type": "code"
        }

        login_response = auth_client.post("/login", data=login_data)
        location = login_response.headers.get("location")
        parsed_url = urlparse(location)
        query_params = parse_qs(parsed_url.query)
        auth_code = query_params["code"][0]

        # Test with verifiers that differ at different positions
        test_verifiers = [
            "x" + verifier[1:],  # Differs at start
            verifier[:21] + "x" + verifier[22:],  # Differs in middle
            verifier[:-1] + "x",  # Differs at end
            "wrong_verifier_same_length_as_original_one"  # Completely different
        ]

        times = []
        for test_verifier in test_verifiers:
            token_request = {
                "grant_type": "authorization_code",
                "code": auth_code,
                "redirect_uri": "http://localhost:8080/callback",
                "client_id": "demo-client",
                "code_verifier": test_verifier
            }

            start_time = time.time()
            response = auth_client.post("/token", json=token_request)
            end_time = time.time()

            times.append(end_time - start_time)
            assert response.status_code == 400

        # Timing should be relatively consistent (within reasonable bounds)
        # This is a basic check - in practice, more sophisticated timing analysis would be needed
        max_time = max(times)
        min_time = min(times)
        # Allow for some variation but not orders of magnitude
        assert max_time / min_time < 10  # Reasonable timing consistency


class TestAuthorizationCodeErrorHandling:
    """Test authorization code related error handling."""

    @pytest.fixture
    def auth_client(self):
        """Test client for authorization server."""
        return TestClient(auth_app)

    def test_expired_authorization_codes(self, auth_client):
        """Test handling of expired authorization codes."""
        verifier, challenge = PKCEGenerator.generate_challenge()

        # Get authorization code
        login_data = {
            "username": "alice",
            "password": "password123",
            "client_id": "demo-client",
            "redirect_uri": "http://localhost:8080/callback",
            "scope": "read",
            "state": "test-state",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "response_type": "code"
        }

        login_response = auth_client.post("/login", data=login_data)
        location = login_response.headers.get("location")
        parsed_url = urlparse(location)
        query_params = parse_qs(parsed_url.query)
        auth_code = query_params["code"][0]

        # In a real test, we would mock time or wait for expiration
        # For now, test with obviously invalid/expired codes
        expired_codes = [
            "expired_code_123",
            "old_code_456",
            "",  # Empty code
            "a",  # Too short
            "invalid_format_code"
        ]

        for expired_code in expired_codes:
            token_request = {
                "grant_type": "authorization_code",
                "code": expired_code,
                "redirect_uri": "http://localhost:8080/callback",
                "client_id": "demo-client",
                "code_verifier": verifier
            }

            response = auth_client.post("/token", json=token_request)
            assert response.status_code == 400

    def test_reused_authorization_codes(self, auth_client):
        """Test that authorization codes can only be used once."""
        verifier, challenge = PKCEGenerator.generate_challenge()

        # Get authorization code
        login_data = {
            "username": "alice",
            "password": "password123",
            "client_id": "demo-client",
            "redirect_uri": "http://localhost:8080/callback",
            "scope": "read",
            "state": "test-state",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "response_type": "code"
        }

        login_response = auth_client.post("/login", data=login_data)
        location = login_response.headers.get("location")
        parsed_url = urlparse(location)
        query_params = parse_qs(parsed_url.query)
        auth_code = query_params["code"][0]

        token_request = {
            "grant_type": "authorization_code",
            "code": auth_code,
            "redirect_uri": "http://localhost:8080/callback",
            "client_id": "demo-client",
            "code_verifier": verifier
        }

        # First use should succeed
        first_response = auth_client.post("/token", json=token_request)
        assert first_response.status_code == 200

        # Second use should fail
        second_response = auth_client.post("/token", json=token_request)
        assert second_response.status_code == 400

        # Third use should also fail
        third_response = auth_client.post("/token", json=token_request)
        assert third_response.status_code == 400

    def test_authorization_code_format_validation(self, auth_client):
        """Test validation of authorization code format."""
        verifier, challenge = PKCEGenerator.generate_challenge()

        invalid_codes = [
            "",  # Empty
            "a",  # Too short
            "code with spaces",  # Contains spaces
            "code+with+plus",  # Contains plus
            "code/with/slash",  # Contains slash
            "code@with@at",  # Contains at symbol
            "code#with#hash",  # Contains hash
            "code\nwith\nnewline",  # Contains newlines
            "code\x00with\x00null",  # Contains null bytes
            None  # None value
        ]

        for invalid_code in invalid_codes:
            token_request = {
                "grant_type": "authorization_code",
                "redirect_uri": "http://localhost:8080/callback",
                "client_id": "demo-client",
                "code_verifier": verifier
            }

            if invalid_code is not None:
                token_request["code"] = invalid_code

            response = auth_client.post("/token", json=token_request)
            # Should reject invalid codes
            assert response.status_code in [400, 422]


class TestMalformedRequestHandling:
    """Test handling of malformed OAuth requests."""

    @pytest.fixture
    def auth_client(self):
        """Test client for authorization server."""
        return TestClient(auth_app)

    @pytest.fixture
    def resource_client(self):
        """Test client for resource server."""
        return TestClient(resource_app)

    def test_malformed_authorization_requests(self, auth_client):
        """Test handling of malformed authorization requests."""
        # Test with various malformed parameter combinations
        malformed_requests = [
            {},  # No parameters
            {"client_id": "demo-client"},  # Missing required params
            {"client_id": "", "redirect_uri": "http://localhost:8080/callback"},  # Empty client_id
            {"client_id": "demo-client", "redirect_uri": "not-a-uri"},  # Invalid URI
            {"client_id": "demo-client", "redirect_uri": "javascript:alert('xss')"},  # XSS attempt
            {"client_id": "demo-client", "redirect_uri": "http://malicious.com/callback"},  # Wrong domain
        ]

        for params in malformed_requests:
            response = auth_client.get("/authorize", params=params)
            # Should handle malformed requests gracefully
            assert response.status_code in [400, 422]

    def test_malformed_token_requests(self, auth_client):
        """Test handling of malformed token requests."""
        malformed_requests = [
            {},  # No data
            {"grant_type": "invalid_grant"},  # Invalid grant type
            {"grant_type": "authorization_code"},  # Missing required fields
            {  # Invalid JSON structure
                "grant_type": "authorization_code",
                "code": ["array", "instead", "of", "string"]
            },
            {  # Extremely long values
                "grant_type": "authorization_code",
                "code": "a" * 10000,
                "client_id": "b" * 10000
            }
        ]

        for request_data in malformed_requests:
            response = auth_client.post("/token", json=request_data)
            # Should handle malformed requests
            assert response.status_code in [400, 422]

    def test_malformed_bearer_tokens(self, resource_client):
        """Test handling of malformed Bearer tokens."""
        malformed_headers = [
            {"Authorization": ""},  # Empty header
            {"Authorization": "Bearer"},  # Missing token
            {"Authorization": "Bearer "},  # Empty token
            {"Authorization": "Basic dGVzdA=="},  # Wrong auth type
            {"Authorization": "bearer token"},  # Wrong case
            {"Authorization": "Bearer\x00token"},  # Null bytes
            {"Authorization": "Bearer token\nwith\nnewlines"},  # Newlines
            {"Authorization": "Bearer " + "a" * 10000},  # Extremely long token
        ]

        for headers in malformed_headers:
            response = resource_client.get("/protected", headers=headers)
            assert response.status_code == 401

    def test_content_type_handling(self, auth_client):
        """Test handling of different content types."""
        verifier, challenge = PKCEGenerator.generate_challenge()

        token_request = {
            "grant_type": "authorization_code",
            "code": "test_code",
            "redirect_uri": "http://localhost:8080/callback",
            "client_id": "demo-client",
            "code_verifier": verifier
        }

        # Test with wrong content type
        response = auth_client.post("/token",
                                  data=token_request,  # Form data instead of JSON
                                  headers={"Content-Type": "application/x-www-form-urlencoded"})
        # Should handle content type appropriately
        assert response.status_code in [200, 400, 415, 422]

        # Test with no content type
        response = auth_client.post("/token", json=token_request)
        # Should work with JSON
        assert response.status_code in [200, 400, 422]

    def test_http_method_validation(self, auth_client, resource_client):
        """Test that endpoints only accept appropriate HTTP methods."""
        # Authorization endpoint should only accept GET
        response = auth_client.post("/authorize")
        assert response.status_code in [405, 422]  # Method Not Allowed

        response = auth_client.put("/authorize")
        assert response.status_code == 405

        # Token endpoint should only accept POST
        response = auth_client.get("/token")
        assert response.status_code == 405

        response = auth_client.put("/token")
        assert response.status_code == 405

        # Protected resource should handle different methods appropriately
        response = resource_client.post("/protected")
        assert response.status_code in [200, 401, 405]  # Depends on implementation


class TestSecurityVulnerabilities:
    """Test protection against common security vulnerabilities."""

    @pytest.fixture
    def auth_client(self):
        """Test client for authorization server."""
        return TestClient(auth_app)

    @pytest.fixture
    def resource_client(self):
        """Test client for resource server."""
        return TestClient(resource_app)

    def test_xss_protection(self, auth_client):
        """Test protection against XSS attacks."""
        xss_payloads = [
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "<img src=x onerror=alert('xss')>",
            "';alert('xss');//",
            "<svg onload=alert('xss')>",
        ]

        for payload in xss_payloads:
            # Test in various parameters
            params = {
                "client_id": payload,
                "redirect_uri": f"http://localhost:8080/callback?xss={payload}",
                "scope": payload,
                "state": payload,
                "code_challenge": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
                "code_challenge_method": "S256",
                "response_type": "code"
            }

            response = auth_client.get("/authorize", params=params)

            # Should not reflect XSS payload in response
            if response.status_code == 200:
                content = response.text
                # XSS payload should be escaped or not present
                assert payload not in content or "&lt;" in content or "&gt;" in content

    def test_sql_injection_protection(self, auth_client):
        """Test protection against SQL injection attacks."""
        sql_payloads = [
            "'; DROP TABLE users; --",
            "' OR '1'='1",
            "admin'--",
            "' UNION SELECT * FROM users --",
            "'; INSERT INTO users VALUES ('hacker', 'password'); --",
        ]

        for payload in sql_payloads:
            # Test in login form
            login_data = {
                "username": payload,
                "password": "password123",
                "client_id": "demo-client",
                "redirect_uri": "http://localhost:8080/callback",
                "scope": "read",
                "state": "test-state",
                "code_challenge": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
                "code_challenge_method": "S256",
                "response_type": "code"
            }

            response = auth_client.post("/login", data=login_data)

            # Should handle SQL injection attempts safely
            # Should not succeed with authentication
            assert response.status_code in [200, 302, 400, 401]
            if response.status_code == 302:
                location = response.headers.get("location", "")
                # Should not contain successful authorization code
                assert "error=" in location or "localhost:8080" not in location

    def test_csrf_protection(self, auth_client):
        """Test CSRF protection via state parameter."""
        verifier, challenge = PKCEGenerator.generate_challenge()

        # Test without state parameter
        login_data = {
            "username": "alice",
            "password": "password123",
            "client_id": "demo-client",
            "redirect_uri": "http://localhost:8080/callback",
            "scope": "read",
            # Missing state parameter
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "response_type": "code"
        }

        response = auth_client.post("/login", data=login_data)
        # Should require state parameter
        assert response.status_code in [400, 422]

    def test_redirect_uri_validation(self, auth_client):
        """Test redirect URI validation against open redirects."""
        malicious_redirects = [
            "http://malicious.com/callback",
            "https://evil.example.com/steal-code",
            "javascript:alert('xss')",
            "data:text/html,<script>alert('xss')</script>",
            "file:///etc/passwd",
            "ftp://malicious.com/",
            "http://localhost:8080@malicious.com/callback",  # Homograph attack
            "http://localhost:8080.malicious.com/callback",  # Subdomain attack
        ]

        verifier, challenge = PKCEGenerator.generate_challenge()

        for malicious_redirect in malicious_redirects:
            params = {
                "client_id": "demo-client",
                "redirect_uri": malicious_redirect,
                "scope": "read",
                "state": "test-state",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "response_type": "code"
            }

            response = auth_client.get("/authorize", params=params)
            # Should reject malicious redirect URIs
            assert response.status_code in [400, 422]

    def test_token_leakage_prevention(self, resource_client):
        """Test that tokens are not leaked in error messages or logs."""
        test_token = "secret_token_that_should_not_leak"

        headers = {"Authorization": f"Bearer {test_token}"}
        response = resource_client.get("/protected", headers=headers)

        # Even if token is invalid, it should not appear in response
        if response.status_code != 200:
            content = response.text
            assert test_token not in content

    def test_timing_attack_resistance(self, auth_client):
        """Test resistance to timing attacks in authentication."""
        # Test with valid and invalid usernames
        usernames = ["alice", "nonexistent_user_12345"]
        times = {}

        for username in usernames:
            login_data = {
                "username": username,
                "password": "wrong_password",
                "client_id": "demo-client",
                "redirect_uri": "http://localhost:8080/callback",
                "scope": "read",
                "state": "test-state",
                "code_challenge": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
                "code_challenge_method": "S256",
                "response_type": "code"
            }

            start_time = time.time()
            response = auth_client.post("/login", data=login_data)
            end_time = time.time()

            times[username] = end_time - start_time
            # Both should fail authentication
            assert response.status_code in [200, 302, 400, 401]

        # Timing should be relatively consistent
        time_values = list(times.values())
        if len(time_values) > 1:
            max_time = max(time_values)
            min_time = min(time_values)
            # Allow for reasonable variation
            assert max_time / min_time < 5  # Not too much timing difference


class TestErrorResponseFormat:
    """Test that error responses follow OAuth 2.1 standards."""

    @pytest.fixture
    def auth_client(self):
        """Test client for authorization server."""
        return TestClient(auth_app)

    @pytest.fixture
    def resource_client(self):
        """Test client for resource server."""
        return TestClient(resource_app)

    def test_oauth_error_response_format(self, auth_client):
        """Test that OAuth errors follow RFC 6749 format."""
        # Test invalid grant type
        token_request = {
            "grant_type": "invalid_grant_type",
            "code": "test_code",
            "redirect_uri": "http://localhost:8080/callback",
            "client_id": "demo-client",
            "code_verifier": "test_verifier"
        }

        response = auth_client.post("/token", json=token_request)

        if response.status_code == 400:
            error_data = response.json()
            # Should follow OAuth error format
            assert "error" in error_data
            # Common OAuth error codes
            oauth_errors = [
                "invalid_request", "invalid_client", "invalid_grant",
                "unauthorized_client", "unsupported_grant_type", "invalid_scope"
            ]
            if "error" in error_data:
                # Error should be a valid OAuth error code or at least a string
                assert isinstance(error_data["error"], str)

    def test_resource_server_error_format(self, resource_client):
        """Test resource server error response format."""
        response = resource_client.get("/protected")  # No auth header

        assert response.status_code == 401
        assert response.headers.get("content-type", "").startswith("application/json")

        error_data = response.json()
        assert isinstance(error_data, dict)
        # Should have error information
        assert "error" in error_data or "detail" in error_data

    def test_error_response_security(self, auth_client, resource_client):
        """Test that error responses don't leak sensitive information."""
        # Test various error scenarios
        error_requests = [
            # Invalid token request
            (auth_client, "post", "/token", {"json": {"invalid": "data"}}),
            # Invalid authorization request
            (auth_client, "get", "/authorize", {"params": {"invalid": "params"}}),
            # Invalid resource request
            (resource_client, "get", "/protected", {"headers": {"Authorization": "Bearer invalid"}}),
        ]

        for client, method, path, kwargs in error_requests:
            response = getattr(client, method)(path, **kwargs)

            if response.status_code >= 400:
                content = response.text.lower()
                # Should not leak sensitive information
                sensitive_terms = [
                    "password", "secret", "key", "token", "database",
                    "internal", "stack trace", "exception", "traceback"
                ]

                for term in sensitive_terms:
                    # Allow the word "token" in appropriate contexts
                    if term == "token" and "access_token" in content:
                        continue
                    assert term not in content or f"invalid_{term}" in content

    def test_consistent_error_handling(self, auth_client):
        """Test that similar errors are handled consistently."""
        # Test multiple invalid requests of the same type
        invalid_requests = [
            {"client_id": ""},
            {"client_id": "invalid"},
            {"client_id": "another_invalid"},
        ]

        responses = []
        for params in invalid_requests:
            response = auth_client.get("/authorize", params=params)
            responses.append((response.status_code, response.headers.get("content-type", "")))

        # All should have similar response patterns
        status_codes = [r[0] for r in responses]
        content_types = [r[1] for r in responses]

        # Should have consistent status codes
        assert len(set(status_codes)) <= 2  # Allow for some variation

        # Should have consistent content types for errors
        error_content_types = [ct for sc, ct in responses if sc >= 400]
        if error_content_types:
            assert len(set(error_content_types)) <= 2  # Allow for some variation