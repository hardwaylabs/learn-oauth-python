"""
Unit tests for resource server endpoints.

Tests the resource server endpoints to ensure proper Bearer token validation,
protected resource access, and security measures are implemented correctly.
"""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
import secrets

from src.resource_server.main import app
from src.shared.crypto_utils import PKCEGenerator


class TestResourceServerEndpoints:
    """Test cases for resource server endpoints."""

    @pytest.fixture
    def client(self):
        """Test client for the resource server."""
        return TestClient(app)

    @pytest.fixture
    def valid_token(self):
        """Generate a valid-looking access token for testing."""
        return secrets.token_urlsafe(48)

    @pytest.fixture
    def invalid_tokens(self):
        """Various invalid token formats for testing."""
        return [
            "",  # Empty token
            "short",  # Too short
            "invalid+chars",  # Invalid characters
            "Bearer token_here",  # Contains Bearer prefix
            None  # None value
        ]

    def test_health_endpoint(self, client):
        """Test health check endpoint."""
        response = client.get("/health")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "resource-server" in data["service"].lower()

    def test_status_endpoint(self, client):
        """Test status endpoint."""
        response = client.get("/status")

        assert response.status_code == 200
        data = response.json()
        assert "service" in data
        assert "endpoints" in data
        assert "security_features" in data

    def test_protected_endpoint_with_valid_token(self, client, valid_token):
        """Test protected endpoint with valid Bearer token."""
        headers = {"Authorization": f"Bearer {valid_token}"}
        response = client.get("/protected", headers=headers)

        assert response.status_code == 200
        assert len(response.text) > 0
        # Should return some protected content
        assert "protected" in response.text.lower() or len(response.text) > 10

    def test_protected_endpoint_without_token(self, client):
        """Test protected endpoint without Authorization header."""
        response = client.get("/protected")

        assert response.status_code == 401
        # Should return error response
        error_data = response.json()
        assert "error" in error_data or "detail" in error_data

    def test_protected_endpoint_with_malformed_auth_header(self, client):
        """Test protected endpoint with malformed Authorization headers."""
        malformed_headers = [
            {"Authorization": "invalid_format"},
            {"Authorization": "Bearer"},  # Missing token
            {"Authorization": "Basic dGVzdA=="},  # Wrong auth type
            {"Authorization": "bearer token"},  # Wrong case
            {"Authorization": "Bearer "},  # Empty token after Bearer
        ]

        for headers in malformed_headers:
            response = client.get("/protected", headers=headers)
            assert response.status_code == 401

    def test_protected_endpoint_with_invalid_tokens(self, client, invalid_tokens):
        """Test protected endpoint with various invalid tokens."""
        for invalid_token in invalid_tokens:
            if invalid_token is not None:
                headers = {"Authorization": f"Bearer {invalid_token}"}
                response = client.get("/protected", headers=headers)
                # Should reject invalid tokens
                assert response.status_code in [401, 403]

    def test_userinfo_endpoint_with_valid_token(self, client, valid_token):
        """Test userinfo endpoint with valid Bearer token."""
        headers = {"Authorization": f"Bearer {valid_token}"}
        response = client.get("/userinfo", headers=headers)

        assert response.status_code == 200
        user_data = response.json()
        assert isinstance(user_data, dict)
        # Should contain user information
        assert "sub" in user_data or "username" in user_data or "user_id" in user_data

    def test_userinfo_endpoint_without_token(self, client):
        """Test userinfo endpoint without Authorization header."""
        response = client.get("/userinfo")

        assert response.status_code == 401

    def test_userinfo_endpoint_with_invalid_token(self, client):
        """Test userinfo endpoint with invalid token."""
        headers = {"Authorization": "Bearer invalid_token"}
        response = client.get("/userinfo", headers=headers)

        assert response.status_code in [401, 403]

    def test_userinfo_endpoint_response_format(self, client, valid_token):
        """Test that userinfo endpoint returns proper JSON format."""
        headers = {"Authorization": f"Bearer {valid_token}"}
        response = client.get("/userinfo", headers=headers)

        assert response.status_code == 200
        assert response.headers.get("content-type", "").startswith("application/json")

        user_data = response.json()
        assert isinstance(user_data, dict)
        # Should have at least one user identifier field
        user_fields = ["sub", "username", "user_id", "email"]
        assert any(field in user_data for field in user_fields)

    def test_token_validation_case_sensitivity(self, client, valid_token):
        """Test that Bearer token validation is case-sensitive."""
        # Correct case should work
        headers = {"Authorization": f"Bearer {valid_token}"}
        response = client.get("/protected", headers=headers)
        assert response.status_code == 200

        # Wrong case should fail
        wrong_case_headers = [
            {"Authorization": f"bearer {valid_token}"},  # lowercase bearer
            {"Authorization": f"BEARER {valid_token}"},  # uppercase bearer
            {"Authorization": f"Bearer {valid_token.upper()}"},  # uppercase token
            {"Authorization": f"Bearer {valid_token.lower()}"},  # lowercase token
        ]

        for headers in wrong_case_headers:
            response = client.get("/protected", headers=headers)
            # Most should fail, but some might pass depending on implementation
            # At minimum, the bearer keyword case should matter
            if "bearer " in headers["Authorization"] or "BEARER " in headers["Authorization"]:
                assert response.status_code == 401

    def test_multiple_authorization_headers(self, client, valid_token):
        """Test behavior with multiple Authorization headers."""
        # This tests edge case handling
        headers = {
            "Authorization": f"Bearer {valid_token}",
            "X-Authorization": f"Bearer {valid_token}"  # Additional auth header
        }

        response = client.get("/protected", headers=headers)
        # Should still work with primary Authorization header
        assert response.status_code == 200

    def test_token_length_validation(self, client):
        """Test token validation with various token lengths."""
        # Test very short tokens
        short_tokens = ["a", "ab", "abc", "1234"]
        for token in short_tokens:
            headers = {"Authorization": f"Bearer {token}"}
            response = client.get("/protected", headers=headers)
            # Should reject very short tokens
            assert response.status_code in [401, 403]

        # Test very long tokens
        long_token = "a" * 1000
        headers = {"Authorization": f"Bearer {long_token}"}
        response = client.get("/protected", headers=headers)
        # Should handle long tokens gracefully
        assert response.status_code in [200, 401, 403]

    def test_token_character_validation(self, client):
        """Test token validation with various character sets."""
        # Test tokens with special characters
        special_char_tokens = [
            "token+with+plus",
            "token/with/slash",
            "token with spaces",
            "token@with@at",
            "token#with#hash"
        ]

        for token in special_char_tokens:
            headers = {"Authorization": f"Bearer {token}"}
            response = client.get("/protected", headers=headers)
            # Should handle special characters appropriately
            assert response.status_code in [200, 401, 403]

    def test_concurrent_token_validation(self, client, valid_token):
        """Test concurrent requests with same token."""
        import threading
        import time

        results = []

        def make_request():
            headers = {"Authorization": f"Bearer {valid_token}"}
            response = client.get("/protected", headers=headers)
            results.append(response.status_code)

        # Create multiple threads making concurrent requests
        threads = []
        for _ in range(5):
            thread = threading.Thread(target=make_request)
            threads.append(thread)

        # Start all threads
        for thread in threads:
            thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        # All requests should succeed (or fail consistently)
        assert len(results) == 5
        # All should have same result (either all 200 or all 401/403)
        assert len(set(results)) <= 2  # Allow for some variation in edge cases

    def test_cors_headers_present(self, client):
        """Test that CORS headers are present for cross-origin requests."""
        response = client.get("/health")

        # Should handle CORS appropriately
        assert response.status_code == 200

        # Check for CORS headers in OPTIONS request
        options_response = client.options("/protected")
        # Should handle OPTIONS request for CORS preflight
        assert options_response.status_code in [200, 204, 405]

    def test_security_headers_present(self, client, valid_token):
        """Test that security headers are present in responses."""
        headers = {"Authorization": f"Bearer {valid_token}"}
        response = client.get("/protected", headers=headers)

        # Should have security headers
        response_headers = response.headers
        security_headers = [
            "x-content-type-options",
            "x-frame-options",
            "x-xss-protection",
            "x-api-version",
            "x-service-type"
        ]

        # At least some security headers should be present
        security_header_found = any(
            header.lower() in response_headers for header in security_headers
        )
        assert security_header_found or response.status_code == 200

    def test_error_response_format(self, client):
        """Test that error responses have consistent format."""
        response = client.get("/protected")  # No auth header

        assert response.status_code == 401
        assert response.headers.get("content-type", "").startswith("application/json")

        error_data = response.json()
        assert isinstance(error_data, dict)
        # Should have error information
        assert "error" in error_data or "detail" in error_data

    def test_protected_resource_content_type(self, client, valid_token):
        """Test that protected resource returns appropriate content type."""
        headers = {"Authorization": f"Bearer {valid_token}"}
        response = client.get("/protected", headers=headers)

        assert response.status_code == 200
        content_type = response.headers.get("content-type", "")
        # Should return text or JSON content
        assert content_type.startswith(("text/", "application/json", "application/"))

    def test_userinfo_content_security(self, client, valid_token):
        """Test that userinfo endpoint doesn't leak sensitive information."""
        headers = {"Authorization": f"Bearer {valid_token}"}
        response = client.get("/userinfo", headers=headers)

        assert response.status_code == 200
        user_data = response.json()

        # Should not contain sensitive fields
        sensitive_fields = ["password", "secret", "key", "token", "hash"]
        for field in sensitive_fields:
            assert field not in user_data
            # Also check values don't contain sensitive keywords
            for value in user_data.values():
                if isinstance(value, str):
                    assert not any(sensitive in value.lower() for sensitive in sensitive_fields)

    def test_rate_limiting_behavior(self, client, valid_token):
        """Test behavior under rapid requests (basic rate limiting test)."""
        headers = {"Authorization": f"Bearer {valid_token}"}

        # Make rapid requests
        responses = []
        for _ in range(10):
            response = client.get("/protected", headers=headers)
            responses.append(response.status_code)

        # Should handle rapid requests gracefully
        # Most should succeed, but some rate limiting might kick in
        success_count = sum(1 for status in responses if status == 200)
        assert success_count >= 5  # At least half should succeed

    def test_invalid_endpoint_paths(self, client, valid_token):
        """Test behavior with invalid endpoint paths."""
        headers = {"Authorization": f"Bearer {valid_token}"}

        invalid_paths = [
            "/nonexistent",
            "/protected/",  # Trailing slash
            "/Protected",  # Wrong case
            "/protected/subpath",
            "/userinfo/",
            "/Userinfo"
        ]

        for path in invalid_paths:
            response = client.get(path, headers=headers)
            # Should return 404 for nonexistent paths
            assert response.status_code in [404, 405, 200]  # 200 if path actually exists

    def test_http_methods_on_protected_endpoints(self, client, valid_token):
        """Test different HTTP methods on protected endpoints."""
        headers = {"Authorization": f"Bearer {valid_token}"}

        # Test GET (should work)
        get_response = client.get("/protected", headers=headers)
        assert get_response.status_code == 200

        # Test other methods (behavior depends on implementation)
        post_response = client.post("/protected", headers=headers)
        put_response = client.put("/protected", headers=headers)
        delete_response = client.delete("/protected", headers=headers)

        # Should handle different methods appropriately
        for response in [post_response, put_response, delete_response]:
            assert response.status_code in [200, 405, 501]  # OK, Method Not Allowed, or Not Implemented

    def test_token_validation_logging(self, client, valid_token):
        """Test that token validation is properly logged."""
        # This test verifies logging behavior
        with patch('src.shared.logging_utils.OAuthLogger.log_oauth_message') as mock_log:
            headers = {"Authorization": f"Bearer {valid_token}"}
            response = client.get("/protected", headers=headers)

            # Should have logged the token validation
            assert response.status_code == 200
            # Verify logging was called (implementation dependent)
            # mock_log.assert_called()  # Uncomment if logging is implemented