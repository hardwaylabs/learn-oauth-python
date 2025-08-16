"""
Pytest configuration and shared fixtures for OAuth 2.1 tests.

This module provides common test fixtures, configuration, and utilities
used across all test modules in the OAuth 2.1 learning project.
"""

import pytest
import asyncio
import secrets
from typing import Generator, Dict, Any
from unittest.mock import MagicMock, patch

# Import shared utilities for testing
from src.shared.crypto_utils import PKCEGenerator
from src.shared.oauth_models import AuthorizationRequest, TokenRequest
from src.shared.security import PasswordHasher


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def pkce_pair() -> tuple[str, str]:
    """Generate a PKCE verifier and challenge pair for testing."""
    return PKCEGenerator.generate_challenge()


@pytest.fixture
def valid_oauth_params(pkce_pair) -> Dict[str, str]:
    """Generate valid OAuth parameters for testing."""
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


@pytest.fixture
def demo_user_credentials() -> Dict[str, str]:
    """Demo user credentials for testing."""
    return {
        "alice": "password123",
        "bob": "secret456",
        "carol": "mypass789"
    }


@pytest.fixture
def valid_authorization_request(valid_oauth_params) -> AuthorizationRequest:
    """Create a valid AuthorizationRequest for testing."""
    return AuthorizationRequest(
        client_id=valid_oauth_params["client_id"],
        redirect_uri=valid_oauth_params["redirect_uri"],
        scope=valid_oauth_params["scope"],
        state=valid_oauth_params["state"],
        code_challenge=valid_oauth_params["code_challenge"],
        code_challenge_method=valid_oauth_params["code_challenge_method"],
        response_type=valid_oauth_params["response_type"]
    )


@pytest.fixture
def valid_token_request(valid_oauth_params) -> TokenRequest:
    """Create a valid TokenRequest for testing."""
    return TokenRequest(
        grant_type="authorization_code",
        code="test_authorization_code",
        redirect_uri=valid_oauth_params["redirect_uri"],
        client_id=valid_oauth_params["client_id"],
        code_verifier=valid_oauth_params["pkce_verifier"]
    )


@pytest.fixture
def mock_access_token() -> str:
    """Generate a mock access token for testing."""
    return secrets.token_urlsafe(48)


@pytest.fixture
def mock_authorization_code() -> str:
    """Generate a mock authorization code for testing."""
    return secrets.token_urlsafe(32)


@pytest.fixture
def invalid_oauth_params() -> Dict[str, Any]:
    """Generate various invalid OAuth parameters for testing."""
    return {
        "empty_client_id": {
            "client_id": "",
            "redirect_uri": "http://localhost:8080/callback",
            "scope": "read",
            "state": "test-state",
            "code_challenge": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            "code_challenge_method": "S256",
            "response_type": "code"
        },
        "invalid_redirect_uri": {
            "client_id": "demo-client",
            "redirect_uri": "not-a-valid-uri",
            "scope": "read",
            "state": "test-state",
            "code_challenge": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            "code_challenge_method": "S256",
            "response_type": "code"
        },
        "invalid_pkce_method": {
            "client_id": "demo-client",
            "redirect_uri": "http://localhost:8080/callback",
            "scope": "read",
            "state": "test-state",
            "code_challenge": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            "code_challenge_method": "plain",  # Invalid for OAuth 2.1
            "response_type": "code"
        },
        "invalid_response_type": {
            "client_id": "demo-client",
            "redirect_uri": "http://localhost:8080/callback",
            "scope": "read",
            "state": "test-state",
            "code_challenge": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            "code_challenge_method": "S256",
            "response_type": "token"  # Invalid for OAuth 2.1
        }
    }


@pytest.fixture
def security_test_payloads() -> Dict[str, list]:
    """Security test payloads for various attack vectors."""
    return {
        "xss_payloads": [
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "<img src=x onerror=alert('xss')>",
            "';alert('xss');//",
            "<svg onload=alert('xss')>"
        ],
        "sql_injection_payloads": [
            "'; DROP TABLE users; --",
            "' OR '1'='1",
            "admin'--",
            "' UNION SELECT * FROM users --",
            "'; INSERT INTO users VALUES ('hacker', 'password'); --"
        ],
        "path_traversal_payloads": [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "....//....//....//etc/passwd"
        ],
        "command_injection_payloads": [
            "; ls -la",
            "| cat /etc/passwd",
            "&& rm -rf /",
            "`whoami`",
            "$(id)"
        ]
    }


@pytest.fixture
def mock_http_responses() -> Dict[str, MagicMock]:
    """Mock HTTP responses for testing external API calls."""
    # Successful token response
    success_token_response = MagicMock()
    success_token_response.status_code = 200
    success_token_response.json.return_value = {
        "access_token": "mock_access_token_12345",
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": "read"
    }

    # Failed token response
    failed_token_response = MagicMock()
    failed_token_response.status_code = 400
    failed_token_response.json.return_value = {
        "error": "invalid_grant",
        "error_description": "Invalid authorization code"
    }
    failed_token_response.headers = {"content-type": "application/json"}

    # Successful resource response
    success_resource_response = MagicMock()
    success_resource_response.status_code = 200
    success_resource_response.text = "Protected resource content"
    success_resource_response.headers = {"content-type": "text/plain"}

    # Unauthorized resource response
    unauthorized_resource_response = MagicMock()
    unauthorized_resource_response.status_code = 401
    unauthorized_resource_response.text = "Unauthorized"

    # Successful userinfo response
    success_userinfo_response = MagicMock()
    success_userinfo_response.status_code = 200
    success_userinfo_response.json.return_value = {
        "sub": "user123",
        "username": "alice",
        "email": "alice@example.com"
    }

    return {
        "success_token": success_token_response,
        "failed_token": failed_token_response,
        "success_resource": success_resource_response,
        "unauthorized_resource": unauthorized_resource_response,
        "success_userinfo": success_userinfo_response
    }


@pytest.fixture
def mock_password_hasher():
    """Mock password hasher for testing without bcrypt dependency."""
    with patch('src.shared.security.PasswordHasher') as mock_hasher:
        # Mock hash_password method
        mock_hasher.hash_password.return_value = "mock_hashed_password"

        # Mock verify_password method
        def mock_verify(password, hashed):
            # Simple mock verification for testing
            demo_passwords = {
                "password123": "alice_hash",
                "secret456": "bob_hash",
                "mypass789": "carol_hash"
            }
            return hashed in demo_passwords.values() and password in demo_passwords

        mock_hasher.verify_password.side_effect = mock_verify

        # Mock generate_demo_hashes
        mock_hasher.generate_demo_hashes.return_value = {
            "alice": "alice_hash",
            "bob": "bob_hash",
            "carol": "carol_hash"
        }

        yield mock_hasher


@pytest.fixture
def mock_logger():
    """Mock OAuth logger to prevent actual logging during tests."""
    with patch('src.shared.logging_utils.OAuthLogger') as mock_logger_class:
        mock_instance = MagicMock()
        mock_logger_class.return_value = mock_instance
        yield mock_instance


@pytest.fixture(autouse=True)
def disable_logging():
    """Disable logging during tests to reduce noise."""
    import logging
    logging.disable(logging.CRITICAL)
    yield
    logging.disable(logging.NOTSET)


# Pytest configuration
def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests"
    )
    config.addinivalue_line(
        "markers", "security: marks tests as security-focused tests"
    )
    config.addinivalue_line(
        "markers", "unit: marks tests as unit tests"
    )


def pytest_collection_modifyitems(config, items):
    """Modify test collection to add markers automatically."""
    for item in items:
        # Add markers based on test file names
        if "integration" in item.nodeid:
            item.add_marker(pytest.mark.integration)
        elif "security" in item.nodeid or "error_handling" in item.nodeid:
            item.add_marker(pytest.mark.security)
        elif "test_" in item.nodeid and "integration" not in item.nodeid:
            item.add_marker(pytest.mark.unit)


# Custom assertions for OAuth testing
def assert_valid_oauth_error_response(response_data: dict):
    """Assert that a response contains a valid OAuth error format."""
    assert isinstance(response_data, dict)
    assert "error" in response_data
    assert isinstance(response_data["error"], str)

    # Check for valid OAuth error codes
    valid_errors = [
        "invalid_request", "invalid_client", "invalid_grant",
        "unauthorized_client", "unsupported_grant_type", "invalid_scope",
        "access_denied", "unsupported_response_type", "server_error",
        "temporarily_unavailable"
    ]

    # Error should be a valid OAuth error or at least a meaningful string
    assert len(response_data["error"]) > 0


def assert_valid_token_response(response_data: dict):
    """Assert that a response contains a valid OAuth token format."""
    assert isinstance(response_data, dict)
    assert "access_token" in response_data
    assert "token_type" in response_data
    assert response_data["token_type"] == "Bearer"
    assert isinstance(response_data["access_token"], str)
    assert len(response_data["access_token"]) > 0

    if "expires_in" in response_data:
        assert isinstance(response_data["expires_in"], int)
        assert response_data["expires_in"] > 0


def assert_secure_headers_present(response_headers: dict):
    """Assert that security headers are present in response."""
    security_headers = [
        "x-content-type-options",
        "x-frame-options",
        "x-xss-protection"
    ]

    # At least one security header should be present
    headers_lower = {k.lower(): v for k, v in response_headers.items()}
    security_header_found = any(
        header in headers_lower for header in security_headers
    )

    assert security_header_found, f"No security headers found in {list(response_headers.keys())}"


# Make custom assertions available to all tests
pytest.assert_valid_oauth_error_response = assert_valid_oauth_error_response
pytest.assert_valid_token_response = assert_valid_token_response
pytest.assert_secure_headers_present = assert_secure_headers_present