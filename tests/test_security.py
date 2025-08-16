"""
Unit tests for security utilities.

Tests password hashing, token generation, input validation, and other
security-related functions to ensure proper implementation of security measures.
"""

import pytest
import re
from src.shared.security import (
    PasswordHasher,
    TokenGenerator,
    InputValidator,
    SecurityHeaders,
    hash_password,
    verify_password,
    generate_secure_token,
    validate_oauth_parameter
)


class TestPasswordHasher:
    """Test cases for PasswordHasher class."""

    def test_hash_password_creates_valid_hash(self):
        """Test that password hashing creates valid bcrypt hash."""
        password = "test_password_123"
        hashed = PasswordHasher.hash_password(password)

        # Should be a string
        assert isinstance(hashed, str)

        # Should be non-empty
        assert len(hashed) > 0

        # Should start with bcrypt prefix or fallback prefix
        assert hashed.startswith('$2b$') or hashed.startswith('sha256$')

    def test_hash_password_different_passwords_different_hashes(self):
        """Test that different passwords produce different hashes."""
        password1 = "password123"
        password2 = "different456"

        hash1 = PasswordHasher.hash_password(password1)
        hash2 = PasswordHasher.hash_password(password2)

        assert hash1 != hash2

    def test_hash_password_same_password_different_hashes(self):
        """Test that same password produces different hashes (due to salt)."""
        password = "same_password"

        hash1 = PasswordHasher.hash_password(password)
        hash2 = PasswordHasher.hash_password(password)

        # Hashes should be different due to random salt
        assert hash1 != hash2

    def test_hash_password_invalid_input(self):
        """Test password hashing with invalid input."""
        # Non-string input
        with pytest.raises(ValueError):
            PasswordHasher.hash_password(123)

        with pytest.raises(ValueError):
            PasswordHasher.hash_password(None)

        # Empty password
        with pytest.raises(ValueError):
            PasswordHasher.hash_password("")

    def test_verify_password_correct_password(self):
        """Test password verification with correct password."""
        password = "correct_password"
        hashed = PasswordHasher.hash_password(password)

        assert PasswordHasher.verify_password(password, hashed) is True

    def test_verify_password_incorrect_password(self):
        """Test password verification with incorrect password."""
        password = "correct_password"
        wrong_password = "wrong_password"
        hashed = PasswordHasher.hash_password(password)

        assert PasswordHasher.verify_password(wrong_password, hashed) is False

    def test_verify_password_invalid_input(self):
        """Test password verification with invalid input."""
        # Non-string inputs
        assert PasswordHasher.verify_password(123, "hash") is False
        assert PasswordHasher.verify_password("password", 456) is False
        assert PasswordHasher.verify_password(None, "hash") is False
        assert PasswordHasher.verify_password("password", None) is False

    def test_verify_password_malformed_hash(self):
        """Test password verification with malformed hash."""
        password = "test_password"
        malformed_hash = "not_a_valid_hash"

        assert PasswordHasher.verify_password(password, malformed_hash) is False

    def test_generate_demo_hashes(self):
        """Test generation of demo account hashes."""
        demo_hashes = PasswordHasher.generate_demo_hashes()

        # Should contain expected usernames
        expected_users = ['alice', 'bob', 'carol']
        assert all(user in demo_hashes for user in expected_users)

        # All hashes should be valid strings
        for username, hashed in demo_hashes.items():
            assert isinstance(hashed, str)
            assert len(hashed) > 0

        # Should be able to verify demo passwords
        demo_passwords = {
            'alice': 'password123',
            'bob': 'secret456',
            'carol': 'mypass789'
        }

        for username, password in demo_passwords.items():
            assert PasswordHasher.verify_password(password, demo_hashes[username])


class TestTokenGenerator:
    """Test cases for TokenGenerator class."""

    def test_generate_authorization_code(self):
        """Test authorization code generation."""
        code = TokenGenerator.generate_authorization_code()

        assert isinstance(code, str)
        assert len(code) > 0
        # Should be URL-safe
        assert re.match(r'^[A-Za-z0-9_-]+$', code)

    def test_generate_access_token(self):
        """Test access token generation."""
        token = TokenGenerator.generate_access_token()

        assert isinstance(token, str)
        assert len(token) > 0
        # Should be URL-safe
        assert re.match(r'^[A-Za-z0-9_-]+$', token)

    def test_generate_refresh_token(self):
        """Test refresh token generation."""
        token = TokenGenerator.generate_refresh_token()

        assert isinstance(token, str)
        assert len(token) > 0
        # Should be URL-safe
        assert re.match(r'^[A-Za-z0-9_-]+$', token)

    def test_generate_client_secret(self):
        """Test client secret generation."""
        secret = TokenGenerator.generate_client_secret()

        assert isinstance(secret, str)
        assert len(secret) > 0
        # Should be URL-safe
        assert re.match(r'^[A-Za-z0-9_-]+$', secret)

    def test_generate_session_id(self):
        """Test session ID generation."""
        session_id = TokenGenerator.generate_session_id()

        assert isinstance(session_id, str)
        assert len(session_id) > 0
        # Should be URL-safe
        assert re.match(r'^[A-Za-z0-9_-]+$', session_id)

    def test_generate_nonce(self):
        """Test nonce generation."""
        nonce = TokenGenerator.generate_nonce()

        assert isinstance(nonce, str)
        assert len(nonce) > 0
        # Should be URL-safe
        assert re.match(r'^[A-Za-z0-9_-]+$', nonce)

    def test_token_uniqueness(self):
        """Test that generated tokens are unique."""
        # Generate multiple tokens of each type
        auth_codes = [TokenGenerator.generate_authorization_code() for _ in range(10)]
        access_tokens = [TokenGenerator.generate_access_token() for _ in range(10)]
        refresh_tokens = [TokenGenerator.generate_refresh_token() for _ in range(10)]

        # All should be unique
        assert len(set(auth_codes)) == 10
        assert len(set(access_tokens)) == 10
        assert len(set(refresh_tokens)) == 10

    def test_token_lengths(self):
        """Test that tokens have reasonable lengths."""
        auth_code = TokenGenerator.generate_authorization_code()
        access_token = TokenGenerator.generate_access_token()
        refresh_token = TokenGenerator.generate_refresh_token()

        # Should be reasonably long for security
        assert len(auth_code) >= 20
        assert len(access_token) >= 30
        assert len(refresh_token) >= 40


class TestInputValidator:
    """Test cases for InputValidator class."""

    def test_validate_client_id_valid(self):
        """Test validation of valid client IDs."""
        valid_client_ids = [
            "demo-client",
            "client_123",
            "my-oauth-client",
            "client123",
            "a",
            "A" * 100  # Max length
        ]

        for client_id in valid_client_ids:
            assert InputValidator.validate_client_id(client_id) is True

    def test_validate_client_id_invalid(self):
        """Test validation of invalid client IDs."""
        invalid_client_ids = [
            "",  # Empty
            "client with spaces",  # Spaces
            "client@domain.com",  # Invalid characters
            "client+plus",  # Plus sign
            "A" * 101,  # Too long
            123,  # Non-string
            None  # None
        ]

        for client_id in invalid_client_ids:
            assert InputValidator.validate_client_id(client_id) is False

    def test_validate_redirect_uri_valid(self):
        """Test validation of valid redirect URIs."""
        valid_uris = [
            "http://localhost:8080/callback",
            "https://example.com/oauth/callback",
            "https://app.example.com:443/auth",
            "http://127.0.0.1:3000/cb"
        ]

        for uri in valid_uris:
            assert InputValidator.validate_redirect_uri(uri) is True

    def test_validate_redirect_uri_invalid(self):
        """Test validation of invalid redirect URIs."""
        invalid_uris = [
            "",  # Empty
            "not-a-uri",  # Not a URI
            "ftp://example.com/callback",  # Wrong scheme
            "javascript:alert('xss')",  # Dangerous scheme
            "http://",  # Missing netloc
            "https://example.com/callback?param=<script>",  # Dangerous chars
            123,  # Non-string
            None  # None
        ]

        for uri in invalid_uris:
            assert InputValidator.validate_redirect_uri(uri) is False

    def test_validate_redirect_uri_custom_schemes(self):
        """Test redirect URI validation with custom allowed schemes."""
        custom_uri = "myapp://oauth/callback"

        # Should fail with default schemes
        assert InputValidator.validate_redirect_uri(custom_uri) is False

        # Should pass with custom schemes
        assert InputValidator.validate_redirect_uri(custom_uri, ['myapp']) is True

    def test_validate_scope_valid(self):
        """Test validation of valid scope parameters."""
        valid_scopes = [
            "read",
            "read write",
            "user:email",
            "repo admin:org",
            "openid profile email",
            "a",
            "A" * 200  # Max length
        ]

        for scope in valid_scopes:
            assert InputValidator.validate_scope(scope) is True

    def test_validate_scope_invalid(self):
        """Test validation of invalid scope parameters."""
        invalid_scopes = [
            "",  # Empty
            "scope@invalid",  # Invalid characters
            "scope+plus",  # Plus sign
            "A" * 201,  # Too long
            123,  # Non-string
            None  # None
        ]

        for scope in invalid_scopes:
            assert InputValidator.validate_scope(scope) is False

    def test_validate_state_valid(self):
        """Test validation of valid state parameters."""
        valid_states = [
            "random-state-123",
            "state_456",
            "abcDEF123-_",
            "a",
            "A" * 128  # Max length
        ]

        for state in valid_states:
            assert InputValidator.validate_state(state) is True

    def test_validate_state_invalid(self):
        """Test validation of invalid state parameters."""
        invalid_states = [
            "",  # Empty
            "state with spaces",  # Spaces
            "state@invalid",  # Invalid characters
            "A" * 129,  # Too long
            123,  # Non-string
            None  # None
        ]

        for state in invalid_states:
            assert InputValidator.validate_state(state) is False

    def test_validate_username_valid(self):
        """Test validation of valid usernames."""
        valid_usernames = [
            "alice",
            "user123",
            "user.name",
            "user-name",
            "user_name",
            "a",
            "A" * 50  # Max length
        ]

        for username in valid_usernames:
            assert InputValidator.validate_username(username) is True

    def test_validate_username_invalid(self):
        """Test validation of invalid usernames."""
        invalid_usernames = [
            "",  # Empty
            "user with spaces",  # Spaces
            "user@domain",  # Invalid characters
            "A" * 51,  # Too long
            123,  # Non-string
            None  # None
        ]

        for username in invalid_usernames:
            assert InputValidator.validate_username(username) is False

    def test_sanitize_string_basic(self):
        """Test basic string sanitization."""
        input_str = "  Hello World  "
        sanitized = InputValidator.sanitize_string(input_str)

        assert sanitized == "Hello World"

    def test_sanitize_string_control_characters(self):
        """Test sanitization of control characters."""
        input_str = "Hello\x00\x01World\x1f"
        sanitized = InputValidator.sanitize_string(input_str)

        assert sanitized == "HelloWorld"

    def test_sanitize_string_preserve_whitespace(self):
        """Test that normal whitespace is preserved."""
        input_str = "Hello\nWorld\tTest\r"
        sanitized = InputValidator.sanitize_string(input_str)

        assert "Hello" in sanitized
        assert "World" in sanitized
        assert "Test" in sanitized

    def test_sanitize_string_max_length(self):
        """Test string truncation to max length."""
        input_str = "A" * 2000
        sanitized = InputValidator.sanitize_string(input_str, max_length=100)

        assert len(sanitized) == 100

    def test_sanitize_string_invalid_input(self):
        """Test sanitization with invalid input."""
        assert InputValidator.sanitize_string(123) == ""
        assert InputValidator.sanitize_string(None) == ""

    def test_validate_password_strength_valid(self):
        """Test validation of strong passwords."""
        strong_passwords = [
            "Password123",
            "MySecureP@ss1",
            "ComplexPassword2023!",
            "Str0ng_P@ssw0rd"
        ]

        for password in strong_passwords:
            is_valid, issues = InputValidator.validate_password_strength(password)
            assert is_valid is True
            assert len(issues) == 0

    def test_validate_password_strength_weak(self):
        """Test validation of weak passwords."""
        weak_cases = [
            ("short", ["Password must be at least 8 characters long"]),
            ("alllowercase123", ["Password must contain at least one uppercase letter"]),
            ("ALLUPPERCASE123", ["Password must contain at least one lowercase letter"]),
            ("NoNumbers!", ["Password must contain at least one digit"]),
            ("password", ["Password is too common", "Password must contain at least one uppercase letter"]),
            ("A" * 200, ["Password must be no more than 128 characters long"])
        ]

        for password, expected_issues in weak_cases:
            is_valid, issues = InputValidator.validate_password_strength(password)
            assert is_valid is False
            for expected_issue in expected_issues:
                assert any(expected_issue in issue for issue in issues)

    def test_validate_password_strength_invalid_input(self):
        """Test password strength validation with invalid input."""
        is_valid, issues = InputValidator.validate_password_strength(123)
        assert is_valid is False
        assert "Password must be a string" in issues


class TestSecurityHeaders:
    """Test cases for SecurityHeaders class."""

    def test_get_oauth_security_headers(self):
        """Test OAuth security headers generation."""
        headers = SecurityHeaders.get_oauth_security_headers()

        # Check for required security headers
        assert 'X-Content-Type-Options' in headers
        assert 'X-Frame-Options' in headers
        assert 'X-XSS-Protection' in headers
        assert 'Strict-Transport-Security' in headers
        assert 'Cache-Control' in headers

        # Check header values
        assert headers['X-Content-Type-Options'] == 'nosniff'
        assert headers['X-Frame-Options'] == 'DENY'
        assert 'no-cache' in headers['Cache-Control']

    def test_get_cors_headers_default(self):
        """Test CORS headers with default origins."""
        headers = SecurityHeaders.get_cors_headers()

        assert 'Access-Control-Allow-Origin' in headers
        assert 'Access-Control-Allow-Methods' in headers
        assert 'Access-Control-Allow-Headers' in headers

        # Should include localhost origins
        assert 'localhost:8080' in headers['Access-Control-Allow-Origin']

    def test_get_cors_headers_custom_origins(self):
        """Test CORS headers with custom origins."""
        custom_origins = ['https://example.com', 'https://app.example.com']
        headers = SecurityHeaders.get_cors_headers(custom_origins)

        assert 'example.com' in headers['Access-Control-Allow-Origin']
        assert 'app.example.com' in headers['Access-Control-Allow-Origin']


class TestConvenienceFunctions:
    """Test cases for convenience functions."""

    def test_hash_password_function(self):
        """Test hash_password convenience function."""
        password = "test_password"
        hashed = hash_password(password)

        assert isinstance(hashed, str)
        assert len(hashed) > 0

    def test_verify_password_function(self):
        """Test verify_password convenience function."""
        password = "test_password"
        hashed = hash_password(password)

        assert verify_password(password, hashed) is True
        assert verify_password("wrong_password", hashed) is False

    def test_generate_secure_token_function(self):
        """Test generate_secure_token convenience function."""
        token = generate_secure_token()

        assert isinstance(token, str)
        assert len(token) > 0

        # Test custom length
        custom_token = generate_secure_token(16)
        assert len(custom_token) > 0

    def test_validate_oauth_parameter_function(self):
        """Test validate_oauth_parameter convenience function."""
        # Test known parameters
        assert validate_oauth_parameter('client_id', 'demo-client') is True
        assert validate_oauth_parameter('client_id', '') is False

        assert validate_oauth_parameter('scope', 'read write') is True
        assert validate_oauth_parameter('scope', '') is False

        # Test unknown parameter (should use default validation)
        assert validate_oauth_parameter('unknown_param', 'valid_value') is True
        assert validate_oauth_parameter('unknown_param', '') is False
        assert validate_oauth_parameter('unknown_param', 'A' * 2000) is False