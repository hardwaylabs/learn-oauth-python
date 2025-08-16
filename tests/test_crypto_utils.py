"""
Unit tests for PKCE cryptographic utilities.

Tests the PKCEGenerator class and related cryptographic functions
to ensure proper PKCE implementation according to RFC 7636.
"""

import pytest
import base64
import hashlib
import secrets
from src.shared.crypto_utils import (
    PKCEGenerator,
    validate_base64url,
    constant_time_compare
)


class TestPKCEGenerator:
    """Test cases for PKCEGenerator class."""

    def test_generate_challenge_returns_valid_pair(self):
        """Test that generate_challenge returns a valid verifier/challenge pair."""
        verifier, challenge = PKCEGenerator.generate_challenge()

        # Verify lengths (43 characters for base64url without padding)
        assert len(verifier) == 43
        assert len(challenge) == 43

        # Verify they are different
        assert verifier != challenge

        # Verify challenge can be verified with verifier
        assert PKCEGenerator.verify_challenge(verifier, challenge)

    def test_generate_challenge_creates_unique_pairs(self):
        """Test that multiple calls generate unique verifier/challenge pairs."""
        pairs = [PKCEGenerator.generate_challenge() for _ in range(10)]

        # All verifiers should be unique
        verifiers = [pair[0] for pair in pairs]
        assert len(set(verifiers)) == 10

        # All challenges should be unique
        challenges = [pair[1] for pair in pairs]
        assert len(set(challenges)) == 10

    def test_verify_challenge_accepts_valid_verifier(self):
        """Test that verify_challenge accepts valid verifier/challenge pairs."""
        verifier, challenge = PKCEGenerator.generate_challenge()
        assert PKCEGenerator.verify_challenge(verifier, challenge) is True

    def test_verify_challenge_rejects_invalid_verifier(self):
        """Test that verify_challenge rejects invalid verifiers."""
        _, challenge = PKCEGenerator.generate_challenge()
        invalid_verifier = "invalid_verifier_string"
        assert PKCEGenerator.verify_challenge(invalid_verifier, challenge) is False

    def test_verify_challenge_rejects_wrong_challenge(self):
        """Test that verify_challenge rejects wrong challenges."""
        verifier, _ = PKCEGenerator.generate_challenge()
        _, wrong_challenge = PKCEGenerator.generate_challenge()
        assert PKCEGenerator.verify_challenge(verifier, wrong_challenge) is False

    def test_verify_challenge_handles_malformed_input(self):
        """Test that verify_challenge handles malformed input gracefully."""
        # Test with None values
        assert PKCEGenerator.verify_challenge(None, "challenge") is False
        assert PKCEGenerator.verify_challenge("verifier", None) is False

        # Test with empty strings
        assert PKCEGenerator.verify_challenge("", "challenge") is False
        assert PKCEGenerator.verify_challenge("verifier", "") is False

        # Test with non-string types
        assert PKCEGenerator.verify_challenge(123, "challenge") is False
        assert PKCEGenerator.verify_challenge("verifier", 456) is False

    def test_challenge_matches_rfc7636_specification(self):
        """Test that challenge generation follows RFC 7636 specification."""
        verifier, challenge = PKCEGenerator.generate_challenge()

        # Manually compute expected challenge
        expected_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode('utf-8')).digest()
        ).decode('utf-8').rstrip('=')

        assert challenge == expected_challenge

    def test_generate_secure_token_default_length(self):
        """Test secure token generation with default length."""
        token = PKCEGenerator.generate_secure_token()

        # Default 32 bytes -> 43 characters base64url
        assert len(token) == 43
        assert validate_base64url(token)

    def test_generate_secure_token_custom_length(self):
        """Test secure token generation with custom lengths."""
        # Test various lengths
        for byte_length in [16, 24, 32, 48, 64]:
            token = PKCEGenerator.generate_secure_token(byte_length)

            # Verify token is valid base64url
            assert validate_base64url(token)

            # Verify we can decode it back to original byte length
            padded = token + '=' * (4 - len(token) % 4)
            decoded = base64.urlsafe_b64decode(padded)
            assert len(decoded) == byte_length

    def test_generate_secure_token_uniqueness(self):
        """Test that secure tokens are unique."""
        tokens = [PKCEGenerator.generate_secure_token() for _ in range(100)]
        assert len(set(tokens)) == 100

    def test_generate_state_parameter(self):
        """Test state parameter generation."""
        state = PKCEGenerator.generate_state_parameter()

        # Should be valid base64url
        assert validate_base64url(state)

        # Should be reasonably long for security
        assert len(state) >= 20

        # Multiple calls should generate unique values
        states = [PKCEGenerator.generate_state_parameter() for _ in range(10)]
        assert len(set(states)) == 10


class TestValidateBase64url:
    """Test cases for base64url validation function."""

    def test_validates_correct_base64url(self):
        """Test validation of correct base64url strings."""
        valid_strings = [
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            "abc123",
            "A-Z_a-z0-9"
        ]

        for valid_str in valid_strings:
            assert validate_base64url(valid_str) is True

    def test_rejects_invalid_base64url(self):
        """Test rejection of invalid base64url strings."""
        invalid_strings = [
            "invalid+chars",  # Contains + instead of -
            "invalid/chars",  # Contains / instead of _
            "invalid=padding",  # Contains padding
            "",  # Empty string
            "!@#$%",  # Invalid characters
        ]

        for invalid_str in invalid_strings:
            assert validate_base64url(invalid_str) is False

    def test_handles_edge_cases(self):
        """Test validation with edge cases."""
        # None input
        assert validate_base64url(None) is False

        # Non-string input
        assert validate_base64url(123) is False
        assert validate_base64url([]) is False


class TestConstantTimeCompare:
    """Test cases for constant-time comparison function."""

    def test_equal_strings_return_true(self):
        """Test that equal strings return True."""
        test_string = "test_string_123"
        assert constant_time_compare(test_string, test_string) is True

    def test_different_strings_return_false(self):
        """Test that different strings return False."""
        assert constant_time_compare("string1", "string2") is False
        assert constant_time_compare("test", "TEST") is False

    def test_different_lengths_return_false(self):
        """Test that strings of different lengths return False."""
        assert constant_time_compare("short", "longer_string") is False
        assert constant_time_compare("longer_string", "short") is False

    def test_empty_strings(self):
        """Test comparison with empty strings."""
        assert constant_time_compare("", "") is True
        assert constant_time_compare("", "non_empty") is False
        assert constant_time_compare("non_empty", "") is False

    def test_unicode_strings(self):
        """Test comparison with unicode strings."""
        unicode_str = "test_ñoñó_🔒"
        assert constant_time_compare(unicode_str, unicode_str) is True
        assert constant_time_compare(unicode_str, "different") is False