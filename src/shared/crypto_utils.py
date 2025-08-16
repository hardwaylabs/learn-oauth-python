"""
PKCE (Proof Key for Code Exchange) cryptographic utilities.

This module implements RFC 7636 PKCE functionality including secure code verifier
generation, SHA256 challenge creation, and verification functions.
"""

import secrets
import hashlib
import base64
from typing import Tuple


class PKCEGenerator:
    """
    PKCE code verifier and challenge generator.

    Implements RFC 7636 PKCE specification with S256 method for enhanced
    security in OAuth 2.1 authorization code flows.
    """

    @staticmethod
    def generate_challenge() -> Tuple[str, str]:
        """
        Generate PKCE code verifier and challenge pair.

        Creates a cryptographically secure random code verifier and derives
        the corresponding SHA256 challenge using base64url encoding.

        Returns:
            Tuple[str, str]: (code_verifier, code_challenge)

        Example:
            verifier, challenge = PKCEGenerator.generate_challenge()
            # verifier: 43-character base64url string
            # challenge: SHA256 hash of verifier, base64url encoded
        """
        # Generate 32 random bytes and encode as base64url (43 characters)
        verifier = base64.urlsafe_b64encode(
            secrets.token_bytes(32)
        ).decode('utf-8').rstrip('=')

        # Create SHA256 hash of verifier and encode as base64url
        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode('utf-8')).digest()
        ).decode('utf-8').rstrip('=')

        return verifier, challenge

    @staticmethod
    def verify_challenge(verifier: str, challenge: str) -> bool:
        """
        Verify PKCE code verifier against challenge.

        Validates that the provided code verifier generates the expected
        challenge when hashed with SHA256.

        Args:
            verifier: The PKCE code verifier
            challenge: The expected PKCE challenge

        Returns:
            bool: True if verifier matches challenge, False otherwise

        Example:
            is_valid = PKCEGenerator.verify_challenge(
                "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
                "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
            )
        """
        try:
            # Generate expected challenge from verifier
            expected_challenge = base64.urlsafe_b64encode(
                hashlib.sha256(verifier.encode('utf-8')).digest()
            ).decode('utf-8').rstrip('=')

            # Constant-time comparison to prevent timing attacks
            return secrets.compare_digest(expected_challenge, challenge)
        except (ValueError, TypeError):
            # Handle encoding errors or invalid input
            return False

    @staticmethod
    def generate_secure_token(length: int = 32) -> str:
        """
        Generate a cryptographically secure random token.

        Creates a URL-safe base64 encoded token suitable for authorization
        codes, access tokens, and other security-sensitive values.

        Args:
            length: Number of random bytes to generate (default: 32)

        Returns:
            str: Base64url encoded token

        Example:
            token = PKCEGenerator.generate_secure_token()
            # Returns: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        """
        return base64.urlsafe_b64encode(
            secrets.token_bytes(length)
        ).decode('utf-8').rstrip('=')

    @staticmethod
    def generate_state_parameter() -> str:
        """
        Generate a secure state parameter for CSRF protection.

        Creates a random state value to prevent cross-site request forgery
        attacks in OAuth flows.

        Returns:
            str: Secure random state parameter

        Example:
            state = PKCEGenerator.generate_state_parameter()
        """
        return PKCEGenerator.generate_secure_token(16)


def validate_base64url(value: str) -> bool:
    """
    Validate base64url encoded string format.

    Checks if a string is properly base64url encoded without padding.

    Args:
        value: String to validate

    Returns:
        bool: True if valid base64url format, False otherwise
    """
    try:
        # Add padding if needed
        padded = value + '=' * (4 - len(value) % 4)
        base64.urlsafe_b64decode(padded)
        return True
    except (ValueError, TypeError):
        return False


def constant_time_compare(a: str, b: str) -> bool:
    """
    Perform constant-time string comparison.

    Prevents timing attacks by ensuring comparison time doesn't depend
    on where strings differ.

    Args:
        a: First string
        b: Second string

    Returns:
        bool: True if strings are equal, False otherwise
    """
    return secrets.compare_digest(a.encode('utf-8'), b.encode('utf-8'))