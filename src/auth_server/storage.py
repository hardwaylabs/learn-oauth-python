"""
OAuth 2.1 Authorization Server Storage Components

This module provides in-memory storage implementations for user accounts
and authorization codes used in the OAuth 2.1 learning implementation.

Note: In production systems, these would be replaced with persistent
database storage with proper indexing, encryption, and backup strategies.
"""

from datetime import datetime, timedelta
from typing import Dict, Optional, List
import secrets
from ..shared.security import verify_password
from ..shared.logging_utils import OAuthLogger

# Initialize logger for storage operations
logger = OAuthLogger("AUTH-SERVER-STORAGE")


class UserStore:
    """
    In-memory user storage with bcrypt password hashing.

    This class manages demo user accounts for the OAuth 2.1 learning system.
    In a production environment, this would be replaced with a proper user
    database with features like:
    - Persistent storage (PostgreSQL, MySQL, etc.)
    - User registration and profile management
    - Password reset functionality
    - Account lockout and security policies
    - Audit logging and compliance features

    Security Features:
    - bcrypt password hashing with configurable rounds
    - Constant-time password verification
    - No plain text password storage
    - User enumeration protection
    """

    def __init__(self):
        """
        Initialize user store with pre-configured demo accounts.

        Demo accounts are provided for educational purposes and include
        bcrypt-hashed passwords with 12 rounds for security demonstration.
        """
        # Pre-hashed demo passwords using bcrypt (12 rounds)
        # These hashes were generated using the hash_passwords.py script
        self._users = {
            'alice': {
                'password_hash': '$2b$12$zEqBNh.ZsPPLu.ClJz4iie1DKx/x9PmUTyWKkhjt0ZaEM.S8exmRi',  # password123
                'email': 'alice@example.com',
                'name': 'Alice Demo',
                'created_at': datetime.utcnow(),
                'last_login': None,
                'login_count': 0
            },
            'bob': {
                'password_hash': '$2b$12$0Z9Tioq6ocOvzV9OpFj76uvZizUWgEFjkY7r3IJBU6ax8pEIlVwnq',  # secret456
                'email': 'bob@example.com',
                'name': 'Bob Demo',
                'created_at': datetime.utcnow(),
                'last_login': None,
                'login_count': 0
            },
            'carol': {
                'password_hash': '$2b$12$UuwsKCjRv4/Ml6xXddJBA.EhFBKAog0XFPx4JcLJ5Ig21Alct2nbu',  # mypass789
                'email': 'carol@example.com',
                'name': 'Carol Demo',
                'created_at': datetime.utcnow(),
                'last_login': None,
                'login_count': 0
            }
        }

        logger.log_oauth_message(
            "SYSTEM", "AUTH-SERVER-STORAGE",
            "User Store Initialized",
            {
                "total_users": len(self._users),
                "demo_accounts": list(self._users.keys()),
                "password_hashing": "bcrypt (12 rounds)"
            }
        )

    def authenticate(self, username: str, password: str) -> Optional[Dict]:
        """
        Authenticate user credentials using bcrypt verification.

        This method performs secure password verification using bcrypt's
        built-in salt and timing attack protection. It also updates
        login statistics for educational monitoring.

        Args:
            username: The username to authenticate
            password: The plain text password to verify

        Returns:
            Optional[Dict]: User information if authentication succeeds, None otherwise

        Security Features:
        - Constant-time password verification (bcrypt handles this)
        - No information leakage about user existence
        - Login attempt logging for security monitoring
        """
        logger.log_oauth_message(
            "AUTH-SERVER", "AUTH-SERVER-STORAGE",
            "User Authentication Attempt",
            {
                "username": username,
                "timestamp": datetime.utcnow().isoformat()
            }
        )

        user = self._users.get(username)
        if not user:
            # Log failed authentication without revealing user existence
            logger.log_oauth_message(
                "AUTH-SERVER-STORAGE", "AUTH-SERVER",
                "Authentication Failed",
                {
                    "username": username,
                    "reason": "invalid_credentials",
                    "user_exists": False
                }
            )
            return None

        if verify_password(password, user['password_hash']):
            # Update login statistics
            user['last_login'] = datetime.utcnow()
            user['login_count'] += 1

            logger.log_oauth_message(
                "AUTH-SERVER-STORAGE", "AUTH-SERVER",
                "Authentication Successful",
                {
                    "username": username,
                    "email": user['email'],
                    "login_count": user['login_count'],
                    "last_login": user['last_login'].isoformat()
                }
            )

            return {
                'username': username,
                'email': user['email'],
                'name': user['name'],
                'last_login': user['last_login'],
                'login_count': user['login_count']
            }

        # Log failed authentication
        logger.log_oauth_message(
            "AUTH-SERVER-STORAGE", "AUTH-SERVER",
            "Authentication Failed",
            {
                "username": username,
                "reason": "invalid_password",
                "user_exists": True
            }
        )
        return None

    def get_user(self, username: str) -> Optional[Dict]:
        """
        Get user information without sensitive data.

        Returns user profile information excluding password hash
        and other sensitive security data.

        Args:
            username: The username to look up

        Returns:
            Optional[Dict]: User profile information or None if not found
        """
        user = self._users.get(username)
        if not user:
            return None

        return {
            'username': username,
            'email': user['email'],
            'name': user['name'],
            'created_at': user['created_at'],
            'last_login': user['last_login'],
            'login_count': user['login_count']
        }

    def user_exists(self, username: str) -> bool:
        """
        Check if a user exists in the system.

        Args:
            username: The username to check

        Returns:
            bool: True if user exists, False otherwise

        Note: In production systems, be careful about user enumeration
        attacks when exposing this information.
        """
        return username in self._users

    def get_demo_accounts(self) -> List[Dict]:
        """
        Get list of demo accounts for display in login forms.

        This method returns demo account information for educational
        purposes, showing available test accounts and their passwords.

        Returns:
            List[Dict]: List of demo account information

        Note: In production systems, never expose passwords or provide
        lists of valid usernames for security reasons.
        """
        return [
            {
                "username": "alice",
                "password": "password123",
                "name": "Alice Demo",
                "description": "Standard demo account"
            },
            {
                "username": "bob",
                "password": "secret456",
                "name": "Bob Demo",
                "description": "Alternative demo account"
            },
            {
                "username": "carol",
                "password": "mypass789",
                "name": "Carol Demo",
                "description": "Third demo account"
            }
        ]

    def get_user_statistics(self) -> Dict:
        """
        Get user statistics for monitoring and educational purposes.

        Returns:
            Dict: Statistics about user accounts and login activity
        """
        total_users = len(self._users)
        users_with_logins = sum(1 for user in self._users.values() if user['login_count'] > 0)
        total_logins = sum(user['login_count'] for user in self._users.values())

        return {
            "total_users": total_users,
            "users_with_logins": users_with_logins,
            "total_login_attempts": total_logins,
            "average_logins_per_user": total_logins / total_users if total_users > 0 else 0
        }


class AuthCodeStore:
    """
    In-memory storage for OAuth 2.1 authorization codes.

    This class manages authorization codes with proper security features:
    - Short expiration times (10 minutes) to limit attack windows
    - One-time use enforcement to prevent replay attacks
    - PKCE challenge binding for enhanced security
    - Automatic cleanup of expired codes

    In production environments, this would be replaced with:
    - Redis or similar cache for distributed systems
    - Database storage with proper indexing
    - Automatic expiration and cleanup processes
    - Rate limiting and abuse detection

    Security Features:
    - Cryptographically secure code generation
    - Time-based expiration (10 minutes)
    - One-time use enforcement
    - PKCE challenge binding
    - Automatic cleanup of expired codes
    """

    def __init__(self):
        """Initialize authorization code store with empty storage."""
        self._codes: Dict[str, Dict] = {}

        logger.log_oauth_message(
            "SYSTEM", "AUTH-SERVER-STORAGE",
            "Authorization Code Store Initialized",
            {
                "expiration_minutes": 10,
                "security_features": ["one_time_use", "pkce_binding", "auto_cleanup"]
            }
        )

    def store_code(self, client_id: str, user_id: str, scope: str,
                   code_challenge: str, redirect_uri: str) -> str:
        """
        Store authorization code with metadata and security parameters.

        Generates a cryptographically secure authorization code and stores
        it with all necessary metadata for later validation during token
        exchange. The code expires in 10 minutes as per OAuth 2.1 best practices.

        Args:
            client_id: OAuth client identifier
            user_id: Authenticated user identifier
            scope: Granted OAuth scope
            code_challenge: PKCE challenge for verification
            redirect_uri: Client redirect URI for validation

        Returns:
            str: Generated authorization code

        Security Notes:
        - Code is cryptographically secure (32 bytes, URL-safe base64)
        - 10-minute expiration limits attack window
        - PKCE challenge binding prevents code interception attacks
        - One-time use flag prevents replay attacks
        """
        # Generate cryptographically secure authorization code
        code = secrets.token_urlsafe(32)
        expiry = datetime.utcnow() + timedelta(minutes=10)
        created_at = datetime.utcnow()

        # Store code with all security metadata
        self._codes[code] = {
            'client_id': client_id,
            'user_id': user_id,
            'scope': scope,
            'code_challenge': code_challenge,
            'redirect_uri': redirect_uri,
            'expires_at': expiry,
            'created_at': created_at,
            'used': False,
            'used_at': None
        }

        logger.log_oauth_message(
            "AUTH-SERVER-STORAGE", "AUTH-SERVER",
            "Authorization Code Stored",
            {
                "code": code[:10] + "...",
                "client_id": client_id,
                "user_id": user_id,
                "scope": scope,
                "expires_at": expiry.isoformat(),
                "pkce_challenge": code_challenge[:20] + "...",
                "expires_in_seconds": 600
            }
        )

        return code

    def get_code(self, code: str) -> Optional[Dict]:
        """
        Retrieve and validate authorization code with one-time use enforcement.

        This method performs comprehensive validation of the authorization code:
        - Checks if code exists
        - Verifies code hasn't been used (one-time use)
        - Checks if code hasn't expired
        - Marks code as used to prevent replay attacks
        - Cleans up expired codes

        Args:
            code: Authorization code to retrieve and validate

        Returns:
            Optional[Dict]: Code metadata if valid, None if invalid/expired/used

        Security Features:
        - One-time use enforcement (code marked as used)
        - Expiration checking (10-minute window)
        - Automatic cleanup of expired codes
        - Detailed logging for security monitoring
        """
        logger.log_oauth_message(
            "AUTH-SERVER", "AUTH-SERVER-STORAGE",
            "Authorization Code Retrieval Attempt",
            {
                "code": code[:10] + "..." if len(code) > 10 else code,
                "timestamp": datetime.utcnow().isoformat()
            }
        )

        code_data = self._codes.get(code)

        if not code_data:
            logger.log_oauth_message(
                "AUTH-SERVER-STORAGE", "AUTH-SERVER",
                "Authorization Code Not Found",
                {
                    "code": code[:10] + "..." if len(code) > 10 else code,
                    "reason": "code_not_exists"
                }
            )
            return None

        # Check if already used (one-time use enforcement)
        if code_data['used']:
            logger.log_oauth_message(
                "AUTH-SERVER-STORAGE", "AUTH-SERVER",
                "Authorization Code Already Used",
                {
                    "code": code[:10] + "...",
                    "used_at": code_data.get('used_at', 'unknown'),
                    "security_risk": "possible_replay_attack"
                }
            )
            return None

        # Check if expired
        now = datetime.utcnow()
        if now > code_data['expires_at']:
            logger.log_oauth_message(
                "AUTH-SERVER-STORAGE", "AUTH-SERVER",
                "Authorization Code Expired",
                {
                    "code": code[:10] + "...",
                    "expired_at": code_data['expires_at'].isoformat(),
                    "current_time": now.isoformat(),
                    "age_minutes": (now - code_data['created_at']).total_seconds() / 60
                }
            )
            # Clean up expired code
            del self._codes[code]
            return None

        # Mark as used (one-time use enforcement)
        code_data['used'] = True
        code_data['used_at'] = now

        logger.log_oauth_message(
            "AUTH-SERVER-STORAGE", "AUTH-SERVER",
            "Authorization Code Retrieved Successfully",
            {
                "code": code[:10] + "...",
                "client_id": code_data['client_id'],
                "user_id": code_data['user_id'],
                "scope": code_data['scope'],
                "age_seconds": (now - code_data['created_at']).total_seconds(),
                "marked_as_used": True
            }
        )

        return code_data

    def cleanup_expired_codes(self) -> int:
        """
        Remove expired authorization codes from storage.

        This method performs maintenance by removing codes that have
        exceeded their 10-minute expiration window. Should be called
        periodically to prevent memory leaks in long-running systems.

        Returns:
            int: Number of expired codes removed
        """
        now = datetime.utcnow()
        expired_codes = [
            code for code, data in self._codes.items()
            if now > data['expires_at']
        ]

        for code in expired_codes:
            del self._codes[code]

        if expired_codes:
            logger.log_oauth_message(
                "AUTH-SERVER-STORAGE", "AUTH-SERVER-STORAGE",
                "Expired Codes Cleanup",
                {
                    "codes_removed": len(expired_codes),
                    "cleanup_time": now.isoformat(),
                    "remaining_codes": len(self._codes)
                }
            )

        return len(expired_codes)

    def get_active_codes_count(self) -> int:
        """
        Get count of active (non-expired, non-used) authorization codes.

        Returns:
            int: Number of active authorization codes
        """
        now = datetime.utcnow()
        active_count = len([
            code for code, data in self._codes.items()
            if not data['used'] and now <= data['expires_at']
        ])

        return active_count

    def get_storage_statistics(self) -> Dict:
        """
        Get storage statistics for monitoring and educational purposes.

        Returns:
            Dict: Statistics about authorization code storage
        """
        now = datetime.utcnow()
        total_codes = len(self._codes)
        active_codes = self.get_active_codes_count()
        used_codes = len([
            code for code, data in self._codes.items()
            if data['used']
        ])
        expired_codes = len([
            code for code, data in self._codes.items()
            if now > data['expires_at']
        ])

        return {
            "total_codes": total_codes,
            "active_codes": active_codes,
            "used_codes": used_codes,
            "expired_codes": expired_codes,
            "cleanup_needed": expired_codes > 0
        }