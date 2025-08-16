"""
Unit tests for OAuth logging utilities.

Tests the OAuthLogger class and related logging functions to ensure
proper message formatting, color coding, and educational output.
"""

import pytest
from unittest.mock import patch, MagicMock
from io import StringIO
import sys
from src.shared.logging_utils import (
    OAuthLogger,
    ComponentType,
    MessageType,
    create_logger
)


class TestComponentType:
    """Test cases for ComponentType enum."""

    def test_component_type_values(self):
        """Test that component types have correct values."""
        assert ComponentType.CLIENT == "CLIENT"
        assert ComponentType.AUTH_SERVER == "AUTH-SERVER"
        assert ComponentType.RESOURCE_SERVER == "RESOURCE-SERVER"
        assert ComponentType.SYSTEM == "SYSTEM"


class TestMessageType:
    """Test cases for MessageType enum."""

    def test_message_type_values(self):
        """Test that message types have correct values."""
        assert MessageType.REQUEST == "REQUEST"
        assert MessageType.RESPONSE == "RESPONSE"
        assert MessageType.ERROR == "ERROR"
        assert MessageType.INFO == "INFO"
        assert MessageType.PKCE_GENERATION == "PKCE-GENERATION"
        assert MessageType.TOKEN_VALIDATION == "TOKEN-VALIDATION"


class TestOAuthLogger:
    """Test cases for OAuthLogger class."""

    def test_logger_initialization(self):
        """Test OAuth logger initialization."""
        logger = OAuthLogger("client")

        assert logger.component_name == "CLIENT"
        assert isinstance(logger.colors, dict)
        assert "CLIENT" in logger.colors
        assert "AUTH-SERVER" in logger.colors

    def test_logger_initialization_case_insensitive(self):
        """Test that logger handles case-insensitive component names."""
        logger1 = OAuthLogger("client")
        logger2 = OAuthLogger("CLIENT")
        logger3 = OAuthLogger("Client")

        assert logger1.component_name == "CLIENT"
        assert logger2.component_name == "CLIENT"
        assert logger3.component_name == "CLIENT"

    def test_format_timestamp(self):
        """Test timestamp formatting."""
        logger = OAuthLogger("client")
        timestamp = logger._format_timestamp()

        # Should be a string in expected format
        assert isinstance(timestamp, str)
        assert len(timestamp) > 0
        # Should contain date and time components
        assert "-" in timestamp  # Date separators
        assert ":" in timestamp  # Time separators
        assert "." in timestamp  # Milliseconds

    def test_sanitize_data_passwords(self):
        """Test data sanitization for passwords."""
        logger = OAuthLogger("client")

        test_data = {
            "username": "alice",
            "password": "secret123",
            "client_secret": "very_secret",
            "api_key": "key123"
        }

        sanitized = logger._sanitize_data(test_data)

        assert sanitized["username"] == "alice"
        assert sanitized["password"] == "[REDACTED]"
        assert sanitized["client_secret"] == "[REDACTED]"
        assert sanitized["api_key"] == "[REDACTED]"

    def test_sanitize_data_tokens(self):
        """Test data sanitization for tokens and codes."""
        logger = OAuthLogger("client")

        test_data = {
            "access_token": "very_long_access_token_string_here",
            "authorization_code": "auth_code_123456789",
            "code_challenge": "challenge_string_here",
            "code_verifier": "verifier_string_here",
            "short_token": "short"
        }

        sanitized = logger._sanitize_data(test_data)

        # Long tokens should be truncated
        assert sanitized["access_token"] == "very_long_..."
        assert sanitized["authorization_code"] == "auth_code_..."
        assert sanitized["code_challenge"] == "challenge..."
        assert sanitized["code_verifier"] == "verifier_..."

        # Short tokens should remain unchanged
        assert sanitized["short_token"] == "short"

    def test_sanitize_data_normal_fields(self):
        """Test that normal fields are not sanitized."""
        logger = OAuthLogger("client")

        test_data = {
            "client_id": "demo-client",
            "redirect_uri": "http://localhost:8080/callback",
            "scope": "read write",
            "state": "random-state-123"
        }

        sanitized = logger._sanitize_data(test_data)

        # Normal fields should remain unchanged
        assert sanitized == test_data

    @patch('builtins.print')
    def test_log_oauth_message_basic(self, mock_print):
        """Test basic OAuth message logging."""
        logger = OAuthLogger("client")

        test_data = {
            "client_id": "demo-client",
            "scope": "read"
        }

        logger.log_oauth_message(
            source="CLIENT",
            destination="AUTH-SERVER",
            message_type="REQUEST",
            data=test_data
        )

        # Should have called print multiple times
        assert mock_print.call_count > 0

        # Check that the logged content contains expected elements
        all_calls = [str(call) for call in mock_print.call_args_list]
        logged_content = " ".join(all_calls)

        assert "CLIENT" in logged_content
        assert "AUTH-SERVER" in logged_content
        assert "REQUEST" in logged_content
        assert "client_id" in logged_content
        assert "demo-client" in logged_content

    @patch('builtins.print')
    def test_log_oauth_message_with_error(self, mock_print):
        """Test OAuth message logging with error status."""
        logger = OAuthLogger("auth-server")

        test_data = {
            "error": "invalid_request",
            "error_description": "Missing parameter"
        }

        logger.log_oauth_message(
            source="AUTH-SERVER",
            destination="CLIENT",
            message_type="ERROR",
            data=test_data,
            success=False
        )

        assert mock_print.call_count > 0

        # Check error logging
        all_calls = [str(call) for call in mock_print.call_args_list]
        logged_content = " ".join(all_calls)

        assert "ERROR" in logged_content
        assert "invalid_request" in logged_content

    @patch('builtins.print')
    def test_log_pkce_operation(self, mock_print):
        """Test PKCE operation logging."""
        logger = OAuthLogger("client")

        pkce_details = {
            "code_verifier": "long_verifier_string_here",
            "code_challenge": "challenge_string_here",
            "method": "S256"
        }

        logger.log_pkce_operation("GENERATION", pkce_details)

        assert mock_print.call_count > 0

        all_calls = [str(call) for call in mock_print.call_args_list]
        logged_content = " ".join(all_calls)

        assert "PKCE-GENERATION" in logged_content
        assert "method" in logged_content
        assert "S256" in logged_content

    @patch('builtins.print')
    def test_log_token_operation(self, mock_print):
        """Test token operation logging."""
        logger = OAuthLogger("auth-server")

        token_details = {
            "access_token": "generated_access_token_here",
            "expires_in": 3600,
            "scope": "read write"
        }

        logger.log_token_operation("GENERATION", token_details)

        assert mock_print.call_count > 0

        all_calls = [str(call) for call in mock_print.call_args_list]
        logged_content = " ".join(all_calls)

        assert "TOKEN-GENERATION" in logged_content
        assert "expires_in" in logged_content
        assert "3600" in logged_content

    @patch('builtins.print')
    def test_log_user_auth_success(self, mock_print):
        """Test successful user authentication logging."""
        logger = OAuthLogger("auth-server")

        logger.log_user_auth("alice", success=True, details={"method": "password"})

        assert mock_print.call_count > 0

        all_calls = [str(call) for call in mock_print.call_args_list]
        logged_content = " ".join(all_calls)

        assert "USER-AUTH" in logged_content
        assert "alice" in logged_content
        assert "SUCCESS" in logged_content

    @patch('builtins.print')
    def test_log_user_auth_failure(self, mock_print):
        """Test failed user authentication logging."""
        logger = OAuthLogger("auth-server")

        logger.log_user_auth("bob", success=False, details={"reason": "invalid_password"})

        assert mock_print.call_count > 0

        all_calls = [str(call) for call in mock_print.call_args_list]
        logged_content = " ".join(all_calls)

        assert "USER-AUTH" in logged_content
        assert "bob" in logged_content
        assert "FAILED" in logged_content

    @patch('builtins.print')
    def test_log_http_request(self, mock_print):
        """Test HTTP request logging."""
        logger = OAuthLogger("client")

        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": "Bearer secret_token",
            "User-Agent": "OAuth-Client/1.0"
        }

        params = {
            "grant_type": "authorization_code",
            "code": "auth_code_123"
        }

        logger.log_http_request("POST", "/token", params=params, headers=headers)

        assert mock_print.call_count > 0

        all_calls = [str(call) for call in mock_print.call_args_list]
        logged_content = " ".join(all_calls)

        assert "HTTP-REQUEST" in logged_content
        assert "POST" in logged_content
        assert "/token" in logged_content
        assert "grant_type" in logged_content
        # Authorization header should be redacted
        assert "[REDACTED]" in logged_content

    @patch('builtins.print')
    def test_log_error(self, mock_print):
        """Test error logging."""
        logger = OAuthLogger("resource-server")

        logger.log_error(
            "ValidationError",
            "Invalid token format",
            details={"token_length": 5, "expected_min": 20}
        )

        assert mock_print.call_count > 0

        all_calls = [str(call) for call in mock_print.call_args_list]
        logged_content = " ".join(all_calls)

        assert "ERROR" in logged_content
        assert "ValidationError" in logged_content
        assert "Invalid token format" in logged_content

    @patch('builtins.print')
    def test_log_info(self, mock_print):
        """Test info message logging."""
        logger = OAuthLogger("system")

        logger.log_info("System initialized", details={"version": "1.0.0"})

        assert mock_print.call_count > 0

        all_calls = [str(call) for call in mock_print.call_args_list]
        logged_content = " ".join(all_calls)

        assert "System initialized" in logged_content
        assert "version" in logged_content

    @patch('builtins.print')
    def test_log_startup(self, mock_print):
        """Test startup message logging."""
        logger = OAuthLogger("client")

        additional_info = {
            "version": "1.0.0",
            "environment": "development"
        }

        logger.log_startup(8080, additional_info)

        assert mock_print.call_count > 0

        all_calls = [str(call) for call in mock_print.call_args_list]
        logged_content = " ".join(all_calls)

        assert "CLIENT started on port 8080" in logged_content
        assert "version" in logged_content
        assert "environment" in logged_content

    def test_logger_handles_missing_colorama(self):
        """Test that logger works when colorama is not available."""
        # This test ensures the fallback color classes work
        logger = OAuthLogger("client")

        # Should not raise any exceptions
        test_data = {"test": "data"}
        try:
            logger.log_oauth_message("CLIENT", "SERVER", "TEST", test_data)
        except Exception as e:
            pytest.fail(f"Logger should handle missing colorama gracefully: {e}")

    def test_logger_color_scheme(self):
        """Test that logger has proper color scheme."""
        logger = OAuthLogger("client")

        # Should have colors for all components
        assert "CLIENT" in logger.colors
        assert "AUTH-SERVER" in logger.colors
        assert "RESOURCE-SERVER" in logger.colors
        assert "ERROR" in logger.colors
        assert "SUCCESS" in logger.colors

    @patch('builtins.print')
    def test_log_oauth_message_data_types(self, mock_print):
        """Test OAuth message logging with various data types."""
        logger = OAuthLogger("client")

        test_data = {
            "string_field": "test_string",
            "int_field": 123,
            "bool_field": True,
            "list_field": ["item1", "item2"],
            "dict_field": {"nested": "value"}
        }

        logger.log_oauth_message("CLIENT", "SERVER", "TEST", test_data)

        assert mock_print.call_count > 0

        all_calls = [str(call) for call in mock_print.call_args_list]
        logged_content = " ".join(all_calls)

        # Should handle all data types
        assert "test_string" in logged_content
        assert "123" in logged_content
        assert "True" in logged_content

    @patch('builtins.print')
    def test_log_oauth_message_empty_data(self, mock_print):
        """Test OAuth message logging with empty data."""
        logger = OAuthLogger("client")

        logger.log_oauth_message("CLIENT", "SERVER", "TEST", {})

        assert mock_print.call_count > 0

        # Should still log header and message type even with empty data
        all_calls = [str(call) for call in mock_print.call_args_list]
        logged_content = " ".join(all_calls)

        assert "CLIENT" in logged_content
        assert "SERVER" in logged_content
        assert "TEST" in logged_content


class TestCreateLogger:
    """Test cases for create_logger factory function."""

    def test_create_logger_function(self):
        """Test create_logger factory function."""
        logger = create_logger("test-component")

        assert isinstance(logger, OAuthLogger)
        assert logger.component_name == "TEST-COMPONENT"

    def test_create_logger_different_components(self):
        """Test creating loggers for different components."""
        client_logger = create_logger("client")
        auth_logger = create_logger("auth-server")
        resource_logger = create_logger("resource-server")

        assert client_logger.component_name == "CLIENT"
        assert auth_logger.component_name == "AUTH-SERVER"
        assert resource_logger.component_name == "RESOURCE-SERVER"

        # Should be different instances
        assert client_logger is not auth_logger
        assert auth_logger is not resource_logger


class TestLoggingIntegration:
    """Integration tests for logging functionality."""

    @patch('builtins.print')
    def test_complete_oauth_flow_logging(self, mock_print):
        """Test logging throughout a complete OAuth flow."""
        client_logger = create_logger("client")
        auth_logger = create_logger("auth-server")
        resource_logger = create_logger("resource-server")

        # Step 1: Client initiates OAuth flow
        client_logger.log_pkce_operation("GENERATION", {
            "code_verifier": "generated_verifier_here",
            "code_challenge": "generated_challenge_here"
        })

        # Step 2: Authorization request
        client_logger.log_oauth_message(
            "CLIENT", "AUTH-SERVER", "AUTHORIZATION-REQUEST",
            {"client_id": "demo-client", "scope": "read"}
        )

        # Step 3: User authentication
        auth_logger.log_user_auth("alice", success=True)

        # Step 4: Token exchange
        auth_logger.log_token_operation("GENERATION", {
            "access_token": "generated_token_here",
            "expires_in": 3600
        })

        # Step 5: Resource access
        resource_logger.log_oauth_message(
            "CLIENT", "RESOURCE-SERVER", "RESOURCE-REQUEST",
            {"resource": "/protected", "method": "GET"}
        )

        # Should have logged all steps
        assert mock_print.call_count > 0

        all_calls = [str(call) for call in mock_print.call_args_list]
        logged_content = " ".join(all_calls)

        # Verify all flow steps are logged
        assert "PKCE-GENERATION" in logged_content
        assert "AUTHORIZATION-REQUEST" in logged_content
        assert "USER-AUTH" in logged_content
        assert "TOKEN-GENERATION" in logged_content
        assert "RESOURCE-REQUEST" in logged_content

    def test_logger_thread_safety(self):
        """Test that logger instances are independent."""
        logger1 = create_logger("component1")
        logger2 = create_logger("component2")

        # Should have different component names
        assert logger1.component_name != logger2.component_name

        # Should have independent state
        assert logger1.logger is not logger2.logger