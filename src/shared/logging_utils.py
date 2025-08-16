"""
Colored logging utilities for OAuth 2.1 educational implementation.

This module provides colored console logging that matches the Go implementation
style, with component identification, timestamps, and message formatting for
clear visualization of OAuth message flows.
"""

import logging
from datetime import datetime
from typing import Dict, Any, Optional
from enum import Enum


# Try to import colorama, fall back to no colors if not available
try:
    from colorama import Fore, Style, Back, init
    init(autoreset=True)  # Initialize colorama for Windows compatibility
    COLORAMA_AVAILABLE = True
except ImportError:
    # Fallback class for when colorama is not available
    class _ForeColors:
        RED = ""
        GREEN = ""
        YELLOW = ""
        BLUE = ""
        MAGENTA = ""
        CYAN = ""
        WHITE = ""
        RESET = ""

    class _StyleColors:
        BRIGHT = ""
        DIM = ""
        RESET_ALL = ""

    class _BackColors:
        BLACK = ""

    Fore = _ForeColors()
    Style = _StyleColors()
    Back = _BackColors()
    COLORAMA_AVAILABLE = False


class ComponentType(str, Enum):
    """OAuth system component types."""
    CLIENT = "CLIENT"
    AUTH_SERVER = "AUTH-SERVER"
    RESOURCE_SERVER = "RESOURCE-SERVER"
    SYSTEM = "SYSTEM"


class MessageType(str, Enum):
    """OAuth message types for logging."""
    REQUEST = "REQUEST"
    RESPONSE = "RESPONSE"
    ERROR = "ERROR"
    INFO = "INFO"
    DEBUG = "DEBUG"
    PKCE_GENERATION = "PKCE-GENERATION"
    PKCE_VERIFICATION = "PKCE-VERIFICATION"
    TOKEN_GENERATION = "TOKEN-GENERATION"
    TOKEN_VALIDATION = "TOKEN-VALIDATION"
    USER_AUTH = "USER-AUTH"
    REDIRECT = "REDIRECT"


class OAuthLogger:
    """
    Colored logger for OAuth 2.1 message flows.

    Provides educational logging with color coding, timestamps, and structured
    message formatting to help visualize OAuth flows and debug issues.
    """

    def __init__(self, component_name: str):
        """
        Initialize OAuth logger for a specific component.

        Args:
            component_name: Name of the component (CLIENT, AUTH-SERVER, etc.)
        """
        self.component_name = component_name.upper()
        self.colors = self._get_component_colors()

        # Set up Python logging
        self.logger = logging.getLogger(f"oauth.{component_name.lower()}")
        self.logger.setLevel(logging.INFO)

        # Remove existing handlers to avoid duplicates
        self.logger.handlers.clear()

        # Add console handler
        handler = logging.StreamHandler()
        handler.setLevel(logging.INFO)
        self.logger.addHandler(handler)
        self.logger.propagate = False

    def _get_component_colors(self) -> Dict[str, str]:
        """Get color scheme for different components and message types."""
        return {
            'CLIENT': Fore.BLUE + Style.BRIGHT,
            'AUTH-SERVER': Fore.GREEN + Style.BRIGHT,
            'RESOURCE-SERVER': Fore.YELLOW + Style.BRIGHT,
            'SYSTEM': Fore.MAGENTA + Style.BRIGHT,
            'ERROR': Fore.RED + Style.BRIGHT,
            'SUCCESS': Fore.GREEN + Style.BRIGHT,
            'INFO': Fore.CYAN,
            'DEBUG': Fore.WHITE + Style.DIM,
            'HEADER': Fore.WHITE + Style.BRIGHT,
            'SEPARATOR': Fore.WHITE + Style.DIM,
            'RESET': Style.RESET_ALL
        }

    def _format_timestamp(self) -> str:
        """Format current timestamp for log messages."""
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

    def _sanitize_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitize sensitive data for logging.

        Redacts passwords and truncates long tokens for security.
        """
        sanitized = {}
        for key, value in data.items():
            key_lower = key.lower()

            if any(sensitive in key_lower for sensitive in ['password', 'secret', 'key']):
                sanitized[key] = '[REDACTED]'
            elif any(token in key_lower for token in ['token', 'code', 'challenge', 'verifier']):
                # Show first 10 characters of tokens/codes for debugging
                if isinstance(value, str) and len(value) > 10:
                    sanitized[key] = f"{value[:10]}..."
                else:
                    sanitized[key] = value
            else:
                sanitized[key] = value

        return sanitized

    def log_oauth_message(self,
                         source: str,
                         destination: str,
                         message_type: str,
                         data: Dict[str, Any],
                         success: bool = True):
        """
        Log OAuth message with color coding and formatting.

        Args:
            source: Source component name
            destination: Destination component name
            message_type: Type of message (REQUEST, RESPONSE, etc.)
            data: Message data dictionary
            success: Whether the operation was successful
        """
        timestamp = self._format_timestamp()
        source_color = self.colors.get(source.upper(), self.colors['INFO'])
        dest_color = self.colors.get(destination.upper(), self.colors['INFO'])

        # Choose message color based on type and success
        if not success:
            msg_color = self.colors['ERROR']
        elif message_type in ['RESPONSE', 'SUCCESS']:
            msg_color = self.colors['SUCCESS']
        else:
            msg_color = self.colors['INFO']

        # Print header with arrow
        header = f"{self.colors['HEADER']}[{timestamp}] {source_color}{source}{self.colors['RESET']} → {dest_color}{destination}{self.colors['RESET']}"
        print(header)

        # Print message type
        print(f"{msg_color}{message_type}:{self.colors['RESET']}")

        # Print sanitized data
        sanitized_data = self._sanitize_data(data)
        for key, value in sanitized_data.items():
            print(f"  {self.colors['INFO']}{key}:{self.colors['RESET']} {value}")

        # Print separator
        print(f"{self.colors['SEPARATOR']}{'-' * 60}{self.colors['RESET']}")
        print()  # Empty line for readability

    def log_pkce_operation(self,
                          operation: str,
                          details: Dict[str, Any],
                          success: bool = True):
        """
        Log PKCE-specific operations with detailed information.

        Args:
            operation: PKCE operation (generation, verification, etc.)
            details: Operation details
            success: Whether operation was successful
        """
        self.log_oauth_message(
            source=self.component_name,
            destination=self.component_name,
            message_type=f"PKCE-{operation.upper()}",
            data=details,
            success=success
        )

    def log_token_operation(self,
                           operation: str,
                           details: Dict[str, Any],
                           success: bool = True):
        """
        Log token-related operations.

        Args:
            operation: Token operation (generation, validation, etc.)
            details: Operation details
            success: Whether operation was successful
        """
        self.log_oauth_message(
            source=self.component_name,
            destination=self.component_name,
            message_type=f"TOKEN-{operation.upper()}",
            data=details,
            success=success
        )

    def log_user_auth(self,
                     username: str,
                     success: bool,
                     details: Optional[Dict[str, Any]] = None):
        """
        Log user authentication attempts.

        Args:
            username: Username being authenticated
            success: Whether authentication succeeded
            details: Additional authentication details
        """
        auth_data = {"username": username, "result": "SUCCESS" if success else "FAILED"}
        if details:
            auth_data.update(details)

        self.log_oauth_message(
            source=self.component_name,
            destination="USER-DATABASE",
            message_type="USER-AUTH",
            data=auth_data,
            success=success
        )

    def log_http_request(self,
                        method: str,
                        path: str,
                        params: Optional[Dict[str, Any]] = None,
                        headers: Optional[Dict[str, str]] = None):
        """
        Log HTTP request details.

        Args:
            method: HTTP method
            path: Request path
            params: Query parameters or form data
            headers: Request headers (sensitive headers will be redacted)
        """
        request_data = {
            "method": method,
            "path": path
        }

        if params:
            request_data["parameters"] = params

        if headers:
            # Redact sensitive headers
            safe_headers = {}
            for key, value in headers.items():
                if key.lower() in ['authorization', 'cookie', 'x-api-key']:
                    safe_headers[key] = '[REDACTED]'
                else:
                    safe_headers[key] = value
            request_data["headers"] = safe_headers

        self.log_oauth_message(
            source="HTTP-CLIENT",
            destination=self.component_name,
            message_type="HTTP-REQUEST",
            data=request_data
        )

    def log_error(self,
                 error_type: str,
                 message: str,
                 details: Optional[Dict[str, Any]] = None):
        """
        Log error messages with context.

        Args:
            error_type: Type of error
            message: Error message
            details: Additional error context
        """
        error_data = {
            "error_type": error_type,
            "message": message
        }

        if details:
            error_data.update(details)

        self.log_oauth_message(
            source=self.component_name,
            destination="ERROR-HANDLER",
            message_type="ERROR",
            data=error_data,
            success=False
        )

    def log_info(self, message: str, details: Optional[Dict[str, Any]] = None):
        """
        Log informational messages.

        Args:
            message: Info message
            details: Additional context
        """
        info_data = {"message": message}
        if details:
            info_data.update(details)

        print(f"{self.colors['INFO']}[{self._format_timestamp()}] {self.component_name}: {message}{self.colors['RESET']}")
        if details:
            for key, value in details.items():
                print(f"  {key}: {value}")
        print()

    def log_startup(self, port: int, additional_info: Optional[Dict[str, Any]] = None):
        """
        Log component startup information.

        Args:
            port: Port number the component is running on
            additional_info: Additional startup information
        """
        startup_data = {
            "component": self.component_name,
            "port": port,
            "status": "STARTED"
        }

        if additional_info:
            startup_data.update(additional_info)

        print(f"{self.colors['SUCCESS']}🚀 {self.component_name} started on port {port}{self.colors['RESET']}")
        if additional_info:
            for key, value in additional_info.items():
                print(f"   {key}: {value}")
        print(f"{self.colors['SEPARATOR']}{'-' * 60}{self.colors['RESET']}")
        print()


def create_logger(component_name: str) -> OAuthLogger:
    """
    Factory function to create OAuth logger instances.

    Args:
        component_name: Name of the component

    Returns:
        OAuthLogger: Configured logger instance
    """
    return OAuthLogger(component_name)