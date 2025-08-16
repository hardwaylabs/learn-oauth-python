"""
OAuth 2.1 Resource Server - Educational Implementation

This FastAPI application implements an OAuth 2.1 resource server that validates
Bearer tokens and serves protected resources. It demonstrates proper token
validation, scope checking, and secure resource access patterns.

Key Features:
- Bearer token validation for protected endpoints
- Comprehensive request/response logging for education
- Protected resource serving with access control
- User information endpoint (userinfo)
- Detailed security logging and monitoring

Security Features:
- Authorization header parsing and validation
- Token format verification and security checks
- Scope-based access control (extensible)
- Request logging for security monitoring
- Error handling without information leakage

Educational Value:
- Clear demonstration of resource server role in OAuth 2.1
- Detailed logging of token validation process
- Examples of protected resource access patterns
- Security best practices for API endpoints
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import sys
import os

# Add the src directory to the path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from src.shared.logging_utils import OAuthLogger
from src.shared.security import SecurityHeaders
from .routes import router

# Initialize logger
logger = OAuthLogger("RESOURCE-SERVER")

# Initialize FastAPI app with comprehensive metadata
app = FastAPI(
    title="OAuth 2.1 Resource Server",
    description="""
    Educational OAuth 2.1 Resource Server Implementation

    This server demonstrates the resource server role in OAuth 2.1 flows:

    **Key Endpoints:**
    - `/protected` - Protected resource requiring Bearer token
    - `/userinfo` - User information endpoint (OpenID Connect style)
    - `/health` - Health check endpoint
    - `/status` - Detailed status information

    **Security Features:**
    - Bearer token validation in Authorization headers
    - Token format verification and security checks
    - Comprehensive request/response logging
    - Scope-based access control (extensible)
    - Security headers for web protection

    **Token Requirements:**
    All protected endpoints require a valid Bearer token in the Authorization header:
    ```
    Authorization: Bearer <access_token>
    ```

    Tokens are obtained from the authorization server at http://localhost:8081/token
    """,
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    contact={
        "name": "OAuth 2.1 Learning Project",
        "url": "https://github.com/oauth-learning/python-oauth-learning",
    },
    license_info={
        "name": "MIT License",
        "url": "https://opensource.org/licenses/MIT",
    },
)

# Add CORS middleware to allow cross-origin requests from client application
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:8080",  # Client application
        "http://localhost:8081",  # Authorization server
        "http://127.0.0.1:8080",  # Alternative localhost format
        "http://127.0.0.1:8081"   # Alternative localhost format
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-Requested-With"],
)

# Security headers middleware for web protection
@app.middleware("http")
async def add_security_headers(request, call_next):
    """
    Add security headers to all HTTP responses.

    This middleware adds standard security headers to protect against
    common web vulnerabilities and provides additional security for
    API endpoints serving protected resources.
    """
    response = await call_next(request)

    # Get OAuth-specific security headers
    security_headers = SecurityHeaders.get_oauth_security_headers()

    # Apply headers to response
    for header_name, header_value in security_headers.items():
        response.headers[header_name] = header_value

    # Add API-specific headers
    response.headers["X-API-Version"] = "1.0.0"
    response.headers["X-Service-Type"] = "OAuth Resource Server"

    # Log security headers application for educational purposes
    if request.url.path not in ["/health", "/status", "/docs", "/redoc"]:
        logger.log_oauth_message(
            "RESOURCE-SERVER", "RESOURCE-SERVER",
            "Security Headers Applied",
            {
                "path": str(request.url.path),
                "method": request.method,
                "headers_applied": list(security_headers.keys()),
                "client_ip": request.client.host if request.client else "unknown"
            }
        )

    return response

# Include all routes from the routes module
app.include_router(router)


if __name__ == "__main__":
    import uvicorn

    logger.log_oauth_message(
        "SYSTEM", "RESOURCE-SERVER",
        "Server Starting",
        {
            "host": "0.0.0.0",
            "port": 8082,
            "docs_url": "http://localhost:8082/docs"
        }
    )

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8082,
        reload=True,
        log_level="info"
    )