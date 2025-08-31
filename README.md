# Python OAuth 2.1 Learning Implementation

🐍 **A comprehensive Python implementation of OAuth 2.1 for educational purposes**

This project provides a complete, working OAuth 2.1 implementation in Python using FastAPI, designed to help developers
understand OAuth concepts through hands-on exploration. It mirrors the educational approach of the Go OAuth
learning project while leveraging Python's ecosystem and modern web frameworks.

## 🎯 What You'll Learn

- **OAuth 2.1 Authorization Code Flow** with step-by-step visualization
- **PKCE (Proof Key for Code Exchange)** implementation and security benefits
- **Three-component OAuth architecture** (Client, Authorization Server, Resource Server)
- **Python web development** with FastAPI, Pydantic, and modern async patterns
- **Security best practices** including bcrypt password hashing and token validation
- **Real-world OAuth integration patterns** applicable to production systems

## 🏗️ Architecture Overview

The system consists of three independent FastAPI applications that communicate via HTTP:

```
┌─────────────────┐    ┌──────────────────────┐    ┌─────────────────────┐
│   Client App    │    │ Authorization Server │    │  Resource Server    │
│   Port 8080     │◄──►│     Port 8081        │    │     Port 8082       │
│                 │    │                      │    │                     │
│ • OAuth Flow    │    │ • User Authentication│    │ • Protected Resource│
│ • PKCE Gen      │    │ • Authorization Codes│    │ • Token Validation  │
│ • Token Storage │    │ • Access Tokens      │    │ • User Info API     │
└─────────────────┘    └──────────────────────┘    └─────────────────────┘
```

### Component Responsibilities

#### 🖥️ Client Application (Port 8080)

- Initiates OAuth flow with PKCE challenge generation
- Handles authorization callbacks and token exchange
- Accesses protected resources with Bearer tokens
- Provides educational UI showing each OAuth step

#### 🔐 Authorization Server (Port 8081)

- Validates authorization requests and PKCE challenges
- Authenticates users with demo accounts
- Issues authorization codes with 10-minute expiration
- Exchanges codes for access tokens after PKCE verification

#### 🛡️ Resource Server (Port 8082)

- Validates Bearer tokens from Authorization headers
- Serves protected resources and user information
- Demonstrates proper token-based access control
- Provides detailed logging of resource access attempts

## 🚀 Quick Start

### Prerequisites

- **Python 3.8+** (Check with `python --version`)
- **uv** package manager (recommended) or pip

### Installation

#### Option 1: Using uv (Recommended)

```bash
# Install uv if not already installed
curl -LsSf https://astral.sh/uv/install.sh | sh

# Clone and setup project
git clone <repository-url>
cd python-oauth-learning

# Install dependencies
uv sync

# Activate virtual environment
source .venv/bin/activate  # On macOS/Linux
# or
.venv\Scripts\activate     # On Windows
```

#### Option 2: Using pip

```bash
# Clone project
git clone <repository-url>
cd python-oauth-learning

# Create virtual environment
python -m venv venv
source venv/bin/activate   # On macOS/Linux
# or
venv\Scripts\activate      # On Windows

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

### Running the System

#### Start All Servers (Recommended)

```bash
# Start all three servers with health checks and monitoring
python scripts/start_all.py
```

This script will:

- ✅ Check that all ports are available
- 🚀 Start servers in the correct order with health checks
- 📊 Display real-time status and connection information
- 🔄 Monitor processes and restart if needed
- 🛑 Handle graceful shutdown with Ctrl+C

#### Manual Server Startup

If you prefer to start servers individually:

```bash
# Terminal 1: Authorization Server
uvicorn src.auth_server.main:app --host 0.0.0.0 --port 8081 --reload

# Terminal 2: Resource Server
uvicorn src.resource_server.main:app --host 0.0.0.0 --port 8082 --reload

# Terminal 3: Client Application
uvicorn src.client.main:app --host 0.0.0.0 --port 8080 --reload
```

### Access the Demo

Once all servers are running:

1. **🌐 Open your browser** to <http://localhost:8080>
1. **🔑 Click "Start OAuth Flow"** to begin the authorization process
1. **👤 Login with demo account:**
   - Username: `alice`, Password: `password123`
   - Username: `bob`, Password: `secret456`
   - Username: `carol`, Password: `mypass789`
1. **📋 Follow the step-by-step flow** and observe the detailed console logging
1. **🔒 Access protected resources** to complete the demonstration

## 📚 Step-by-Step OAuth Flow Walkthrough

### Step 1: Authorization Request with PKCE

The client generates a PKCE challenge and redirects to the authorization server:

```python
# Generate PKCE challenge pair
verifier, challenge = PKCEGenerator.generate_challenge()

# Build authorization URL
auth_params = {
    'client_id': 'demo-client',
    'redirect_uri': 'http://localhost:8080/callback',
    'scope': 'read',
    'state': 'demo-state-123',
    'code_challenge': challenge,
    'code_challenge_method': 'S256',
    'response_type': 'code'
}
```

**🔍 What happens:**

- Client generates cryptographically secure PKCE verifier (43 characters)
- SHA256 hash of verifier becomes the challenge
- User is redirected to authorization server with challenge
- State parameter prevents CSRF attacks

### Step 2: User Authentication

The authorization server presents a login form:

```python
# Demo accounts with bcrypt-hashed passwords
demo_accounts = {
    'alice': '$2b$12$...',  # password123
    'bob': '$2b$12$...',    # secret456
    'carol': '$2b$12$...'   # mypass789
}

# Verify credentials
if verify_password(password, user['password_hash']):
    # Generate authorization code
    auth_code = generate_secure_token()
```

**🔍 What happens:**

- User enters credentials on authorization server
- Server validates against bcrypt-hashed passwords
- Authorization code generated with 10-minute expiration
- Code tied to client_id, user, and PKCE challenge

### Step 3: Authorization Code Exchange

The client exchanges the code + PKCE verifier for an access token:

```python
# Token request with PKCE verification
token_request = {
    'grant_type': 'authorization_code',
    'code': authorization_code,
    'redirect_uri': 'http://localhost:8080/callback',
    'client_id': 'demo-client',
    'code_verifier': pkce_verifier
}

# Server verifies PKCE
if PKCEGenerator.verify_challenge(verifier, stored_challenge):
    access_token = generate_secure_token()
```

**🔍 What happens:**

- Client sends authorization code + PKCE verifier
- Server verifies PKCE challenge matches verifier
- Access token issued only if PKCE verification succeeds
- Authorization code marked as used (one-time only)

### Step 4: Protected Resource Access

The client uses the Bearer token to access protected resources:

```python
# Access protected resource
headers = {'Authorization': f'Bearer {access_token}'}
response = httpx.get('http://localhost:8082/protected', headers=headers)

# Resource server validates token
def validate_bearer_token(authorization: str = Header(None)):
    if not authorization or not authorization.startswith('Bearer '):
        raise HTTPException(401, "Invalid Authorization header")
    return authorization[7:]  # Extract token
```

**🔍 What happens:**

- Client includes Bearer token in Authorization header
- Resource server validates token format and presence
- Protected content served if token is valid
- All requests logged with security details

## 🔧 Demo Automation

### Automated Flow Testing

Run the complete OAuth flow programmatically:

```bash
# Test single account
python scripts/demo_flow.py --username alice

# Test all demo accounts
python scripts/demo_flow.py --test-all

# Save results to file
python scripts/demo_flow.py --test-all --output results.json

# Custom server URLs
python scripts/demo_flow.py --auth-url http://localhost:9081
```

### Password Hash Generation

Generate bcrypt hashes for new demo accounts:

```bash
# Generate hashes for all demo accounts
python scripts/hash_passwords.py

# Generate hash for specific password
python scripts/hash_passwords.py --password "newpassword123"
```

## 🛠️ Development and Customization

### Project Structure

```
python-oauth-learning/
├── 📄 pyproject.toml              # uv project configuration
├── 📄 requirements.txt            # Production dependencies
├── 📄 requirements-dev.txt        # Development dependencies
├── 📁 src/
│   ├── 📁 shared/                 # Common utilities and models
│   │   ├── 🐍 oauth_models.py     # Pydantic models for validation
│   │   ├── 🔐 crypto_utils.py     # PKCE and token generation
│   │   ├── 📊 logging_utils.py    # Colored console logging
│   │   └── 🛡️ security.py         # Password hashing utilities
│   ├── 📁 client/                 # Client application (Port 8080)
│   │   ├── 🐍 main.py             # FastAPI app and configuration
│   │   ├── 🛣️ routes.py           # OAuth flow endpoints
│   │   ├── 📁 templates/          # Jinja2 HTML templates
│   │   └── 📁 static/             # CSS and JavaScript files
│   ├── 📁 auth_server/           # Authorization server (Port 8081)
│   │   ├── 🐍 main.py             # FastAPI app and configuration
│   │   ├── 🛣️ routes.py           # OAuth authorization endpoints
│   │   ├── 💾 storage.py          # In-memory user and code storage
│   │   └── 📁 templates/          # Login form templates
│   └── 📁 resource_server/       # Resource server (Port 8082)
│       ├── 🐍 main.py             # FastAPI app and configuration
│       ├── 🛣️ routes.py           # Protected resource endpoints
│       ├── 🛡️ middleware.py       # Token validation middleware
│       └── 📁 data/               # Protected resource files
├── 📁 scripts/                   # Utility and automation scripts
│   ├── 🚀 start_all.py           # Multi-server startup with monitoring
│   ├── 🔐 hash_passwords.py      # Password hash generation
│   └── 🤖 demo_flow.py           # Automated OAuth flow testing
└── 📁 tests/                     # Test suite
    ├── 🧪 test_crypto_utils.py   # PKCE and crypto function tests
    └── 🧪 test_oauth_flow.py     # Integration tests
```

### Key Python Libraries Used

- **[FastAPI](https://fastapi.tiangolo.com/)** - Modern async web framework with automatic API docs
- **[Pydantic](https://pydantic-docs.helpmanual.io/)** - Data validation using Python type hints
- **[uvicorn](https://www.uvicorn.org/)** - ASGI server for running FastAPI applications
- **[Jinja2](https://jinja.palletsprojects.com/)** - Template engine for HTML rendering
- **[passlib](https://passlib.readthedocs.io/)** - Password hashing library with bcrypt support
- **[httpx](https://www.python-httpx.org/)** - Async HTTP client for server-to-server communication
- **[colorama](https://pypi.org/project/colorama/)** - Cross-platform colored terminal output

### Adding New Demo Accounts

1. **Generate password hash:**
   ```bash
   python scripts/hash_passwords.py --password "newpassword"
   ```

1. **Add to user store** in `src/auth_server/storage.py`:
   ```python
   self._users = {
       'alice': {'password_hash': '$2b$12$...', 'email': 'alice@example.com'},
       'newuser': {'password_hash': '$2b$12$...', 'email': 'newuser@example.com'},
   }
   ```

1. **Update demo account list** in templates and documentation

### Extending OAuth Scopes

1. **Define new scopes** in `src/shared/oauth_models.py`:
   ```python
   class OAuthScope(str, Enum):
       READ = "read"
       WRITE = "write"
       ADMIN = "admin"
   ```

2. **Add scope validation** in authorization server
3. **Implement scope-based access control** in resource server

### Custom Resource Endpoints

Add new protected endpoints in `src/resource_server/routes.py`:

```python
@app.get("/api/profile")
async def get_user_profile(token: str = Depends(validate_bearer_token)):
    """Get user profile information"""
    # Implement profile logic
    return {"profile": "user_data"}
```

## 🔍 Educational Features

### Detailed Console Logging

The system provides comprehensive, color-coded logging of all OAuth messages:

```text
[2024-01-15 10:30:15] CLIENT → AUTH-SERVER
Authorization Request:
  client_id: demo-client
  redirect_uri: http://localhost:8080/callback
  scope: read
  state: demo-state-123
  code_challenge: dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
  code_challenge_method: S256
  response_type: code
--------------------------------------------------
```

### PKCE Implementation Details

The PKCE implementation demonstrates RFC 7636 compliance:

```python
# Code verifier: 43-character base64url string
verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')

# Code challenge: SHA256 hash of verifier
challenge = base64.urlsafe_b64encode(
    hashlib.sha256(verifier.encode('utf-8')).digest()
).decode('utf-8').rstrip('=')

# Verification: constant-time comparison
def verify_challenge(verifier: str, challenge: str) -> bool:
    expected = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode('utf-8')).digest()
    ).decode('utf-8').rstrip('=')
    return secrets.compare_digest(expected, challenge)
```

### Security Best Practices Demonstrated

- **🔐 PKCE mandatory** - All authorization flows require PKCE
- **⏰ Short-lived codes** - Authorization codes expire in 10 minutes
- **🔒 Secure token generation** - Cryptographically secure random tokens
- **🛡️ bcrypt password hashing** - Industry-standard password protection
- **🚫 One-time code use** - Authorization codes invalidated after use
- **🎲 CSRF protection** - State parameter validation
- **⚡ Constant-time comparison** - Prevents timing attacks

## 🧪 Testing

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src

# Run specific test file
pytest tests/test_crypto_utils.py

# Run with verbose output
pytest -v
```

### Test Categories

**Unit Tests** - Test individual components:

- PKCE generation and verification
- Password hashing and validation
- OAuth model validation
- Token generation utilities

**Integration Tests** - Test complete flows:

- End-to-end OAuth authorization
- Multi-server communication
- Error handling scenarios
- Security validation

### Manual Testing Scenarios

1. **Happy Path Flow**
   - Complete OAuth flow with valid credentials
   - Verify all steps complete successfully
   - Check token-based resource access

1. **Error Scenarios**
   - Invalid PKCE verifier
   - Expired authorization code
   - Missing or malformed tokens
   - Invalid user credentials

1. **Security Tests**
   - CSRF attack prevention (state parameter)
   - Authorization code interception (PKCE protection)
   - Token replay attacks
   - Scope validation

## 🚨 Troubleshooting

### Common Issues

#### ❌ Port Already in Use

```bash
# Check what's using the port
lsof -i :8080
# Kill the process
kill -9 <PID>
```

#### ❌ Module Import Errors

```bash
# Ensure you're in the project root and virtual environment is activated
pwd  # Should show python-oauth-learning directory
which python  # Should show virtual environment path

# Reinstall dependencies
pip install -r requirements.txt
```

#### ❌ Server Health Check Failures

```bash
# Check server logs for startup errors
python scripts/start_all.py

# Test individual server health
curl http://localhost:8081/health
curl http://localhost:8082/health
curl http://localhost:8080/health
```

#### ❌ PKCE Verification Failures

- Ensure code verifier is stored correctly in session
- Check that challenge generation uses SHA256
- Verify base64url encoding (no padding)

#### ❌ Authentication Failures

- Verify demo account passwords match hashed values
- Check bcrypt hash generation
- Ensure password verification uses correct hash

### Debug Mode

Enable detailed debugging:

```bash
# Set debug environment variables
export OAUTH_DEBUG=true
export LOG_LEVEL=DEBUG

# Run with debug logging
python scripts/start_all.py
```

### Performance Issues

**Slow Startup:**

- Check available system resources
- Ensure no port conflicts
- Verify network connectivity between servers

**High Memory Usage:**

- Monitor process memory with `top` or `htop`
- Check for memory leaks in long-running processes
- Consider restarting servers periodically

## 🤝 Contributing

### Development Setup

1. **Fork and clone** the repository
1. **Install development dependencies:**

   ```bash
   uv sync --dev
   # or
   pip install -r requirements-dev.txt
   ```

1. **Install pre-commit hooks:**

   ```bash
   pre-commit install
   ```

1. **Run tests** to ensure everything works:

   ```bash
   pytest
   ```

### Code Style

The project uses:

- **Black** for code formatting
- **Ruff** for linting
- **Type hints** throughout the codebase
- **Docstrings** for all public functions and classes

```bash
# Format code
black src/ tests/ scripts/

# Lint code
ruff check src/ tests/ scripts/

# Type checking
mypy src/
```

### Adding Features

1. **Create feature branch:** `git checkout -b feature/new-feature`
1. **Write tests first** (TDD approach)
1. **Implement feature** with proper documentation
1. **Update README** if needed
1. **Submit pull request** with clear description

## 📖 Additional Resources

### OAuth 2.1 Specification

- [RFC 6749 - OAuth 2.0 Authorization Framework](https://tools.ietf.org/html/rfc6749)
- [RFC 7636 - PKCE](https://tools.ietf.org/html/rfc7636)
- [OAuth 2.1 Draft](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1)

### Python Web Development

- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [Pydantic Documentation](https://pydantic-docs.helpmanual.io/)
- [Python Async/Await Tutorial](https://realpython.com/async-io-python/)

### Security Best Practices

- [OWASP OAuth Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html)
- [OAuth 2.0 Security Best Current Practice](https://tools.ietf.org/html/draft-ietf-oauth-security-topics)

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Inspired by the Go OAuth learning implementation
- Built with modern Python web development best practices
- Designed for educational use and real-world understanding

---

**🎓 Happy Learning!** This implementation provides a solid foundation for understanding OAuth 2.1 concepts and building secure,
modern web applications with Python.