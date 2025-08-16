# OAuth 2.1 Learning Project - Test Suite

This directory contains comprehensive tests for the Python OAuth 2.1 learning implementation. The test suite covers unit tests, integration tests, and security/error handling tests to ensure robust OAuth functionality.

## Test Structure

### Unit Tests

- `test_crypto_utils.py` - Tests for PKCE generation, validation, and cryptographic utilities
- `test_oauth_models.py` - Tests for Pydantic models and data validation
- `test_security.py` - Tests for password hashing, token generation, and input validation
- `test_logging_utils.py` - Tests for colored logging and message formatting

### Integration Tests

- `test_integration_oauth_flow.py` - End-to-end OAuth flow tests across all three applications
- `test_auth_server_endpoints.py` - Authorization server endpoint tests
- `test_resource_server_endpoints.py` - Resource server endpoint tests
- `test_client_application.py` - Client application tests

### Error Handling & Security Tests

- `test_error_handling_edge_cases.py` - Comprehensive error scenarios and security vulnerability tests

### Configuration

- `conftest.py` - Shared fixtures and test configuration
- `pytest.ini` - Pytest configuration and settings

## Running Tests

### Prerequisites

Install test dependencies:

```bash
pip install pytest pytest-asyncio pytest-cov
```

### Basic Test Execution

Run all tests:

```bash
pytest
```

Run with verbose output:

```bash
pytest -v
```

Run specific test file:

```bash
pytest tests/test_crypto_utils.py
```

Run specific test class:

```bash
pytest tests/test_crypto_utils.py::TestPKCEGenerator
```

Run specific test method:

```bash
pytest tests/test_crypto_utils.py::TestPKCEGenerator::test_generate_challenge_returns_valid_pair
```

### Test Categories

Run only unit tests:

```bash
pytest -m unit
```

Run only integration tests:

```bash
pytest -m integration
```

Run only security tests:

```bash
pytest -m security
```

Run tests excluding slow ones:

```bash
pytest -m "not slow"
```

### Coverage Reports

Run tests with coverage:

```bash
pytest --cov=src
```

Generate HTML coverage report:

```bash
pytest --cov=src --cov-report=html
```

View coverage report:

```bash
open htmlcov/index.html
```

### Parallel Execution

Run tests in parallel (requires pytest-xdist):

```bash
pip install pytest-xdist
pytest -n auto
```

## Test Categories and Markers

### Available Markers

- `unit` - Unit tests for individual components
- `integration` - Integration tests across multiple components
- `security` - Security-focused tests for vulnerabilities
- `slow` - Tests that take more than a few seconds
- `pkce` - Tests specifically for PKCE functionality
- `oauth` - Tests for OAuth flow functionality
- `auth` - Tests for authentication functionality
- `token` - Tests for token handling
- `error` - Tests for error handling

### Example Usage

```bash
# Run only PKCE-related tests
pytest -m pkce

# Run OAuth flow tests
pytest -m oauth

# Run security tests excluding slow ones
pytest -m "security and not slow"
```

## Test Coverage Goals

The test suite aims for:

- **Overall Coverage**: 80%+ code coverage
- **Critical Paths**: 95%+ coverage for OAuth flow, PKCE, and security functions
- **Error Handling**: Comprehensive coverage of error scenarios and edge cases

## Key Test Areas

### 1. PKCE Implementation (Requirements 2.1, 2.2)

- Code verifier and challenge generation
- SHA256 hashing with Base64url encoding
- Challenge verification and security validation
- Timing attack resistance

### 2. OAuth Flow Integration (Requirements 1.1, 5.2)

- Complete authorization code flow
- Cross-application communication
- State parameter validation (CSRF protection)
- Error handling and recovery

### 3. Security Measures (Requirements 2.3, 4.4)

- Password hashing with bcrypt
- Token generation and validation
- Input sanitization and validation
- Protection against common vulnerabilities (XSS, SQL injection, etc.)

### 4. Educational Logging (Requirements 7.1, 7.2, 7.4)

- Message formatting and color coding
- Component identification and flow visualization
- Error logging and debugging information

## Continuous Integration

The test suite is designed to run in CI/CD environments:

```yaml
# Example GitHub Actions workflow
- name: Run Tests
  run: |
    pip install -r requirements-dev.txt
    pytest --cov=src --cov-report=xml

- name: Upload Coverage
  uses: codecov/codecov-action@v3
  with:
    file: ./coverage.xml
```

## Troubleshooting

### Common Issues

1. **Import Errors**: Ensure you're running tests from the project root directory
2. **Missing Dependencies**: Install test dependencies with `pip install -r requirements-dev.txt`
3. **Async Test Issues**: Make sure pytest-asyncio is installed for async integration tests
4. **Coverage Issues**: Use `--cov-report=term-missing` to see which lines aren't covered

### Debug Mode

Run tests with debug output:

```bash
pytest -v -s --tb=long
```

Run specific failing test with maximum detail:

```bash
pytest tests/test_file.py::test_method -vvv -s --tb=long
```

## Contributing

When adding new tests:

1. Follow the existing naming conventions
2. Add appropriate markers for test categorization
3. Include docstrings explaining what the test validates
4. Test both success and failure scenarios
5. Add security-focused tests for new functionality
6. Maintain or improve overall test coverage

## Test Data and Fixtures

The test suite uses:

- **Demo Users**: alice/password123, bob/secret456, carol/mypass789
- **Mock Tokens**: Generated using secure random functions
- **Test URLs**: localhost with standard OAuth ports (8080, 8081, 8082)
- **PKCE Pairs**: Generated fresh for each test to ensure isolation

All test data is isolated and doesn't affect the actual application state.