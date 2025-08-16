# OAuth 2.1 Learning System - Utility Scripts

This directory contains utility scripts for managing and testing the OAuth 2.1 learning system.

## Scripts Overview

### 🚀 `start_all.py` - Multi-Server Startup Script

Launches all three OAuth servers with proper process management and health checks.

**Features:**
- Staggered startup with health checks
- Graceful shutdown handling (Ctrl+C)
- Process monitoring and automatic restart
- Clear status messages and instructions
- Port availability checking

**Usage:**

```bash
# Start all servers
python scripts/start_all.py

# Or make it executable and run directly
./scripts/start_all.py
```

**What it does:**
1. Starts Authorization Server on port 8081
2. Starts Resource Server on port 8082
3. Starts Client Application on port 8080
4. Monitors all processes and restarts if needed
5. Provides clear instructions for using the system

### 🔐 `hash_passwords.py` - Password Hashing Utility

Generates bcrypt password hashes for demo accounts and provides testing utilities.

**Features:**
- Generate hashes for all demo accounts
- Verify hash correctness
- Output in multiple formats (Python code, JSON)
- Interactive mode for custom passwords
- Password strength validation

**Usage:**

```bash
# Generate demo account hashes
python scripts/hash_passwords.py

# Interactive mode for custom passwords
python scripts/hash_passwords.py --interactive

# Just verify existing hashes
python scripts/hash_passwords.py --verify-only

# Don't save output files
python scripts/hash_passwords.py --no-save
```

**Demo Accounts:**
- `alice` / `password123`
- `bob` / `secret456`
- `carol` / `mypass789`

### 🧪 `demo_flow.py` - OAuth Flow Automation

Automates the complete OAuth 2.1 flow for testing and demonstration.

**Features:**
- Complete OAuth 2.1 flow automation with PKCE
- Tests all demo accounts
- Step-by-step flow verification
- Detailed logging and error reporting
- Health checks for all servers
- JSON output for results

**Usage:**

```bash
# Test with alice account
python scripts/demo_flow.py

# Test with specific account
python scripts/demo_flow.py --username bob

# Test all demo accounts
python scripts/demo_flow.py --test-all

# Save results to file
python scripts/demo_flow.py --test-all --output results.json

# Custom server URLs
python scripts/demo_flow.py --auth-url http://localhost:9001 --resource-url http://localhost:9002
```

**Flow Steps:**
1. Generate PKCE challenge and authorization URL
2. Request authorization page from auth server
3. Authenticate user with demo credentials
4. Exchange authorization code + PKCE verifier for access token
5. Access protected resource with Bearer token
6. Access user info endpoint

## Dependencies

Make sure you have the required dependencies installed:

```bash
# Core dependencies (should already be installed)
pip install fastapi uvicorn httpx passlib[bcrypt] colorama

# Additional dependencies for demo automation
pip install beautifulsoup4
```

## Quick Start

1. **Start all servers:**

   ```bash
   python scripts/start_all.py
   ```

2. **In another terminal, test the flow:**

   ```bash
   python scripts/demo_flow.py --test-all
   ```

3. **Generate fresh password hashes (if needed):**

   ```bash
   python scripts/hash_passwords.py
   ```

## Troubleshooting

### Port Already in Use
If you get "port already in use" errors:

```bash
# Check what's using the ports
lsof -i :8080 -i :8081 -i :8082

# Kill processes if needed
pkill -f uvicorn
```

### Missing Dependencies

```bash
# Install missing packages
pip install httpx beautifulsoup4 'passlib[bcrypt]'
```

### Server Health Check Failures

```bash
# Check if servers are responding
curl http://localhost:8080/health
curl http://localhost:8081/health
curl http://localhost:8082/health
```

### Demo Flow Failures
1. Make sure all servers are running and healthy
2. Check that demo accounts are properly configured
3. Verify network connectivity between components
4. Check server logs for detailed error information

## Output Files

Scripts may create output files in `scripts/output/`:
- `demo_users.py` - Python code for user storage
- `demo_users.json` - JSON format user data
- `user_storage_template.py` - Complete UserStore template
- `hash_*.py` - Individual password hashes
- `results.json` - Demo flow test results

## Educational Value

These scripts demonstrate:
- **OAuth 2.1 Security**: PKCE implementation, state parameters, secure token handling
- **Process Management**: Multi-server coordination, health monitoring, graceful shutdown
- **Password Security**: bcrypt hashing, verification, strength validation
- **HTTP Client Patterns**: Session management, error handling, redirect following
- **Testing Automation**: End-to-end flow testing, multiple account validation
- **Logging and Monitoring**: Structured logging, flow tracing, error reporting

## Integration with Main System

These scripts are designed to work with the main OAuth learning system:
- Use the same shared utilities (`src/shared/`)
- Follow the same logging patterns
- Support the same demo accounts
- Work with the existing server configurations

For more information about the OAuth 2.1 learning system, see the main README.md file.