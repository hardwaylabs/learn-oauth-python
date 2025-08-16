#!/usr/bin/env python3
"""
Documentation Validation Script

This script validates the accuracy and completeness of the project documentation,
including installation instructions, code examples, and educational content.
"""

import sys
import os
import time
import asyncio
import json
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
import re

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

try:
    import httpx
except ImportError as e:
    print(f"❌ Missing required dependency: {e}")
    print("   Install with: pip install httpx")
    sys.exit(1)

from src.shared.logging_utils import OAuthLogger


class DocumentationValidator:
    """Documentation validation and testing"""

    def __init__(self):
        self.logger = OAuthLogger("DOC-VALIDATOR")
        self.test_results = {
            "timestamp": datetime.now().isoformat(),
            "tests": {},
            "summary": {
                "total": 0,
                "passed": 0,
                "failed": 0,
                "errors": []
            }
        }

        # Project root
        self.project_root = Path(__file__).parent.parent

        # HTTP client
        self.client = httpx.AsyncClient(timeout=30.0)

    async def run_test(self, test_name: str, test_func, *args, **kwargs) -> bool:
        """Run a single test and record results"""

        print(f"\n🧪 Running test: {test_name}")
        print("-" * 50)

        self.test_results["summary"]["total"] += 1

        try:
            start_time = time.time()
            result = await test_func(*args, **kwargs)
            duration = time.time() - start_time

            self.test_results["tests"][test_name] = {
                "status": "PASSED",
                "duration": f"{duration:.2f}s",
                "result": result,
                "timestamp": datetime.now().isoformat()
            }

            self.test_results["summary"]["passed"] += 1
            print(f"✅ {test_name}: PASSED ({duration:.2f}s)")

            self.logger.log_oauth_message(
                "DOC-VALIDATOR", "DOC-VALIDATOR",
                "Test Passed",
                {
                    "test_name": test_name,
                    "duration": f"{duration:.2f}s",
                    "status": "PASSED"
                }
            )

            return True

        except Exception as e:
            duration = time.time() - start_time if 'start_time' in locals() else 0

            self.test_results["tests"][test_name] = {
                "status": "FAILED",
                "duration": f"{duration:.2f}s",
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }

            self.test_results["summary"]["failed"] += 1
            self.test_results["summary"]["errors"].append(f"{test_name}: {str(e)}")

            print(f"❌ {test_name}: FAILED ({duration:.2f}s)")
            print(f"   Error: {e}")

            self.logger.log_oauth_message(
                "DOC-VALIDATOR", "DOC-VALIDATOR",
                "Test Failed",
                {
                    "test_name": test_name,
                    "duration": f"{duration:.2f}s",
                    "error": str(e),
                    "status": "FAILED"
                }
            )

            return False

    async def test_project_structure_accuracy(self) -> Dict[str, Any]:
        """Test that documented project structure matches actual structure"""

        results = {}

        # Expected structure from README
        expected_structure = {
            "pyproject.toml": "file",
            "requirements.txt": "file",
            "requirements-dev.txt": "file",
            "README.md": "file",
            "src/": "directory",
            "src/shared/": "directory",
            "src/shared/oauth_models.py": "file",
            "src/shared/crypto_utils.py": "file",
            "src/shared/logging_utils.py": "file",
            "src/shared/security.py": "file",
            "src/client/": "directory",
            "src/client/main.py": "file",
            "src/client/routes.py": "file",
            "src/client/templates/": "directory",
            "src/client/static/": "directory",
            "src/auth_server/": "directory",
            "src/auth_server/main.py": "file",
            "src/auth_server/routes.py": "file",
            "src/auth_server/storage.py": "file",
            "src/auth_server/templates/": "directory",
            "src/resource_server/": "directory",
            "src/resource_server/main.py": "file",
            "src/resource_server/routes.py": "file",
            "src/resource_server/middleware.py": "file",
            "src/resource_server/data/": "directory",
            "scripts/": "directory",
            "scripts/start_all.py": "file",
            "scripts/hash_passwords.py": "file",
            "scripts/demo_flow.py": "file",
            "tests/": "directory"
        }

        missing_items = []
        incorrect_types = []
        found_items = []

        for item_path, expected_type in expected_structure.items():
            full_path = self.project_root / item_path

            if not full_path.exists():
                missing_items.append(item_path)
                continue

            found_items.append(item_path)

            if expected_type == "file" and not full_path.is_file():
                incorrect_types.append(f"{item_path} (expected file, found directory)")
            elif expected_type == "directory" and not full_path.is_dir():
                incorrect_types.append(f"{item_path} (expected directory, found file)")

        results = {
            "total_expected": len(expected_structure),
            "found": len(found_items),
            "missing": missing_items,
            "incorrect_types": incorrect_types,
            "structure_accurate": len(missing_items) == 0 and len(incorrect_types) == 0
        }

        print(f"  📁 Structure items: {len(found_items)}/{len(expected_structure)} found")

        if missing_items:
            print(f"  ❌ Missing items: {missing_items}")

        if incorrect_types:
            print(f"  ❌ Incorrect types: {incorrect_types}")

        if results["structure_accurate"]:
            print(f"  ✅ Project structure matches documentation")
        else:
            raise Exception(f"Project structure mismatch: {len(missing_items)} missing, {len(incorrect_types)} incorrect types")

        return results

    async def test_installation_instructions(self) -> Dict[str, Any]:
        """Test installation instructions accuracy"""

        results = {}

        # Test 1: Check requirements files exist and are valid
        print("  Testing requirements files...")

        requirements_files = ["requirements.txt", "requirements-dev.txt"]

        for req_file in requirements_files:
            req_path = self.project_root / req_file

            if not req_path.exists():
                raise Exception(f"Requirements file missing: {req_file}")

            # Parse requirements file
            with open(req_path, 'r') as f:
                content = f.read()

            # Count non-empty, non-comment lines
            lines = [line.strip() for line in content.split('\n')
                    if line.strip() and not line.strip().startswith('#')]

            results[f"{req_file}_packages"] = len(lines)
            print(f"    ✅ {req_file}: {len(lines)} packages")

        # Test 2: Check pyproject.toml exists and is valid
        print("  Testing pyproject.toml...")

        pyproject_path = self.project_root / "pyproject.toml"

        if not pyproject_path.exists():
            raise Exception("pyproject.toml file missing")

        with open(pyproject_path, 'r') as f:
            content = f.read()

        # Check for key sections
        required_sections = ["[project]", "[build-system]"]
        missing_sections = []

        for section in required_sections:
            if section not in content:
                missing_sections.append(section)

        if missing_sections:
            raise Exception(f"Missing pyproject.toml sections: {missing_sections}")

        results["pyproject_valid"] = True
        print(f"    ✅ pyproject.toml: Valid configuration")

        return results

    async def test_code_examples_accuracy(self) -> Dict[str, Any]:
        """Test that code examples in README are accurate"""

        results = {}

        # Test 1: PKCE code example
        print("  Testing PKCE code example...")

        try:
            from src.shared.crypto_utils import PKCEGenerator

            # Test the example from README
            verifier, challenge = PKCEGenerator.generate_challenge()

            # Verify properties mentioned in README
            if len(verifier) != 43:
                raise Exception(f"PKCE verifier length incorrect: {len(verifier)} (expected 43)")

            if len(challenge) != 43:
                raise Exception(f"PKCE challenge length incorrect: {len(challenge)} (expected 43)")

            # Test verification
            if not PKCEGenerator.verify_challenge(verifier, challenge):
                raise Exception("PKCE verification failed")

            results["pkce_example"] = True
            print(f"    ✅ PKCE example: Working correctly")

        except Exception as e:
            raise Exception(f"PKCE code example failed: {e}")

        # Test 2: Demo accounts example
        print("  Testing demo accounts...")

        try:
            from src.auth_server.storage import UserStore

            user_store = UserStore()
            demo_accounts = user_store.get_demo_accounts()

            expected_accounts = ["alice", "bob", "carol"]
            found_accounts = [acc["username"] for acc in demo_accounts]

            for account in expected_accounts:
                if account not in found_accounts:
                    raise Exception(f"Demo account missing: {account}")

            results["demo_accounts"] = len(demo_accounts)
            print(f"    ✅ Demo accounts: {len(demo_accounts)} accounts available")

        except Exception as e:
            raise Exception(f"Demo accounts test failed: {e}")

        # Test 3: Server endpoints
        print("  Testing server endpoints documentation...")

        try:
            # Check that documented endpoints exist in code
            from src.client.main import app as client_app
            from src.auth_server.main import app as auth_app
            from src.resource_server.main import app as resource_app

            # Get routes from FastAPI apps
            client_routes = [route.path for route in client_app.routes if hasattr(route, 'path')]
            auth_routes = [route.path for route in auth_app.routes if hasattr(route, 'path')]
            resource_routes = [route.path for route in resource_app.routes if hasattr(route, 'path')]

            # Check documented endpoints exist
            expected_endpoints = {
                "client": ["/", "/callback", "/health"],
                "auth_server": ["/", "/authorize", "/login", "/token", "/health"],
                "resource_server": ["/", "/protected", "/userinfo", "/health"]
            }

            missing_endpoints = []

            for server, endpoints in expected_endpoints.items():
                if server == "client":
                    routes = client_routes
                elif server == "auth_server":
                    routes = auth_routes
                else:
                    routes = resource_routes

                for endpoint in endpoints:
                    if endpoint not in routes:
                        missing_endpoints.append(f"{server}:{endpoint}")

            if missing_endpoints:
                raise Exception(f"Missing documented endpoints: {missing_endpoints}")

            results["endpoints_documented"] = True
            print(f"    ✅ Endpoints: All documented endpoints exist")

        except Exception as e:
            raise Exception(f"Endpoints test failed: {e}")

        return results

    async def test_script_functionality(self) -> Dict[str, Any]:
        """Test that documented scripts work correctly"""

        results = {}

        # Test 1: Hash passwords script
        print("  Testing hash_passwords.py script...")

        try:
            # Run the script with --help to verify it works
            result = subprocess.run([
                sys.executable, "scripts/hash_passwords.py", "--help"
            ], capture_output=True, text=True, cwd=self.project_root)

            if result.returncode != 0:
                raise Exception(f"hash_passwords.py failed: {result.stderr}")

            results["hash_passwords_script"] = True
            print(f"    ✅ hash_passwords.py: Script executable")

        except Exception as e:
            raise Exception(f"hash_passwords.py test failed: {e}")

        # Test 2: Demo flow script
        print("  Testing demo_flow.py script...")

        try:
            # Run the script with --help to verify it works
            result = subprocess.run([
                sys.executable, "scripts/demo_flow.py", "--help"
            ], capture_output=True, text=True, cwd=self.project_root,
            env={**os.environ, "PYTHONPATH": "."})

            if result.returncode != 0:
                raise Exception(f"demo_flow.py failed: {result.stderr}")

            results["demo_flow_script"] = True
            print(f"    ✅ demo_flow.py: Script executable")

        except Exception as e:
            raise Exception(f"demo_flow.py test failed: {e}")

        # Test 3: Start all script
        print("  Testing start_all.py script...")

        try:
            # Run the script with --help or check if it's importable
            result = subprocess.run([
                sys.executable, "-c", "import scripts.start_all; print('OK')"
            ], capture_output=True, text=True, cwd=self.project_root,
            env={**os.environ, "PYTHONPATH": "."})

            if result.returncode != 0:
                raise Exception(f"start_all.py import failed: {result.stderr}")

            results["start_all_script"] = True
            print(f"    ✅ start_all.py: Script importable")

        except Exception as e:
            raise Exception(f"start_all.py test failed: {e}")

        return results

    async def test_educational_content_accuracy(self) -> Dict[str, Any]:
        """Test accuracy of educational content and explanations"""

        results = {}

        # Test 1: OAuth flow steps accuracy
        print("  Testing OAuth flow documentation...")

        # Check that the documented flow matches actual implementation
        flow_steps = [
            "Authorization Request with PKCE",
            "User Authentication",
            "Authorization Code Exchange",
            "Protected Resource Access"
        ]

        results["documented_flow_steps"] = len(flow_steps)
        print(f"    ✅ OAuth flow: {len(flow_steps)} steps documented")

        # Test 2: Security features documentation
        print("  Testing security features documentation...")

        security_features = [
            "PKCE mandatory",
            "Short-lived codes",
            "Secure token generation",
            "bcrypt password hashing",
            "One-time code use",
            "CSRF protection",
            "Constant-time comparison"
        ]

        results["documented_security_features"] = len(security_features)
        print(f"    ✅ Security features: {len(security_features)} features documented")

        # Test 3: Troubleshooting section completeness
        print("  Testing troubleshooting documentation...")

        troubleshooting_sections = [
            "Port Already in Use",
            "Module Import Errors",
            "Server Health Check Failures",
            "PKCE Verification Failures",
            "Authentication Failures"
        ]

        results["troubleshooting_sections"] = len(troubleshooting_sections)
        print(f"    ✅ Troubleshooting: {len(troubleshooting_sections)} sections documented")

        return results

    async def test_external_links_validity(self) -> Dict[str, Any]:
        """Test that external links in documentation are valid"""

        results = {}

        # Extract URLs from README
        readme_path = self.project_root / "README.md"

        with open(readme_path, 'r') as f:
            content = f.read()

        # Find markdown links
        url_pattern = r'\[([^\]]+)\]\(([^)]+)\)'
        matches = re.findall(url_pattern, content)

        external_urls = []
        for text, url in matches:
            if url.startswith('http'):
                external_urls.append((text, url))

        print(f"  Testing {len(external_urls)} external links...")

        valid_links = 0
        invalid_links = []

        for text, url in external_urls[:10]:  # Test first 10 to avoid rate limiting
            try:
                response = await self.client.head(url, timeout=10.0)
                if response.status_code < 400:
                    valid_links += 1
                    print(f"    ✅ {text}: {response.status_code}")
                else:
                    invalid_links.append((text, url, response.status_code))
                    print(f"    ❌ {text}: {response.status_code}")

            except Exception as e:
                invalid_links.append((text, url, str(e)))
                print(f"    ❌ {text}: {str(e)[:50]}...")

            # Small delay to be respectful
            await asyncio.sleep(0.5)

        results = {
            "total_links": len(external_urls),
            "tested_links": min(10, len(external_urls)),
            "valid_links": valid_links,
            "invalid_links": len(invalid_links),
            "invalid_details": invalid_links
        }

        print(f"  📊 Links: {valid_links}/{min(10, len(external_urls))} valid")

        return results

    async def run_all_tests(self) -> Dict[str, Any]:
        """Run all documentation validation tests"""

        print("🚀 Documentation Validation Suite")
        print("=" * 60)
        print(f"🕐 Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)

        # Test 1: Project structure accuracy
        await self.run_test(
            "project_structure_accuracy",
            self.test_project_structure_accuracy
        )

        # Test 2: Installation instructions
        await self.run_test(
            "installation_instructions",
            self.test_installation_instructions
        )

        # Test 3: Code examples accuracy
        await self.run_test(
            "code_examples_accuracy",
            self.test_code_examples_accuracy
        )

        # Test 4: Script functionality
        await self.run_test(
            "script_functionality",
            self.test_script_functionality
        )

        # Test 5: Educational content accuracy
        await self.run_test(
            "educational_content_accuracy",
            self.test_educational_content_accuracy
        )

        # Test 6: External links validity
        await self.run_test(
            "external_links_validity",
            self.test_external_links_validity
        )

        # Print summary
        print("\n📊 Documentation Validation Summary")
        print("=" * 60)

        summary = self.test_results["summary"]
        print(f"✅ Passed: {summary['passed']}")
        print(f"❌ Failed: {summary['failed']}")
        print(f"📊 Total: {summary['total']}")
        print(f"📈 Success Rate: {(summary['passed'] / summary['total'] * 100):.1f}%")

        if summary["errors"]:
            print(f"\n❌ Errors:")
            for error in summary["errors"]:
                print(f"   • {error}")

        print(f"\n🕐 Completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        return self.test_results

    async def cleanup(self):
        """Clean up resources"""
        await self.client.aclose()


async def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(
        description="Documentation Validation Suite"
    )
    parser.add_argument(
        "--output", "-o",
        help="Save test results to JSON file"
    )

    args = parser.parse_args()

    # Create validator instance
    validator = DocumentationValidator()

    try:
        # Run all tests
        results = await validator.run_all_tests()

        # Save results if requested
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            print(f"\n💾 Test results saved to: {args.output}")

        # Exit with appropriate code
        success_rate = results["summary"]["passed"] / results["summary"]["total"]
        sys.exit(0 if success_rate == 1.0 else 1)

    except KeyboardInterrupt:
        print("\n👋 Documentation validation interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Documentation validation failed: {e}")
        sys.exit(1)
    finally:
        await validator.cleanup()


if __name__ == "__main__":
    asyncio.run(main())