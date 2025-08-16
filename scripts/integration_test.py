#!/usr/bin/env python3
"""
OAuth 2.1 System Integration Test Suite

This script performs comprehensive integration testing of the complete OAuth 2.1
learning system, including all three servers, demo accounts, error scenarios,
and security features validation.
"""

import sys
import os
import time
import asyncio
import json
import subprocess
import signal
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
import tempfile

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

try:
    import httpx
    import pytest
except ImportError as e:
    print(f"❌ Missing required dependency: {e}")
    print("   Install with: pip install httpx pytest")
    sys.exit(1)

from src.shared.crypto_utils import PKCEGenerator
from src.shared.logging_utils import OAuthLogger
from scripts.demo_flow import OAuthFlowAutomation


class SystemIntegrationTester:
    """Comprehensive system integration testing"""

    def __init__(self):
        self.logger = OAuthLogger("INTEGRATION-TEST")
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

        # Server URLs
        self.urls = {
            "client": "http://localhost:8080",
            "auth_server": "http://localhost:8081",
            "resource_server": "http://localhost:8082"
        }

        # Demo accounts for testing
        self.demo_accounts = {
            "alice": "password123",
            "bob": "secret456",
            "carol": "mypass789"
        }

        # HTTP client
        self.client = httpx.AsyncClient(timeout=30.0, follow_redirects=False)

        # Server processes (if we start them)
        self.server_processes = []

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
                "INTEGRATION-TEST", "INTEGRATION-TEST",
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
                "INTEGRATION-TEST", "INTEGRATION-TEST",
                "Test Failed",
                {
                    "test_name": test_name,
                    "duration": f"{duration:.2f}s",
                    "error": str(e),
                    "status": "FAILED"
                }
            )

            return False

    async def test_server_health_checks(self) -> Dict[str, Any]:
        """Test that all servers are running and healthy"""

        health_results = {}

        for server_name, url in self.urls.items():
            try:
                response = await self.client.get(f"{url}/health", timeout=5.0)

                health_results[server_name] = {
                    "status_code": response.status_code,
                    "healthy": response.status_code == 200,
                    "response_time": response.elapsed.total_seconds()
                }

                print(f"  {server_name}: {'✅' if response.status_code == 200 else '❌'} HTTP {response.status_code}")

            except Exception as e:
                health_results[server_name] = {
                    "healthy": False,
                    "error": str(e)
                }
                print(f"  {server_name}: ❌ Connection failed - {e}")

        all_healthy = all(result.get("healthy", False) for result in health_results.values())

        if not all_healthy:
            raise Exception("Not all servers are healthy")

        return health_results

    async def test_complete_oauth_flow_all_accounts(self) -> Dict[str, Any]:
        """Test complete OAuth flow with all demo accounts"""

        automation = OAuthFlowAutomation(self.urls)
        results = {}

        try:
            for username, password in self.demo_accounts.items():
                print(f"  Testing account: {username}")

                # Reset automation state
                automation.flow_state = {}

                flow_result = await automation.run_complete_flow(username, password)
                results[username] = flow_result

                if not flow_result["success"]:
                    raise Exception(f"OAuth flow failed for {username}: {flow_result['errors']}")

                print(f"    ✅ {username}: {len(flow_result['steps_completed'])}/6 steps completed")

                # Small delay between accounts
                await asyncio.sleep(1)

        finally:
            await automation.cleanup()

        return results

    async def test_pkce_security_validation(self) -> Dict[str, Any]:
        """Test PKCE implementation security features"""

        results = {}

        # Test 1: Valid PKCE flow
        verifier, challenge = PKCEGenerator.generate_challenge()
        valid_verification = PKCEGenerator.verify_challenge(verifier, challenge)
        results["valid_pkce"] = valid_verification

        if not valid_verification:
            raise Exception("Valid PKCE verification failed")

        # Test 2: Invalid verifier should fail
        invalid_verification = PKCEGenerator.verify_challenge("invalid_verifier", challenge)
        results["invalid_verifier_rejected"] = not invalid_verification

        if invalid_verification:
            raise Exception("Invalid PKCE verifier was accepted")

        # Test 3: Challenge format validation
        results["challenge_length"] = len(challenge)
        results["verifier_length"] = len(verifier)

        if len(challenge) < 43 or len(verifier) < 43:
            raise Exception("PKCE challenge/verifier too short")

        # Test 4: Multiple challenges are unique
        verifier2, challenge2 = PKCEGenerator.generate_challenge()
        results["challenges_unique"] = challenge != challenge2

        if challenge == challenge2:
            raise Exception("PKCE challenges are not unique")

        print(f"  ✅ Valid PKCE verification: {valid_verification}")
        print(f"  ✅ Invalid verifier rejected: {not invalid_verification}")
        print(f"  ✅ Challenge length: {len(challenge)} chars")
        print(f"  ✅ Challenges are unique: {challenge != challenge2}")

        return results

    async def test_error_scenarios(self) -> Dict[str, Any]:
        """Test various error scenarios and proper error handling"""

        results = {}

        # Test 1: Invalid client_id
        try:
            response = await self.client.get(
                f"{self.urls['auth_server']}/authorize",
                params={
                    "client_id": "invalid-client",
                    "redirect_uri": "http://localhost:8080/callback",
                    "scope": "read",
                    "state": "test-state",
                    "code_challenge": "test-challenge",
                    "code_challenge_method": "S256",
                    "response_type": "code"
                }
            )
            results["invalid_client_id"] = {
                "status_code": response.status_code,
                "handled_properly": response.status_code in [400, 401]
            }
            print(f"  Invalid client_id: HTTP {response.status_code}")

        except Exception as e:
            results["invalid_client_id"] = {"error": str(e)}

        # Test 2: Missing PKCE challenge
        try:
            response = await self.client.get(
                f"{self.urls['auth_server']}/authorize",
                params={
                    "client_id": "demo-client",
                    "redirect_uri": "http://localhost:8080/callback",
                    "scope": "read",
                    "state": "test-state",
                    "response_type": "code"
                    # Missing code_challenge
                }
            )
            results["missing_pkce"] = {
                "status_code": response.status_code,
                "handled_properly": response.status_code == 400
            }
            print(f"  Missing PKCE: HTTP {response.status_code}")

        except Exception as e:
            results["missing_pkce"] = {"error": str(e)}

        # Test 3: Invalid token request
        try:
            response = await self.client.post(
                f"{self.urls['auth_server']}/token",
                json={
                    "grant_type": "authorization_code",
                    "code": "invalid-code",
                    "redirect_uri": "http://localhost:8080/callback",
                    "client_id": "demo-client",
                    "code_verifier": "invalid-verifier"
                }
            )
            results["invalid_token_request"] = {
                "status_code": response.status_code,
                "handled_properly": response.status_code == 400
            }
            print(f"  Invalid token request: HTTP {response.status_code}")

        except Exception as e:
            results["invalid_token_request"] = {"error": str(e)}

        # Test 4: Unauthorized resource access
        try:
            response = await self.client.get(
                f"{self.urls['resource_server']}/protected"
                # Missing Authorization header
            )
            results["unauthorized_resource"] = {
                "status_code": response.status_code,
                "handled_properly": response.status_code == 401
            }
            print(f"  Unauthorized resource access: HTTP {response.status_code}")

        except Exception as e:
            results["unauthorized_resource"] = {"error": str(e)}

        # Test 5: Invalid bearer token
        try:
            response = await self.client.get(
                f"{self.urls['resource_server']}/protected",
                headers={"Authorization": "Bearer invalid-token"}
            )
            results["invalid_bearer_token"] = {
                "status_code": response.status_code,
                "handled_properly": response.status_code == 401
            }
            print(f"  Invalid bearer token: HTTP {response.status_code}")

        except Exception as e:
            results["invalid_bearer_token"] = {"error": str(e)}

        return results

    async def test_logging_output_validation(self) -> Dict[str, Any]:
        """Test that logging output matches educational requirements"""

        results = {}

        # Capture log output during a simple OAuth flow
        automation = OAuthFlowAutomation(self.urls)

        try:
            # Run a single OAuth flow and capture the logging
            flow_result = await automation.run_complete_flow("alice")

            results["flow_completed"] = flow_result["success"]
            results["steps_logged"] = len(flow_result["steps_completed"])

            # Verify that key OAuth messages were logged
            # (This is a simplified check - in a real implementation,
            # we might capture actual log output)
            expected_steps = [
                "health_check",
                "initiate_flow",
                "get_auth_page",
                "authenticate_user",
                "exchange_token",
                "access_protected_resource",
                "access_user_info"
            ]

            completed_steps = flow_result["steps_completed"]
            results["all_steps_completed"] = all(step in completed_steps for step in expected_steps[1:])  # Skip health_check

            if not results["all_steps_completed"]:
                missing_steps = [step for step in expected_steps[1:] if step not in completed_steps]
                raise Exception(f"Missing steps in logging: {missing_steps}")

            print(f"  ✅ Flow completed: {flow_result['success']}")
            print(f"  ✅ Steps logged: {len(flow_result['steps_completed'])}")
            print(f"  ✅ All expected steps completed: {results['all_steps_completed']}")

        finally:
            await automation.cleanup()

        return results

    async def test_concurrent_oauth_flows(self) -> Dict[str, Any]:
        """Test concurrent OAuth flows to validate system stability"""

        results = {}

        # Create multiple automation instances for concurrent testing
        automations = [OAuthFlowAutomation(self.urls) for _ in range(3)]
        accounts = ["alice", "bob", "carol"]

        try:
            print(f"  Running {len(automations)} concurrent OAuth flows...")

            # Run concurrent flows
            tasks = []
            for i, (automation, account) in enumerate(zip(automations, accounts)):
                task = asyncio.create_task(
                    automation.run_complete_flow(account),
                    name=f"flow_{account}"
                )
                tasks.append(task)

            # Wait for all flows to complete
            flow_results = await asyncio.gather(*tasks, return_exceptions=True)

            # Analyze results
            successful_flows = 0
            failed_flows = 0

            for i, result in enumerate(flow_results):
                account = accounts[i]

                if isinstance(result, Exception):
                    print(f"    ❌ {account}: Exception - {result}")
                    failed_flows += 1
                    results[f"flow_{account}"] = {"success": False, "error": str(result)}
                elif result.get("success"):
                    print(f"    ✅ {account}: Success")
                    successful_flows += 1
                    results[f"flow_{account}"] = {"success": True, "steps": len(result["steps_completed"])}
                else:
                    print(f"    ❌ {account}: Failed - {result.get('errors', [])}")
                    failed_flows += 1
                    results[f"flow_{account}"] = {"success": False, "errors": result.get("errors", [])}

            results["summary"] = {
                "total_flows": len(automations),
                "successful": successful_flows,
                "failed": failed_flows,
                "success_rate": successful_flows / len(automations)
            }

            print(f"  📊 Concurrent flow results: {successful_flows}/{len(automations)} successful")

            if successful_flows < len(automations):
                raise Exception(f"Only {successful_flows}/{len(automations)} concurrent flows succeeded")

        finally:
            # Cleanup all automation instances
            for automation in automations:
                await automation.cleanup()

        return results

    async def test_security_headers_and_cors(self) -> Dict[str, Any]:
        """Test security headers and CORS configuration"""

        results = {}

        # Test each server's security headers
        for server_name, url in self.urls.items():
            try:
                response = await self.client.get(f"{url}/health")
                headers = dict(response.headers)

                server_results = {
                    "status_code": response.status_code,
                    "headers": headers,
                    "security_headers": {}
                }

                # Check for common security headers
                security_headers = [
                    "x-content-type-options",
                    "x-frame-options",
                    "x-xss-protection",
                    "strict-transport-security"
                ]

                for header in security_headers:
                    server_results["security_headers"][header] = header in headers

                results[server_name] = server_results

                print(f"  {server_name}: HTTP {response.status_code}")
                for header in security_headers:
                    status = "✅" if header in headers else "⚠️"
                    print(f"    {status} {header}: {headers.get(header, 'Not set')}")

            except Exception as e:
                results[server_name] = {"error": str(e)}
                print(f"  {server_name}: ❌ Error - {e}")

        return results

    async def run_all_tests(self) -> Dict[str, Any]:
        """Run all integration tests"""

        print("🚀 OAuth 2.1 System Integration Test Suite")
        print("=" * 60)
        print(f"🕐 Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)

        # Test 1: Server health checks
        await self.run_test(
            "server_health_checks",
            self.test_server_health_checks
        )

        # Test 2: Complete OAuth flow with all accounts
        await self.run_test(
            "complete_oauth_flow_all_accounts",
            self.test_complete_oauth_flow_all_accounts
        )

        # Test 3: PKCE security validation
        await self.run_test(
            "pkce_security_validation",
            self.test_pkce_security_validation
        )

        # Test 4: Error scenarios
        await self.run_test(
            "error_scenarios",
            self.test_error_scenarios
        )

        # Test 5: Logging output validation
        await self.run_test(
            "logging_output_validation",
            self.test_logging_output_validation
        )

        # Test 6: Concurrent OAuth flows
        await self.run_test(
            "concurrent_oauth_flows",
            self.test_concurrent_oauth_flows
        )

        # Test 7: Security headers and CORS
        await self.run_test(
            "security_headers_and_cors",
            self.test_security_headers_and_cors
        )

        # Print summary
        print("\n📊 Integration Test Summary")
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
        description="OAuth 2.1 System Integration Test Suite"
    )
    parser.add_argument(
        "--output", "-o",
        help="Save test results to JSON file"
    )
    parser.add_argument(
        "--client-url",
        default="http://localhost:8080",
        help="Client application URL"
    )
    parser.add_argument(
        "--auth-url",
        default="http://localhost:8081",
        help="Authorization server URL"
    )
    parser.add_argument(
        "--resource-url",
        default="http://localhost:8082",
        help="Resource server URL"
    )

    args = parser.parse_args()

    # Create tester instance
    tester = SystemIntegrationTester()

    # Override URLs if provided
    if args.client_url != "http://localhost:8080":
        tester.urls["client"] = args.client_url
    if args.auth_url != "http://localhost:8081":
        tester.urls["auth_server"] = args.auth_url
    if args.resource_url != "http://localhost:8082":
        tester.urls["resource_server"] = args.resource_url

    try:
        # Run all tests
        results = await tester.run_all_tests()

        # Save results if requested
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            print(f"\n💾 Test results saved to: {args.output}")

        # Exit with appropriate code
        success_rate = results["summary"]["passed"] / results["summary"]["total"]
        sys.exit(0 if success_rate == 1.0 else 1)

    except KeyboardInterrupt:
        print("\n👋 Integration tests interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Integration tests failed: {e}")
        sys.exit(1)
    finally:
        await tester.cleanup()


if __name__ == "__main__":
    asyncio.run(main())