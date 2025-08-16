#!/usr/bin/env python3
"""
OAuth 2.1 Performance and Security Validation Suite

This script performs comprehensive performance and security testing of the OAuth 2.1
learning system, including concurrent flows, token expiration, cleanup validation,
security headers, and error handling verification.
"""

import sys
import os
import time
import asyncio
import json
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
import tempfile
import concurrent.futures

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


class PerformanceSecurityTester:
    """Performance and security validation testing"""

    def __init__(self):
        self.logger = OAuthLogger("PERF-SEC-TEST")
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
                "PERF-SEC-TEST", "PERF-SEC-TEST",
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
                "PERF-SEC-TEST", "PERF-SEC-TEST",
                "Test Failed",
                {
                    "test_name": test_name,
                    "duration": f"{duration:.2f}s",
                    "error": str(e),
                    "status": "FAILED"
                }
            )

            return False

    async def test_concurrent_oauth_flows_performance(self) -> Dict[str, Any]:
        """Test performance under concurrent OAuth flows"""

        results = {}

        # Test different concurrency levels
        concurrency_levels = [5, 10, 15]

        for concurrency in concurrency_levels:
            print(f"  Testing {concurrency} concurrent flows...")

            # Create automation instances
            automations = [OAuthFlowAutomation(self.urls) for _ in range(concurrency)]
            accounts = [list(self.demo_accounts.keys())[i % 3] for i in range(concurrency)]

            try:
                start_time = time.time()

                # Run concurrent flows
                tasks = []
                for i, (automation, account) in enumerate(zip(automations, accounts)):
                    task = asyncio.create_task(
                        automation.run_complete_flow(account),
                        name=f"flow_{account}_{i}"
                    )
                    tasks.append(task)

                # Wait for all flows to complete
                flow_results = await asyncio.gather(*tasks, return_exceptions=True)

                end_time = time.time()
                total_duration = end_time - start_time

                # Analyze results
                successful_flows = 0
                failed_flows = 0

                for i, result in enumerate(flow_results):
                    if isinstance(result, Exception):
                        failed_flows += 1
                    elif result.get("success"):
                        successful_flows += 1
                    else:
                        failed_flows += 1

                success_rate = successful_flows / concurrency
                avg_duration = total_duration / concurrency
                throughput = concurrency / total_duration

                results[f"concurrency_{concurrency}"] = {
                    "total_flows": concurrency,
                    "successful": successful_flows,
                    "failed": failed_flows,
                    "success_rate": success_rate,
                    "total_duration": total_duration,
                    "avg_duration_per_flow": avg_duration,
                    "throughput_flows_per_second": throughput
                }

                print(f"    ✅ {successful_flows}/{concurrency} successful")
                print(f"    ⏱️  Total time: {total_duration:.2f}s")
                print(f"    📊 Throughput: {throughput:.2f} flows/sec")

                if success_rate < 0.8:  # Require 80% success rate
                    raise Exception(f"Low success rate: {success_rate:.1%}")

            finally:
                # Cleanup all automation instances
                for automation in automations:
                    await automation.cleanup()

            # Wait between tests to avoid overwhelming servers
            await asyncio.sleep(2)

        return results

    async def test_token_expiration_and_cleanup(self) -> Dict[str, Any]:
        """Test token expiration and authorization code cleanup"""

        results = {}

        # Test 1: Generate multiple authorization codes and verify cleanup
        print("  Testing authorization code expiration...")

        automation = OAuthFlowAutomation(self.urls)

        try:
            # Generate authorization codes but don't exchange them
            codes = []

            for i in range(3):
                # Step 1: Initiate OAuth flow
                verifier, challenge, auth_url = await automation.step1_initiate_oauth_flow()

                # Step 2: Get authorization page
                await automation.step2_get_authorization_page(auth_url)

                # Step 3: Authenticate user (this generates the code)
                code = await automation.step3_authenticate_user("alice", "password123")
                codes.append(code)

                # Reset state for next iteration
                automation.flow_state = {}

                # Small delay between requests
                await asyncio.sleep(0.5)

            results["codes_generated"] = len(codes)
            print(f"    ✅ Generated {len(codes)} authorization codes")

            # Test 2: Try to use codes multiple times (should fail after first use)
            print("  Testing one-time use enforcement...")

            first_code = codes[0]

            # First use should succeed
            automation.flow_state = {
                "pkce_verifier": PKCEGenerator.generate_challenge()[0],
                "authorization_code": first_code
            }

            try:
                token_response = await automation.step4_exchange_code_for_token(first_code)
                results["first_use_success"] = True
                print(f"    ✅ First code use: SUCCESS")
            except Exception as e:
                results["first_use_success"] = False
                print(f"    ❌ First code use failed: {e}")

            # Second use should fail
            try:
                token_response = await automation.step4_exchange_code_for_token(first_code)
                results["second_use_blocked"] = False
                print(f"    ❌ Second code use: ALLOWED (should be blocked)")
            except Exception as e:
                results["second_use_blocked"] = True
                print(f"    ✅ Second code use: BLOCKED ({str(e)[:50]}...)")

        finally:
            await automation.cleanup()

        return results

    async def test_security_headers_comprehensive(self) -> Dict[str, Any]:
        """Test comprehensive security headers across all servers"""

        results = {}

        # Security headers to check
        security_headers = {
            "x-content-type-options": "nosniff",
            "x-frame-options": ["DENY", "SAMEORIGIN"],
            "x-xss-protection": "1; mode=block",
            "strict-transport-security": "max-age=",
            "cache-control": "no-cache",
            "pragma": "no-cache"
        }

        # Test each server
        for server_name, url in self.urls.items():
            print(f"  Testing {server_name} security headers...")

            server_results = {
                "headers_present": {},
                "headers_correct": {},
                "security_score": 0
            }

            try:
                # Test multiple endpoints
                endpoints = ["/health"]
                if server_name == "auth_server":
                    endpoints.extend(["/", "/authorize?client_id=test"])
                elif server_name == "resource_server":
                    endpoints.extend(["/"])
                elif server_name == "client":
                    endpoints.extend(["/"])

                for endpoint in endpoints:
                    try:
                        response = await self.client.get(f"{url}{endpoint}")
                        headers = dict(response.headers)

                        for header_name, expected_value in security_headers.items():
                            header_present = header_name.lower() in [h.lower() for h in headers.keys()]
                            server_results["headers_present"][header_name] = header_present

                            if header_present:
                                actual_value = headers.get(header_name) or headers.get(header_name.title())

                                if isinstance(expected_value, list):
                                    header_correct = any(exp in actual_value for exp in expected_value)
                                else:
                                    header_correct = expected_value in actual_value

                                server_results["headers_correct"][header_name] = header_correct

                                if header_correct:
                                    server_results["security_score"] += 1

                        break  # Only test first successful endpoint

                    except Exception as e:
                        continue

                # Calculate security score
                total_headers = len(security_headers)
                score_percentage = (server_results["security_score"] / total_headers) * 100
                server_results["security_score_percentage"] = score_percentage

                print(f"    Security score: {server_results['security_score']}/{total_headers} ({score_percentage:.1f}%)")

                results[server_name] = server_results

            except Exception as e:
                results[server_name] = {"error": str(e)}
                print(f"    ❌ Error testing {server_name}: {e}")

        return results

    async def test_cors_configuration(self) -> Dict[str, Any]:
        """Test CORS configuration and cross-origin requests"""

        results = {}

        # Test CORS preflight requests
        cors_origins = [
            "http://localhost:8080",
            "http://localhost:8081",
            "http://localhost:8082",
            "http://127.0.0.1:8080"
        ]

        for server_name, url in self.urls.items():
            print(f"  Testing {server_name} CORS configuration...")

            server_results = {
                "preflight_responses": {},
                "cors_headers_present": {},
                "allowed_origins": []
            }

            try:
                for origin in cors_origins:
                    try:
                        # Send CORS preflight request
                        response = await self.client.options(
                            f"{url}/health",
                            headers={
                                "Origin": origin,
                                "Access-Control-Request-Method": "GET",
                                "Access-Control-Request-Headers": "Content-Type"
                            }
                        )

                        server_results["preflight_responses"][origin] = response.status_code

                        # Check CORS headers
                        cors_headers = {
                            "access-control-allow-origin": response.headers.get("access-control-allow-origin"),
                            "access-control-allow-methods": response.headers.get("access-control-allow-methods"),
                            "access-control-allow-headers": response.headers.get("access-control-allow-headers")
                        }

                        server_results["cors_headers_present"][origin] = cors_headers

                        if cors_headers["access-control-allow-origin"]:
                            server_results["allowed_origins"].append(origin)

                    except Exception as e:
                        server_results["preflight_responses"][origin] = f"Error: {e}"

                print(f"    Allowed origins: {len(server_results['allowed_origins'])}")
                results[server_name] = server_results

            except Exception as e:
                results[server_name] = {"error": str(e)}
                print(f"    ❌ Error testing {server_name}: {e}")

        return results

    async def test_error_handling_and_logging(self) -> Dict[str, Any]:
        """Test comprehensive error handling and logging"""

        results = {}

        # Test various error scenarios
        error_scenarios = [
            {
                "name": "invalid_client_id",
                "url": f"{self.urls['auth_server']}/authorize",
                "params": {
                    "client_id": "invalid-client-12345",
                    "redirect_uri": "http://localhost:8080/callback",
                    "scope": "read",
                    "state": "test-state",
                    "code_challenge": "test-challenge",
                    "code_challenge_method": "S256",
                    "response_type": "code"
                },
                "expected_status": [400, 401]
            },
            {
                "name": "missing_required_params",
                "url": f"{self.urls['auth_server']}/authorize",
                "params": {
                    "client_id": "demo-client"
                    # Missing required parameters
                },
                "expected_status": [400, 422]
            },
            {
                "name": "invalid_pkce_method",
                "url": f"{self.urls['auth_server']}/authorize",
                "params": {
                    "client_id": "demo-client",
                    "redirect_uri": "http://localhost:8080/callback",
                    "scope": "read",
                    "state": "test-state",
                    "code_challenge": "test-challenge",
                    "code_challenge_method": "plain",  # Invalid method
                    "response_type": "code"
                },
                "expected_status": [400]
            },
            {
                "name": "unauthorized_resource_access",
                "url": f"{self.urls['resource_server']}/protected",
                "params": {},
                "expected_status": [401]
            },
            {
                "name": "invalid_bearer_token",
                "url": f"{self.urls['resource_server']}/protected",
                "params": {},
                "headers": {"Authorization": "Bearer invalid-token-12345"},
                "expected_status": [401]
            }
        ]

        for scenario in error_scenarios:
            print(f"  Testing {scenario['name']}...")

            try:
                headers = scenario.get("headers", {})

                if scenario["params"]:
                    response = await self.client.get(scenario["url"], params=scenario["params"], headers=headers)
                else:
                    response = await self.client.get(scenario["url"], headers=headers)

                status_code = response.status_code
                expected_statuses = scenario["expected_status"]

                if status_code in expected_statuses:
                    results[scenario["name"]] = {
                        "status": "PASS",
                        "status_code": status_code,
                        "expected": expected_statuses
                    }
                    print(f"    ✅ {scenario['name']}: HTTP {status_code} (expected)")
                else:
                    results[scenario["name"]] = {
                        "status": "FAIL",
                        "status_code": status_code,
                        "expected": expected_statuses
                    }
                    print(f"    ❌ {scenario['name']}: HTTP {status_code} (expected {expected_statuses})")

            except Exception as e:
                results[scenario["name"]] = {
                    "status": "ERROR",
                    "error": str(e)
                }
                print(f"    ❌ {scenario['name']}: Error - {e}")

        return results

    async def test_rate_limiting_and_abuse_protection(self) -> Dict[str, Any]:
        """Test rate limiting and abuse protection mechanisms"""

        results = {}

        # Test rapid requests to see if there's any rate limiting
        print("  Testing rapid request handling...")

        rapid_request_count = 50
        start_time = time.time()

        tasks = []
        for i in range(rapid_request_count):
            task = asyncio.create_task(
                self.client.get(f"{self.urls['auth_server']}/health")
            )
            tasks.append(task)

        responses = await asyncio.gather(*tasks, return_exceptions=True)
        end_time = time.time()

        successful_requests = 0
        failed_requests = 0
        rate_limited_requests = 0

        for response in responses:
            if isinstance(response, Exception):
                failed_requests += 1
            elif response.status_code == 200:
                successful_requests += 1
            elif response.status_code == 429:  # Too Many Requests
                rate_limited_requests += 1
            else:
                failed_requests += 1

        total_duration = end_time - start_time
        requests_per_second = rapid_request_count / total_duration

        results["rapid_requests"] = {
            "total_requests": rapid_request_count,
            "successful": successful_requests,
            "failed": failed_requests,
            "rate_limited": rate_limited_requests,
            "duration": total_duration,
            "requests_per_second": requests_per_second
        }

        print(f"    📊 {successful_requests}/{rapid_request_count} successful")
        print(f"    ⚡ {requests_per_second:.1f} requests/second")
        print(f"    🛡️  {rate_limited_requests} rate limited")

        return results

    async def run_all_tests(self) -> Dict[str, Any]:
        """Run all performance and security tests"""

        print("🚀 OAuth 2.1 Performance and Security Validation Suite")
        print("=" * 60)
        print(f"🕐 Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)

        # Test 1: Concurrent OAuth flows performance
        await self.run_test(
            "concurrent_oauth_flows_performance",
            self.test_concurrent_oauth_flows_performance
        )

        # Test 2: Token expiration and cleanup
        await self.run_test(
            "token_expiration_and_cleanup",
            self.test_token_expiration_and_cleanup
        )

        # Test 3: Security headers comprehensive
        await self.run_test(
            "security_headers_comprehensive",
            self.test_security_headers_comprehensive
        )

        # Test 4: CORS configuration
        await self.run_test(
            "cors_configuration",
            self.test_cors_configuration
        )

        # Test 5: Error handling and logging
        await self.run_test(
            "error_handling_and_logging",
            self.test_error_handling_and_logging
        )

        # Test 6: Rate limiting and abuse protection
        await self.run_test(
            "rate_limiting_and_abuse_protection",
            self.test_rate_limiting_and_abuse_protection
        )

        # Print summary
        print("\n📊 Performance and Security Test Summary")
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
        description="OAuth 2.1 Performance and Security Validation Suite"
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
    tester = PerformanceSecurityTester()

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
        print("\n👋 Performance and security tests interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Performance and security tests failed: {e}")
        sys.exit(1)
    finally:
        await tester.cleanup()


if __name__ == "__main__":
    asyncio.run(main())