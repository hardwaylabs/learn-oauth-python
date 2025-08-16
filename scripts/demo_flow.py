#!/usr/bin/env python3
"""
OAuth 2.1 Demo Flow Automation Script

This script automates the complete OAuth 2.1 flow for testing and demonstration
purposes. It simulates a client application going through the authorization code
flow with PKCE, including user authentication and resource access.
"""

import sys
import os
import time
import asyncio
import json
from pathlib import Path
from typing import Dict, Optional, Tuple, Any
from urllib.parse import urlencode, parse_qs, urlparse
import re

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

try:
    import httpx
    from bs4 import BeautifulSoup
except ImportError as e:
    print(f"❌ Missing required dependency: {e}")
    print("   Install with: pip install httpx beautifulsoup4")
    sys.exit(1)

from src.shared.crypto_utils import PKCEGenerator
from src.shared.logging_utils import OAuthLogger


class OAuthFlowAutomation:
    """Automated OAuth 2.1 flow testing with PKCE"""

    def __init__(self, base_urls: Optional[Dict[str, str]] = None):
        self.logger = OAuthLogger("DEMO-AUTOMATION")

        # Default server URLs
        self.urls = base_urls or {
            "client": "http://localhost:8080",
            "auth_server": "http://localhost:8081",
            "resource_server": "http://localhost:8082"
        }

        # OAuth configuration
        self.oauth_config = {
            "client_id": "demo-client",
            "redirect_uri": "http://localhost:8080/callback",
            "scope": "read"
        }

        # Demo accounts
        self.demo_accounts = {
            "alice": "password123",
            "bob": "secret456",
            "carol": "mypass789"
        }

        # Flow state
        self.flow_state = {}

        # HTTP client with session support
        self.client = httpx.AsyncClient(
            timeout=30.0,
            follow_redirects=False  # We want to handle redirects manually
        )

    async def check_server_health(self) -> Dict[str, bool]:
        """Check if all servers are running and healthy"""

        print("🔍 Checking server health...")
        health_status = {}

        for server_name, base_url in self.urls.items():
            try:
                response = await self.client.get(f"{base_url}/health", timeout=5.0)

                if response.status_code == 200:
                    health_status[server_name] = True
                    print(f"  ✅ {server_name.title()}: {base_url} - Healthy")

                    self.logger.log_oauth_message(
                        "DEMO-AUTOMATION", server_name.upper().replace("_", "-"),
                        "Health Check Success",
                        {
                            "url": f"{base_url}/health",
                            "status_code": response.status_code,
                            "response_time": f"{response.elapsed.total_seconds():.2f}s"
                        }
                    )
                else:
                    health_status[server_name] = False
                    print(f"  ❌ {server_name.title()}: {base_url} - Unhealthy (HTTP {response.status_code})")

            except Exception as e:
                health_status[server_name] = False
                print(f"  ❌ {server_name.title()}: {base_url} - Connection failed ({e})")

        all_healthy = all(health_status.values())
        if all_healthy:
            print("✅ All servers are healthy and ready")
        else:
            print("❌ Some servers are not responding")

        return health_status

    async def step1_initiate_oauth_flow(self) -> Tuple[str, str, str]:
        """
        Step 1: Generate PKCE challenge and build authorization URL

        Returns:
            Tuple of (verifier, challenge, authorization_url)
        """

        print("\n📋 Step 1: Initiating OAuth Flow")
        print("-" * 40)

        # Generate PKCE challenge
        verifier, challenge = PKCEGenerator.generate_challenge()

        # Generate state parameter
        import secrets
        state = secrets.token_urlsafe(16)

        # Store in flow state
        self.flow_state.update({
            "pkce_verifier": verifier,
            "pkce_challenge": challenge,
            "state": state
        })

        # Build authorization URL
        auth_params = {
            "client_id": self.oauth_config["client_id"],
            "redirect_uri": self.oauth_config["redirect_uri"],
            "scope": self.oauth_config["scope"],
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "response_type": "code"
        }

        authorization_url = f"{self.urls['auth_server']}/authorize?{urlencode(auth_params)}"

        print(f"🔑 PKCE Verifier: {verifier[:20]}...{verifier[-10:]}")
        print(f"🔐 PKCE Challenge: {challenge[:20]}...{challenge[-10:]}")
        print(f"🎲 State: {state}")
        print(f"🌐 Authorization URL: {authorization_url}")

        self.logger.log_oauth_message(
            "DEMO-AUTOMATION", "DEMO-AUTOMATION",
            "OAuth Flow Initiated",
            {
                "client_id": self.oauth_config["client_id"],
                "redirect_uri": self.oauth_config["redirect_uri"],
                "scope": self.oauth_config["scope"],
                "state": state,
                "pkce_challenge": challenge[:20] + "...",
                "pkce_method": "S256",
                "authorization_url": authorization_url
            }
        )

        return verifier, challenge, authorization_url

    async def step2_get_authorization_page(self, authorization_url: str) -> str:
        """
        Step 2: Request authorization page from auth server

        Args:
            authorization_url: The authorization URL to request

        Returns:
            HTML content of the login page
        """

        print("\n🌐 Step 2: Requesting Authorization Page")
        print("-" * 40)

        try:
            response = await self.client.get(authorization_url)

            if response.status_code == 200:
                print(f"✅ Authorization page received (HTTP {response.status_code})")
                print(f"📄 Content length: {len(response.text)} bytes")

                # Parse the HTML to extract form details
                soup = BeautifulSoup(response.text, 'html.parser')
                form = soup.find('form')

                if form:
                    action = form.get('action', '/login')
                    method = form.get('method', 'POST')
                    print(f"📝 Login form found: {method} {action}")

                    # Extract hidden fields
                    hidden_fields = {}
                    for input_field in form.find_all('input', type='hidden'):
                        name = input_field.get('name')
                        value = input_field.get('value')
                        if name and value:
                            hidden_fields[name] = value

                    if hidden_fields:
                        print(f"🔒 Hidden fields: {list(hidden_fields.keys())}")
                        self.flow_state['hidden_fields'] = hidden_fields

                self.logger.log_oauth_message(
                    "AUTH-SERVER", "DEMO-AUTOMATION",
                    "Authorization Page Response",
                    {
                        "status_code": response.status_code,
                        "content_length": len(response.text),
                        "form_found": form is not None,
                        "hidden_fields": len(hidden_fields) if form else 0
                    }
                )

                return response.text
            else:
                print(f"❌ Failed to get authorization page (HTTP {response.status_code})")
                print(f"Response: {response.text}")
                raise Exception(f"Authorization request failed: HTTP {response.status_code}")

        except Exception as e:
            print(f"❌ Error requesting authorization page: {e}")
            raise

    async def step3_authenticate_user(self, username: str, password: str) -> str:
        """
        Step 3: Submit user credentials to get authorization code

        Args:
            username: Demo account username
            password: Demo account password

        Returns:
            Authorization code from the callback
        """

        print(f"\n🔐 Step 3: Authenticating User '{username}'")
        print("-" * 40)

        # Prepare login form data
        login_data = {
            "username": username,
            "password": password,
            **self.flow_state.get('hidden_fields', {})
        }

        print(f"👤 Username: {username}")
        print(f"🔑 Password: {'*' * len(password)}")
        print(f"📝 Form fields: {list(login_data.keys())}")

        try:
            # Submit login form
            response = await self.client.post(
                f"{self.urls['auth_server']}/login",
                data=login_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )

            self.logger.log_oauth_message(
                "DEMO-AUTOMATION", "AUTH-SERVER",
                "User Authentication Request",
                {
                    "username": username,
                    "form_fields": list(login_data.keys()),
                    "endpoint": f"{self.urls['auth_server']}/login"
                }
            )

            if response.status_code == 302:
                # Successful authentication - should redirect to callback
                location = response.headers.get('location')
                print(f"✅ Authentication successful (HTTP {response.status_code})")
                print(f"🔄 Redirect location: {location}")

                if location:
                    # Parse authorization code from redirect URL
                    parsed_url = urlparse(location)
                    query_params = parse_qs(parsed_url.query)

                    auth_code = query_params.get('code', [None])[0]
                    returned_state = query_params.get('state', [None])[0]

                    if auth_code:
                        print(f"🎫 Authorization code: {auth_code[:20]}...{auth_code[-10:]}")
                        print(f"🎲 Returned state: {returned_state}")

                        # Verify state parameter
                        if returned_state == self.flow_state.get('state'):
                            print("✅ State parameter verified")
                        else:
                            print("❌ State parameter mismatch!")
                            raise Exception("State parameter validation failed")

                        self.flow_state['authorization_code'] = auth_code

                        self.logger.log_oauth_message(
                            "AUTH-SERVER", "DEMO-AUTOMATION",
                            "Authorization Code Received",
                            {
                                "code": auth_code[:10] + "...",
                                "state": returned_state,
                                "state_verified": True,
                                "redirect_uri": location
                            }
                        )

                        return auth_code
                    else:
                        print("❌ No authorization code in redirect")
                        raise Exception("Authorization code not found in redirect")
                else:
                    print("❌ No redirect location header")
                    raise Exception("No redirect location in response")
            else:
                print(f"❌ Authentication failed (HTTP {response.status_code})")
                print(f"Response: {response.text}")
                raise Exception(f"Authentication failed: HTTP {response.status_code}")

        except Exception as e:
            print(f"❌ Error during authentication: {e}")
            raise

    async def step4_exchange_code_for_token(self, auth_code: str) -> Dict[str, Any]:
        """
        Step 4: Exchange authorization code + PKCE verifier for access token

        Args:
            auth_code: Authorization code from step 3

        Returns:
            Token response dictionary
        """

        print("\n🔄 Step 4: Exchanging Code for Access Token")
        print("-" * 40)

        # Prepare token request
        token_data = {
            "grant_type": "authorization_code",
            "code": auth_code,
            "redirect_uri": self.oauth_config["redirect_uri"],
            "client_id": self.oauth_config["client_id"],
            "code_verifier": self.flow_state["pkce_verifier"]
        }

        print(f"🎫 Authorization code: {auth_code[:20]}...{auth_code[-10:]}")
        print(f"🔐 PKCE verifier: {self.flow_state['pkce_verifier'][:20]}...{self.flow_state['pkce_verifier'][-10:]}")
        print(f"🏢 Client ID: {token_data['client_id']}")
        print(f"🔄 Grant type: {token_data['grant_type']}")

        try:
            self.logger.log_oauth_message(
                "DEMO-AUTOMATION", "AUTH-SERVER",
                "Token Exchange Request",
                {
                    "grant_type": token_data["grant_type"],
                    "client_id": token_data["client_id"],
                    "redirect_uri": token_data["redirect_uri"],
                    "code": auth_code[:10] + "...",
                    "code_verifier": self.flow_state["pkce_verifier"][:10] + "...",
                    "endpoint": f"{self.urls['auth_server']}/token"
                }
            )

            # Make token request
            response = await self.client.post(
                f"{self.urls['auth_server']}/token",
                json=token_data,
                headers={"Content-Type": "application/json"}
            )

            if response.status_code == 200:
                token_response = response.json()

                print(f"✅ Token exchange successful (HTTP {response.status_code})")
                print(f"🎟️  Access token: {token_response['access_token'][:20]}...{token_response['access_token'][-10:]}")
                print(f"🏷️  Token type: {token_response.get('token_type', 'Bearer')}")
                print(f"⏰ Expires in: {token_response.get('expires_in', 3600)} seconds")
                print(f"🎯 Scope: {token_response.get('scope', 'read')}")

                self.flow_state['access_token'] = token_response['access_token']
                self.flow_state['token_type'] = token_response.get('token_type', 'Bearer')

                self.logger.log_oauth_message(
                    "AUTH-SERVER", "DEMO-AUTOMATION",
                    "Access Token Received",
                    {
                        "access_token": token_response['access_token'][:10] + "...",
                        "token_type": token_response.get('token_type', 'Bearer'),
                        "expires_in": token_response.get('expires_in', 3600),
                        "scope": token_response.get('scope', 'read')
                    }
                )

                return token_response
            else:
                error_data = response.json() if response.headers.get("content-type", "").startswith("application/json") else {}
                print(f"❌ Token exchange failed (HTTP {response.status_code})")
                print(f"Error: {error_data.get('error', 'unknown_error')}")
                print(f"Description: {error_data.get('error_description', 'No description')}")
                raise Exception(f"Token exchange failed: {error_data.get('error', 'HTTP ' + str(response.status_code))}")

        except Exception as e:
            print(f"❌ Error during token exchange: {e}")
            raise

    async def step5_access_protected_resource(self) -> str:
        """
        Step 5: Access protected resource using Bearer token

        Returns:
            Protected resource content
        """

        print("\n🔒 Step 5: Accessing Protected Resource")
        print("-" * 40)

        access_token = self.flow_state.get('access_token')
        token_type = self.flow_state.get('token_type', 'Bearer')

        if not access_token:
            raise Exception("No access token available")

        # Prepare authorization header
        auth_header = f"{token_type} {access_token}"

        print(f"🎟️  Using token: {access_token[:20]}...{access_token[-10:]}")
        print(f"🔐 Authorization: {token_type} {access_token[:10]}...")

        try:
            self.logger.log_oauth_message(
                "DEMO-AUTOMATION", "RESOURCE-SERVER",
                "Protected Resource Request",
                {
                    "endpoint": f"{self.urls['resource_server']}/protected",
                    "method": "GET",
                    "authorization": f"{token_type} {access_token[:10]}...",
                    "resource_server": self.urls['resource_server']
                }
            )

            # Access protected resource
            response = await self.client.get(
                f"{self.urls['resource_server']}/protected",
                headers={"Authorization": auth_header}
            )

            if response.status_code == 200:
                content = response.text

                print(f"✅ Protected resource accessed successfully (HTTP {response.status_code})")
                print(f"📄 Content length: {len(content)} bytes")
                print(f"📝 Content preview: {content[:100]}...")

                self.logger.log_oauth_message(
                    "RESOURCE-SERVER", "DEMO-AUTOMATION",
                    "Protected Resource Response",
                    {
                        "status_code": 200,
                        "content_length": len(content),
                        "content_type": response.headers.get("content-type", "text/plain"),
                        "access_granted": True
                    }
                )

                return content
            else:
                print(f"❌ Failed to access protected resource (HTTP {response.status_code})")
                print(f"Response: {response.text}")
                raise Exception(f"Resource access failed: HTTP {response.status_code}")

        except Exception as e:
            print(f"❌ Error accessing protected resource: {e}")
            raise

    async def step6_access_user_info(self) -> Dict[str, Any]:
        """
        Step 6: Access user info endpoint using Bearer token

        Returns:
            User info dictionary
        """

        print("\n👤 Step 6: Accessing User Info")
        print("-" * 40)

        access_token = self.flow_state.get('access_token')
        token_type = self.flow_state.get('token_type', 'Bearer')

        if not access_token:
            raise Exception("No access token available")

        # Prepare authorization header
        auth_header = f"{token_type} {access_token}"

        print(f"🎟️  Using token: {access_token[:20]}...{access_token[-10:]}")

        try:
            self.logger.log_oauth_message(
                "DEMO-AUTOMATION", "RESOURCE-SERVER",
                "User Info Request",
                {
                    "endpoint": f"{self.urls['resource_server']}/userinfo",
                    "method": "GET",
                    "authorization": f"{token_type} {access_token[:10]}...",
                    "resource_server": self.urls['resource_server']
                }
            )

            # Access user info endpoint
            response = await self.client.get(
                f"{self.urls['resource_server']}/userinfo",
                headers={"Authorization": auth_header}
            )

            if response.status_code == 200:
                user_info = response.json()

                print(f"✅ User info accessed successfully (HTTP {response.status_code})")
                print(f"👤 User ID: {user_info.get('sub', 'N/A')}")
                print(f"📧 Email: {user_info.get('email', 'N/A')}")
                print(f"👤 Name: {user_info.get('name', 'N/A')}")
                print(f"🔗 Profile: {user_info.get('profile', 'N/A')}")

                self.logger.log_oauth_message(
                    "RESOURCE-SERVER", "DEMO-AUTOMATION",
                    "User Info Response",
                    {
                        "status_code": 200,
                        "user_id": user_info.get('sub'),
                        "email": user_info.get('email'),
                        "fields_returned": list(user_info.keys())
                    }
                )

                return user_info
            else:
                print(f"❌ Failed to access user info (HTTP {response.status_code})")
                print(f"Response: {response.text}")
                raise Exception(f"User info access failed: HTTP {response.status_code}")

        except Exception as e:
            print(f"❌ Error accessing user info: {e}")
            raise

    async def run_complete_flow(self, username: str = "alice", password: Optional[str] = None) -> Dict[str, Any]:
        """
        Run the complete OAuth 2.1 flow from start to finish

        Args:
            username: Demo account username (default: alice)
            password: Demo account password (auto-detected if None)

        Returns:
            Dictionary with flow results
        """

        if password is None:
            password = self.demo_accounts.get(username)
            if not password:
                raise ValueError(f"Unknown demo account: {username}")

        print("🚀 OAuth 2.1 Complete Flow Automation")
        print("=" * 60)
        print(f"👤 Demo Account: {username}")
        print(f"🏢 Client ID: {self.oauth_config['client_id']}")
        print(f"🎯 Scope: {self.oauth_config['scope']}")
        print(f"🔄 Redirect URI: {self.oauth_config['redirect_uri']}")
        print("=" * 60)

        results = {
            "success": False,
            "steps_completed": [],
            "flow_state": {},
            "errors": []
        }

        try:
            # Check server health first
            health_status = await self.check_server_health()
            if not all(health_status.values()):
                raise Exception("Not all servers are healthy")
            results["steps_completed"].append("health_check")

            # Step 1: Initiate OAuth flow
            verifier, challenge, auth_url = await self.step1_initiate_oauth_flow()
            results["steps_completed"].append("initiate_flow")

            # Step 2: Get authorization page
            auth_page = await self.step2_get_authorization_page(auth_url)
            results["steps_completed"].append("get_auth_page")

            # Step 3: Authenticate user
            auth_code = await self.step3_authenticate_user(username, password)
            results["steps_completed"].append("authenticate_user")

            # Step 4: Exchange code for token
            token_response = await self.step4_exchange_code_for_token(auth_code)
            results["steps_completed"].append("exchange_token")

            # Step 5: Access protected resource
            protected_content = await self.step5_access_protected_resource()
            results["steps_completed"].append("access_protected_resource")

            # Step 6: Access user info
            user_info = await self.step6_access_user_info()
            results["steps_completed"].append("access_user_info")

            # Success!
            results.update({
                "success": True,
                "flow_state": self.flow_state.copy(),
                "token_response": token_response,
                "protected_content": protected_content,
                "user_info": user_info
            })

            print("\n🎉 OAuth 2.1 Flow Completed Successfully!")
            print("=" * 60)
            print("✅ All steps completed:")
            for step in results["steps_completed"]:
                print(f"   • {step.replace('_', ' ').title()}")

            self.logger.log_oauth_message(
                "DEMO-AUTOMATION", "DEMO-AUTOMATION",
                "Complete Flow Success",
                {
                    "username": username,
                    "steps_completed": len(results["steps_completed"]),
                    "total_steps": 6,
                    "success": True,
                    "flow_duration": "completed"
                }
            )

        except Exception as e:
            results["errors"].append(str(e))
            print(f"\n❌ OAuth Flow Failed: {e}")

            self.logger.log_oauth_message(
                "DEMO-AUTOMATION", "DEMO-AUTOMATION",
                "Complete Flow Failed",
                {
                    "username": username,
                    "steps_completed": len(results["steps_completed"]),
                    "error": str(e),
                    "last_step": results["steps_completed"][-1] if results["steps_completed"] else "none"
                }
            )

        return results

    async def test_all_demo_accounts(self) -> Dict[str, Dict[str, Any]]:
        """Test OAuth flow with all demo accounts"""

        print("🧪 Testing All Demo Accounts")
        print("=" * 60)

        all_results = {}

        for username, password in self.demo_accounts.items():
            print(f"\n🔄 Testing account: {username}")
            print("-" * 30)

            # Reset flow state for each account
            self.flow_state = {}

            try:
                results = await self.run_complete_flow(username, password)
                all_results[username] = results

                if results["success"]:
                    print(f"✅ {username}: SUCCESS")
                else:
                    print(f"❌ {username}: FAILED - {results['errors']}")

            except Exception as e:
                all_results[username] = {
                    "success": False,
                    "errors": [str(e)],
                    "steps_completed": []
                }
                print(f"❌ {username}: EXCEPTION - {e}")

            # Wait between tests to avoid overwhelming servers
            if username != list(self.demo_accounts.keys())[-1]:  # Not the last account
                print("⏳ Waiting 2 seconds before next test...")
                await asyncio.sleep(2)

        # Summary
        print("\n📊 Test Summary")
        print("=" * 60)
        successful = sum(1 for r in all_results.values() if r["success"])
        total = len(all_results)

        print(f"✅ Successful: {successful}/{total}")
        print(f"❌ Failed: {total - successful}/{total}")

        for username, results in all_results.items():
            status = "✅ PASS" if results["success"] else "❌ FAIL"
            steps = len(results["steps_completed"])
            print(f"   {username}: {status} ({steps}/6 steps)")

        return all_results

    async def cleanup(self):
        """Clean up resources"""
        await self.client.aclose()


async def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(
        description="Automated OAuth 2.1 flow testing and demonstration"
    )
    parser.add_argument(
        "--username", "-u",
        default="alice",
        help="Demo account username (default: alice)"
    )
    parser.add_argument(
        "--password", "-p",
        help="Demo account password (auto-detected if not provided)"
    )
    parser.add_argument(
        "--test-all",
        action="store_true",
        help="Test all demo accounts"
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
    parser.add_argument(
        "--output",
        help="Save results to JSON file"
    )

    args = parser.parse_args()

    # Configure server URLs
    urls = {
        "client": args.client_url,
        "auth_server": args.auth_url,
        "resource_server": args.resource_url
    }

    # Create automation instance
    automation = OAuthFlowAutomation(urls)

    try:
        if args.test_all:
            # Test all demo accounts
            results = await automation.test_all_demo_accounts()
        else:
            # Test single account
            results = await automation.run_complete_flow(args.username, args.password)

        # Save results if requested
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            print(f"\n💾 Results saved to: {args.output}")

        # Exit with appropriate code
        if isinstance(results, dict):
            # Single account test
            sys.exit(0 if results.get("success") else 1)
        else:
            # Multiple account test
            all_successful = all(r.get("success", False) for r in results.values())
            sys.exit(0 if all_successful else 1)

    except KeyboardInterrupt:
        print("\n👋 Demo automation interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Demo automation failed: {e}")
        sys.exit(1)
    finally:
        await automation.cleanup()


if __name__ == "__main__":
    asyncio.run(main())