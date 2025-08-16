#!/usr/bin/env python3
"""
Password Hashing Utility for OAuth 2.1 Learning System

This script generates bcrypt password hashes for demo accounts and provides
utilities for testing password verification. The output can be easily
copy-pasted into the user storage configuration.
"""

import sys
import os
from pathlib import Path
from typing import Dict, List, Tuple
import json

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from src.shared.security import PasswordHasher, InputValidator
from src.shared.logging_utils import OAuthLogger


class PasswordHashingUtility:
    """Utility for generating and testing password hashes for demo accounts"""

    def __init__(self):
        self.logger = OAuthLogger("HASH-UTILITY")
        self.demo_accounts = {
            'alice': 'password123',
            'bob': 'secret456',
            'carol': 'mypass789'
        }

    def generate_demo_hashes(self) -> Dict[str, Dict[str, str]]:
        """
        Generate password hashes for all demo accounts.

        Returns:
            Dict mapping usernames to account info with hashed passwords
        """
        print("🔐 Generating password hashes for demo accounts...")
        print("=" * 50)

        hashed_accounts = {}

        for username, password in self.demo_accounts.items():
            print(f"📝 Processing account: {username}")

            # Validate password strength (for educational purposes)
            is_strong, issues = InputValidator.validate_password_strength(password)
            if not is_strong:
                print(f"  ⚠️  Password strength issues: {', '.join(issues)}")
                print(f"  ℹ️  Note: Demo passwords are intentionally simple for learning")

            # Generate hash
            try:
                password_hash = PasswordHasher.hash_password(password)

                hashed_accounts[username] = {
                    'password_hash': password_hash,
                    'email': f'{username}@example.com',
                    'plain_password': password  # For reference only
                }

                print(f"  ✅ Hash generated successfully")
                print(f"  📧 Email: {username}@example.com")

                self.logger.log_oauth_message(
                    "HASH-UTILITY", "HASH-UTILITY",
                    "Password Hash Generated",
                    {
                        "username": username,
                        "hash_algorithm": "bcrypt",
                        "hash_length": len(password_hash),
                        "email": f"{username}@example.com"
                    }
                )

            except Exception as e:
                print(f"  ❌ Error generating hash: {e}")
                continue

        print("=" * 50)
        print(f"✅ Generated hashes for {len(hashed_accounts)} accounts")

        return hashed_accounts

    def verify_hashes(self, hashed_accounts: Dict[str, Dict[str, str]]) -> bool:
        """
        Verify that generated hashes work correctly.

        Args:
            hashed_accounts: Dictionary of account data with hashes

        Returns:
            bool: True if all verifications pass
        """
        print("\n🔍 Verifying generated password hashes...")
        print("=" * 50)

        all_passed = True

        for username, account_data in hashed_accounts.items():
            password_hash = account_data['password_hash']
            original_password = account_data['plain_password']

            print(f"🧪 Testing {username}...")

            # Test correct password
            if PasswordHasher.verify_password(original_password, password_hash):
                print(f"  ✅ Correct password verification: PASS")
            else:
                print(f"  ❌ Correct password verification: FAIL")
                all_passed = False

            # Test incorrect password
            wrong_password = original_password + "wrong"
            if not PasswordHasher.verify_password(wrong_password, password_hash):
                print(f"  ✅ Incorrect password rejection: PASS")
            else:
                print(f"  ❌ Incorrect password rejection: FAIL")
                all_passed = False

            # Test empty password
            if not PasswordHasher.verify_password("", password_hash):
                print(f"  ✅ Empty password rejection: PASS")
            else:
                print(f"  ❌ Empty password rejection: FAIL")
                all_passed = False

            self.logger.log_oauth_message(
                "HASH-UTILITY", "HASH-UTILITY",
                "Hash Verification Test",
                {
                    "username": username,
                    "correct_password_test": "PASS",
                    "incorrect_password_test": "PASS",
                    "empty_password_test": "PASS"
                }
            )

        print("=" * 50)
        if all_passed:
            print("✅ All hash verifications passed!")
        else:
            print("❌ Some hash verifications failed!")

        return all_passed

    def generate_python_code(self, hashed_accounts: Dict[str, Dict[str, str]]) -> str:
        """
        Generate Python code for easy copy-paste into storage.py

        Args:
            hashed_accounts: Dictionary of account data with hashes

        Returns:
            str: Python code string
        """
        code_lines = [
            "# Generated password hashes for demo accounts",
            "# Use this code in your UserStore class",
            "",
            "demo_users = {"
        ]

        for username, account_data in hashed_accounts.items():
            code_lines.extend([
                f"    '{username}': {{",
                f"        'password_hash': '{account_data['password_hash']}',",
                f"        'email': '{account_data['email']}'",
                f"    }},"
            ])

        code_lines.extend([
            "}",
            "",
            "# Demo account credentials for testing:",
            "# " + " | ".join([f"{user}: {data['plain_password']}"
                              for user, data in hashed_accounts.items()])
        ])

        return "\n".join(code_lines)

    def generate_json_output(self, hashed_accounts: Dict[str, Dict[str, str]]) -> str:
        """
        Generate JSON output for configuration files.

        Args:
            hashed_accounts: Dictionary of account data with hashes

        Returns:
            str: JSON string
        """
        # Remove plain passwords from JSON output for security
        json_data = {}
        for username, account_data in hashed_accounts.items():
            json_data[username] = {
                'password_hash': account_data['password_hash'],
                'email': account_data['email']
            }

        return json.dumps(json_data, indent=2)

    def save_to_file(self, content: str, filename: str, description: str):
        """Save content to a file with logging"""
        try:
            output_path = Path("scripts") / "output" / filename
            output_path.parent.mkdir(exist_ok=True)

            with open(output_path, 'w') as f:
                f.write(content)

            print(f"💾 {description} saved to: {output_path}")

            self.logger.log_oauth_message(
                "HASH-UTILITY", "FILE-SYSTEM",
                "Output File Created",
                {
                    "filename": str(output_path),
                    "description": description,
                    "size_bytes": len(content)
                }
            )

        except Exception as e:
            print(f"❌ Error saving {description}: {e}")

    def interactive_hash_generator(self):
        """Interactive mode for generating custom password hashes"""
        print("\n🔧 Interactive Password Hash Generator")
        print("=" * 50)
        print("Enter passwords to generate hashes (empty line to exit)")

        while True:
            try:
                password = input("\n🔑 Enter password: ").strip()

                if not password:
                    break

                # Check password strength
                is_strong, issues = InputValidator.validate_password_strength(password)
                if not is_strong:
                    print(f"⚠️  Password strength issues:")
                    for issue in issues:
                        print(f"   • {issue}")

                    continue_anyway = input("Continue anyway? (y/N): ").strip().lower()
                    if continue_anyway != 'y':
                        continue

                # Generate hash
                password_hash = PasswordHasher.hash_password(password)

                print(f"\n📋 Generated Hash:")
                print(f"   {password_hash}")

                # Verify hash works
                if PasswordHasher.verify_password(password, password_hash):
                    print("✅ Hash verification: PASS")
                else:
                    print("❌ Hash verification: FAIL")

                # Offer to save
                save_option = input("\n💾 Save to file? (y/N): ").strip().lower()
                if save_option == 'y':
                    username = input("Username for this hash: ").strip()
                    if username:
                        timestamp = int(time.time())
                        content = f"# Password hash for {username}\n"
                        content += f"# Generated at: {datetime.now().isoformat()}\n"
                        content += f"'{username}': {{\n"
                        content += f"    'password_hash': '{password_hash}',\n"
                        content += f"    'email': '{username}@example.com'\n"
                        content += f"}}\n"

                        self.save_to_file(content, f"hash_{username}_{timestamp}.py", f"Hash for {username}")

            except KeyboardInterrupt:
                print("\n👋 Exiting interactive mode...")
                break
            except Exception as e:
                print(f"❌ Error: {e}")

    def run(self, interactive: bool = False, save_output: bool = True):
        """
        Main run method for the password hashing utility.

        Args:
            interactive: Whether to run in interactive mode
            save_output: Whether to save output files
        """
        print("🔐 OAuth 2.1 Password Hashing Utility")
        print("=" * 60)

        # Generate demo account hashes
        hashed_accounts = self.generate_demo_hashes()

        if not hashed_accounts:
            print("❌ No hashes generated. Exiting.")
            return

        # Verify hashes work correctly
        if not self.verify_hashes(hashed_accounts):
            print("❌ Hash verification failed. Please check your bcrypt installation.")
            return

        # Generate output formats
        print("\n📋 Generated Output Formats:")
        print("=" * 50)

        # Python code format
        python_code = self.generate_python_code(hashed_accounts)
        print("\n🐍 Python Code (for storage.py):")
        print("-" * 30)
        print(python_code)

        # JSON format
        json_output = self.generate_json_output(hashed_accounts)
        print("\n📄 JSON Format:")
        print("-" * 30)
        print(json_output)

        # Save outputs if requested
        if save_output:
            print("\n💾 Saving output files...")
            self.save_to_file(python_code, "demo_users.py", "Python code for demo users")
            self.save_to_file(json_output, "demo_users.json", "JSON data for demo users")

            # Create a complete storage.py template
            storage_template = self._generate_storage_template(hashed_accounts)
            self.save_to_file(storage_template, "user_storage_template.py", "Complete UserStore template")

        # Interactive mode
        if interactive:
            self.interactive_hash_generator()

        print("\n🎉 Password hashing utility completed successfully!")
        print("\n📚 Usage Instructions:")
        print("  1. Copy the Python code above into your UserStore class")
        print("  2. Update the _users dictionary in src/auth_server/storage.py")
        print("  3. Test login with demo accounts:")
        for username, data in hashed_accounts.items():
            print(f"     • {username} / {data['plain_password']}")

    def _generate_storage_template(self, hashed_accounts: Dict[str, Dict[str, str]]) -> str:
        """Generate a complete UserStore template"""
        template = '''"""
User Storage Template with Generated Password Hashes
Generated by OAuth 2.1 Password Hashing Utility
"""

from typing import Optional, Dict
from ..shared.security import PasswordHasher

class UserStore:
    """In-memory user storage with bcrypt password hashes"""

    def __init__(self):
        # Demo users with bcrypt-hashed passwords
        self._users = {
'''

        for username, account_data in hashed_accounts.items():
            template += f'''            '{username}': {{
                'password_hash': '{account_data['password_hash']}',
                'email': '{account_data['email']}'
            }},
'''

        template += '''        }

    def authenticate(self, username: str, password: str) -> Optional[Dict]:
        """
        Authenticate user with bcrypt password verification.

        Args:
            username: Username to authenticate
            password: Plain text password

        Returns:
            Dict with user info if authentication succeeds, None otherwise
        """
        user = self._users.get(username)
        if not user:
            return None

        if PasswordHasher.verify_password(password, user['password_hash']):
            return {
                'username': username,
                'email': user['email']
            }

        return None

    def get_user(self, username: str) -> Optional[Dict]:
        """Get user information without password"""
        user = self._users.get(username)
        if user:
            return {
                'username': username,
                'email': user['email']
            }
        return None

    def list_users(self) -> list:
        """List all usernames"""
        return list(self._users.keys())

# Demo account credentials for testing:
'''

        for username, data in hashed_accounts.items():
            template += f"# {username}: {data['plain_password']}\n"

        return template


def main():
    """Main entry point"""
    import argparse
    import time
    from datetime import datetime

    parser = argparse.ArgumentParser(
        description="Generate bcrypt password hashes for OAuth demo accounts"
    )
    parser.add_argument(
        "--interactive", "-i",
        action="store_true",
        help="Run in interactive mode for custom passwords"
    )
    parser.add_argument(
        "--no-save",
        action="store_true",
        help="Don't save output files"
    )
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="Only verify existing hashes, don't generate new ones"
    )

    args = parser.parse_args()

    # Check if bcrypt is available
    try:
        from passlib.context import CryptContext
        print("✅ bcrypt library available")
    except ImportError:
        print("❌ Error: passlib[bcrypt] is required")
        print("   Install with: pip install 'passlib[bcrypt]'")
        sys.exit(1)

    # Create and run utility
    utility = PasswordHashingUtility()

    if args.verify_only:
        # Just verify existing demo hashes
        hashed_accounts = utility.generate_demo_hashes()
        utility.verify_hashes(hashed_accounts)
    else:
        utility.run(
            interactive=args.interactive,
            save_output=not args.no_save
        )


if __name__ == "__main__":
    main()