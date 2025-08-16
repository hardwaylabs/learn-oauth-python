#!/usr/bin/env python3
"""
Multi-Server Startup Script for OAuth 2.1 Learning System

This script launches all three OAuth servers (client, authorization server, resource server)
with proper process management, health checks, and graceful shutdown handling.
"""

import subprocess
import sys
import time
import signal
import os
import httpx
from pathlib import Path
from typing import List, Dict, Optional
import threading
from datetime import datetime

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from src.shared.logging_utils import OAuthLogger

class ServerManager:
    """Manages multiple OAuth servers with health checks and graceful shutdown"""

    def __init__(self):
        self.logger = OAuthLogger("SYSTEM")
        self.processes: List[subprocess.Popen] = []
        self.servers = [
            {
                "name": "Authorization Server",
                "module": "src.auth_server.main:app",
                "port": 8081,
                "health_url": "http://localhost:8081/health",
                "process": None
            },
            {
                "name": "Resource Server",
                "module": "src.resource_server.main:app",
                "port": 8082,
                "health_url": "http://localhost:8082/health",
                "process": None
            },
            {
                "name": "Client Application",
                "module": "src.client.main:app",
                "port": 8080,
                "health_url": "http://localhost:8080/health",
                "process": None
            }
        ]
        self.shutdown_requested = False

        # Register signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully"""
        self.logger.log_oauth_message(
            "SYSTEM", "SYSTEM",
            "Shutdown Signal Received",
            {
                "signal": signum,
                "timestamp": datetime.now().isoformat(),
                "active_servers": len([s for s in self.servers if s["process"]])
            }
        )
        self.shutdown_requested = True
        self.stop_all_servers()
        sys.exit(0)

    def check_port_available(self, port: int) -> bool:
        """Check if a port is available for use"""
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            result = sock.connect_ex(('localhost', port))
            return result != 0

    def wait_for_health_check(self, server: Dict, timeout: int = 30) -> bool:
        """Wait for server to respond to health checks"""
        start_time = time.time()

        while time.time() - start_time < timeout:
            try:
                with httpx.Client() as client:
                    response = client.get(server["health_url"], timeout=2)
                if response.status_code == 200:
                    self.logger.log_oauth_message(
                        "SYSTEM", server["name"].upper().replace(" ", "-"),
                        "Health Check Passed",
                        {
                            "url": server["health_url"],
                            "status_code": response.status_code,
                            "response_time": f"{time.time() - start_time:.2f}s"
                        }
                    )
                    return True
            except (httpx.RequestError, httpx.HTTPStatusError):
                pass

            time.sleep(1)

        return False

    def start_server(self, server: Dict) -> bool:
        """Start a single server with uvicorn"""

        # Check if port is available
        if not self.check_port_available(server["port"]):
            self.logger.log_oauth_message(
                "SYSTEM", "SYSTEM",
                "Port Already In Use",
                {
                    "server": server["name"],
                    "port": server["port"],
                    "error": f"Port {server['port']} is already in use"
                }
            )
            return False

        self.logger.log_oauth_message(
            "SYSTEM", server["name"].upper().replace(" ", "-"),
            "Starting Server",
            {
                "module": server["module"],
                "port": server["port"],
                "health_url": server["health_url"]
            }
        )

        try:
            # Start server process
            process = subprocess.Popen([
                sys.executable, "-m", "uvicorn",
                server["module"],
                "--host", "0.0.0.0",
                "--port", str(server["port"]),
                "--reload",
                "--log-level", "info"
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
            )

            server["process"] = process
            self.processes.append(process)

            # Wait for server to start and pass health check
            if self.wait_for_health_check(server):
                self.logger.log_oauth_message(
                    "SYSTEM", server["name"].upper().replace(" ", "-"),
                    "Server Started Successfully",
                    {
                        "pid": process.pid,
                        "port": server["port"],
                        "status": "healthy"
                    }
                )
                return True
            else:
                self.logger.log_oauth_message(
                    "SYSTEM", server["name"].upper().replace(" ", "-"),
                    "Server Health Check Failed",
                    {
                        "port": server["port"],
                        "timeout": "30s",
                        "status": "unhealthy"
                    }
                )
                process.terminate()
                return False

        except Exception as e:
            self.logger.log_oauth_message(
                "SYSTEM", "SYSTEM",
                "Server Start Failed",
                {
                    "server": server["name"],
                    "error": str(e),
                    "port": server["port"]
                }
            )
            return False

    def start_all_servers(self) -> bool:
        """Start all servers in the correct order with staggered startup"""

        self.logger.log_oauth_message(
            "SYSTEM", "SYSTEM",
            "OAuth System Startup Initiated",
            {
                "servers_to_start": len(self.servers),
                "startup_order": [s["name"] for s in self.servers],
                "timestamp": datetime.now().isoformat()
            }
        )

        print("\n" + "="*60)
        print("🚀 OAuth 2.1 Learning System - Multi-Server Startup")
        print("="*60)
        print()

        # Start servers in order (auth server first, then resource server, then client)
        for i, server in enumerate(self.servers):
            if self.shutdown_requested:
                break

            print(f"📡 Starting {server['name']} on port {server['port']}...")

            if self.start_server(server):
                print(f"✅ {server['name']} started successfully")

                # Stagger startup to avoid port conflicts and dependency issues
                if i < len(self.servers) - 1:
                    print(f"⏳ Waiting 3 seconds before starting next server...")
                    time.sleep(3)
            else:
                print(f"❌ Failed to start {server['name']}")
                print(f"🛑 Stopping startup process due to failure")
                self.stop_all_servers()
                return False

        if not self.shutdown_requested:
            print()
            print("🎉 All servers started successfully!")
            print()
            print("📋 Server Status:")
            print("-" * 40)
            for server in self.servers:
                if server["process"]:
                    print(f"  {server['name']}: http://localhost:{server['port']}")
            print()
            print("🌐 Ready to use:")
            print(f"  • Visit http://localhost:8080 to start the OAuth flow")
            print(f"  • Authorization Server: http://localhost:8081")
            print(f"  • Resource Server: http://localhost:8082")
            print()
            print("📚 Educational Features:")
            print("  • Detailed console logging of OAuth message flows")
            print("  • PKCE (Proof Key for Code Exchange) implementation")
            print("  • Step-by-step OAuth 2.1 flow demonstration")
            print("  • Pre-configured demo accounts (alice, bob, carol)")
            print()
            print("🔧 Demo Accounts:")
            print("  • alice / password123")
            print("  • bob / secret456")
            print("  • carol / mypass789")
            print()
            print("⚠️  Press Ctrl+C to stop all servers")
            print("="*60)

            return True

        return False

    def stop_all_servers(self):
        """Stop all running servers gracefully"""

        if not self.processes:
            return

        self.logger.log_oauth_message(
            "SYSTEM", "SYSTEM",
            "Shutdown Initiated",
            {
                "active_processes": len(self.processes),
                "timestamp": datetime.now().isoformat()
            }
        )

        print("\n🛑 Stopping all servers...")

        # Send SIGTERM to all processes
        for i, process in enumerate(self.processes):
            if process and process.poll() is None:
                server_name = self.servers[i]["name"] if i < len(self.servers) else f"Process {i}"
                print(f"  🔄 Stopping {server_name}...")

                try:
                    process.terminate()

                    # Wait up to 5 seconds for graceful shutdown
                    try:
                        process.wait(timeout=5)
                        print(f"  ✅ {server_name} stopped gracefully")
                    except subprocess.TimeoutExpired:
                        print(f"  ⚠️  Force killing {server_name}...")
                        process.kill()
                        process.wait()
                        print(f"  ✅ {server_name} force stopped")

                except Exception as e:
                    print(f"  ❌ Error stopping {server_name}: {e}")

        self.processes.clear()
        for server in self.servers:
            server["process"] = None

        print("✅ All servers stopped")

        self.logger.log_oauth_message(
            "SYSTEM", "SYSTEM",
            "Shutdown Complete",
            {
                "timestamp": datetime.now().isoformat(),
                "status": "clean_shutdown"
            }
        )

    def monitor_servers(self):
        """Monitor server processes and restart if needed"""
        while not self.shutdown_requested:
            time.sleep(10)  # Check every 10 seconds

            for server in self.servers:
                if server["process"] and server["process"].poll() is not None:
                    # Process has died
                    self.logger.log_oauth_message(
                        "SYSTEM", server["name"].upper().replace(" ", "-"),
                        "Server Process Died",
                        {
                            "exit_code": server["process"].returncode,
                            "restart_attempt": True
                        }
                    )

                    print(f"⚠️  {server['name']} has stopped unexpectedly. Restarting...")

                    # Remove from processes list
                    if server["process"] in self.processes:
                        self.processes.remove(server["process"])

                    # Restart server
                    if self.start_server(server):
                        print(f"✅ {server['name']} restarted successfully")
                    else:
                        print(f"❌ Failed to restart {server['name']}")

    def run(self):
        """Main run method"""
        try:
            if self.start_all_servers():
                # Start monitoring thread
                monitor_thread = threading.Thread(target=self.monitor_servers, daemon=True)
                monitor_thread.start()

                # Keep main thread alive
                while not self.shutdown_requested:
                    time.sleep(1)
            else:
                print("❌ Failed to start OAuth system")
                sys.exit(1)

        except KeyboardInterrupt:
            pass  # Handled by signal handler
        except Exception as e:
            self.logger.log_oauth_message(
                "SYSTEM", "SYSTEM",
                "Unexpected Error",
                {
                    "error": str(e),
                    "timestamp": datetime.now().isoformat()
                }
            )
            print(f"❌ Unexpected error: {e}")
        finally:
            self.stop_all_servers()


def main():
    """Main entry point"""

    # Check if we're in the right directory
    if not Path("src").exists():
        print("❌ Error: This script must be run from the project root directory")
        print("   Current directory should contain 'src/' folder")
        sys.exit(1)

    # Check Python version
    if sys.version_info < (3, 8):
        print("❌ Error: Python 3.8 or higher is required")
        sys.exit(1)

    # Check if required modules are available
    try:
        import uvicorn
        import fastapi
        import requests
    except ImportError as e:
        print(f"❌ Error: Missing required dependency: {e}")
        print("   Please install dependencies with: pip install -r requirements.txt")
        sys.exit(1)

    print("🔍 Pre-flight checks passed")

    # Create and run server manager
    manager = ServerManager()
    manager.run()


if __name__ == "__main__":
    main()