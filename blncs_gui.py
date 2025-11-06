#!/usr/bin/env python3
"""
BLNCS GUI Launcher with Atlassian-inspired design.

This script provides a modern command-line interface for launching the
professional BLNCS dashboard with proper configuration and error handling.
"""

import argparse
import logging
import os
import sys
from typing import Optional

# Add blncs package to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from blncs.gui.dashboard_gui import create_dashboard_gui, DashboardGUI


def setup_logging(verbose: bool = False) -> None:
    """Configure logging for the GUI launcher."""
    log_level = logging.DEBUG if verbose else logging.INFO

    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler('blncs_gui.log', mode='a')
        ]
    )

    # Suppress noisy third-party logs unless verbose
    if not verbose:
        logging.getLogger('urllib3').setLevel(logging.WARNING)
        logging.getLogger('requests').setLevel(logging.WARNING)
        logging.getLogger('websocket').setLevel(logging.WARNING)


def print_banner() -> None:
    """Print a modern startup banner."""
    print("🚀 BLNCS Dashboard")
    print("Bitcoin Lightning Network Control System")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print()


def print_http_config(base_url: str, poll_interval: int) -> None:
    """Print HTTP configuration summary."""
    print("📡 Network Configuration:")
    print(f"   API Server: {base_url}")
    print(f"   Poll Interval: {poll_interval}s")
    print()


def print_ws_config(base_url: str) -> None:
    """Print WebSocket configuration summary."""
    try:
        # Import here to avoid issues if websocket not available
        from blncs.gui.net_utils import network_utils

        ws_url = network_utils.build_ws_url(base_url)
        print("🔗 WebSocket Configuration:")
        print(f"   WebSocket URL: {ws_url}")
        print()

    except Exception as e:
        print(f"⚠️  WebSocket configuration unavailable: {e}")
        print()


def check_dependencies() -> bool:
    """Check for required dependencies."""
    missing_deps = []

    try:
        import tkinter
    except ImportError:
        missing_deps.append('tkinter')

    try:
        import requests
    except ImportError:
        missing_deps.append('requests')

    if missing_deps:
        print("❌ Missing required dependencies:")
        for dep in missing_deps:
            print(f"   • {dep}")
        print()
        print("Please install missing dependencies:")
        print(f"   pip install {' '.join(missing_deps)}")
        return False

    return True


def test_connectivity(base_url: str, timeout: int = 5) -> bool:
    """Test connectivity to the API server."""
    try:
        from blncs.gui.net_utils import network_utils

        success, message = network_utils.test_connectivity(base_url, timeout)
        if success:
            print(f"✅ API connectivity verified: {message}")
            return True
        else:
            print(f"❌ API connectivity failed: {message}")
            return False

    except Exception as e:
        print(f"❌ Connectivity test failed: {e}")
        return False


def run_gui(base_url: str, poll_interval: int, verbose: bool, no_test: bool) -> int:
    """
    Run the BLNCS GUI application.

    Returns:
        Exit code (0 for success, 1 for error)
    """
    try:
        # Setup logging
        setup_logging(verbose)

        # Print banner
        print_banner()

        # Check dependencies
        if not check_dependencies():
            return 1

        # Test connectivity if requested
        if not no_test:
            print("🔍 Testing connectivity...")
            if not test_connectivity(base_url):
                print()
                print("💡 Troubleshooting tips:")
                print("   • Ensure BLNCS API server is running")
                print("   • Check firewall and network configuration")
                print("   • Verify the server URL is correct")
                print("   • Use --no-test to skip connectivity check")
                return 1

        # Print configuration
        print_http_config(base_url, poll_interval)
        print_ws_config(base_url)

        print("🎨 Starting modern GUI with Atlassian design...")
        print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        print()

        # Create and start GUI
        gui = create_dashboard_gui(base_url)

        # Override poll interval if specified
        gui.poll_interval = poll_interval

        # Start the GUI (this blocks until window is closed)
        gui.start()

        print()
        print("✅ GUI session completed successfully")
        return 0

    except KeyboardInterrupt:
        print()
        print("⏹️  GUI interrupted by user")
        return 0

    except Exception as e:
        print(f"❌ GUI failed to start: {e}")
        if verbose:
            import traceback
            traceback.print_exc()
        return 1


def main() -> int:
    """Main entry point for the GUI launcher."""
    parser = argparse.ArgumentParser(
        description="Launch BLNCS Dashboard GUI with modern Atlassian design",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                                    # Launch with defaults
  %(prog)s --url http://localhost:8080       # Custom API server
  %(prog)s --poll-interval 60               # Poll every 60 seconds
  %(prog)s --no-test                        # Skip connectivity test
  %(prog)s --verbose                        # Enable debug logging
  %(prog)s --print-config                   # Show configuration only
        """
    )

    # Core options
    parser.add_argument(
        '--url',
        default='http://localhost:5000',
        help='BLNCS API server URL (default: http://localhost:5000)'
    )

    parser.add_argument(
        '--poll-interval',
        type=int,
        default=30,
        help='Dashboard polling interval in seconds (default: 30)'
    )

    # Configuration and debugging
    parser.add_argument(
        '--print-config',
        action='store_true',
        help='Print configuration summary and exit'
    )

    parser.add_argument(
        '--print-ws-config',
        action='store_true',
        help='Print WebSocket configuration and exit'
    )

    parser.add_argument(
        '--no-test',
        action='store_true',
        help='Skip API connectivity test on startup'
    )

    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose logging for debugging'
    )

    # Proxy and network options (matching existing patterns)
    parser.add_argument(
        '--no-proxy',
        action='store_true',
        help='Disable proxy usage completely'
    )

    parser.add_argument(
        '--no-trust-env',
        action='store_true',
        help='Ignore proxy environment variables'
    )

    args = parser.parse_args()

    # Handle special modes
    if args.print_config:
        print_banner()
        print_http_config(args.url, args.poll_interval)
        return 0

    if args.print_ws_config:
        print_banner()
        print_ws_config(args.url)
        return 0

    # Set environment variables for proxy control
    if args.no_proxy:
        os.environ['BLNCS_GUI_NO_PROXY'] = '1'

    if args.no_trust_env:
        os.environ['BLNCS_GUI_NO_TRUST_ENV'] = '1'

    # Run the GUI
    return run_gui(
        base_url=args.url,
        poll_interval=args.poll_interval,
        verbose=args.verbose,
        no_test=args.no_test
    )


if __name__ == '__main__':
    exit_code = main()
    sys.exit(exit_code)
