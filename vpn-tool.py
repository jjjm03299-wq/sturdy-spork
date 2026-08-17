#!/usr/bin/env python3

import argparse
import getpass
import hashlib
import os
import secrets
import sys

import requests


VERSION = "1.0.0"

BASE_URL = (
    "https://vpn-gateway-manager--jjajajjajahsh.replit.app/api"
)

CONFIG_DIR = os.path.expanduser("~/.vpn-tool")
PIN_FILE = os.path.join(CONFIG_DIR, "pin.sha256")


# ============================================================
# API
# ============================================================

def api_request(method, endpoint, params=None):
    url = BASE_URL.rstrip("/") + endpoint

    print()
    print(f"{method} {url}")

    if params:
        print("Parameters:", params)

    print("-" * 50)

    try:
        response = requests.request(
            method=method,
            url=url,
            params=params,
            timeout=60,
        )

        print(f"HTTP {response.status_code}")

        try:
            print(response.json())
        except ValueError:
            print(response.text)

        return 0 if response.ok else 1

    except requests.exceptions.Timeout:
        print("Error: request timed out.", file=sys.stderr)
        return 1

    except requests.exceptions.ConnectionError as error:
        print(
            f"Error: connection failed: {error}",
            file=sys.stderr,
        )
        return 1

    except requests.exceptions.RequestException as error:
        print(
            f"Error: {error}",
            file=sys.stderr,
        )
        return 1


# ============================================================
# PIN
# ============================================================

def hash_pin(pin):
    return hashlib.sha256(
        pin.encode("utf-8")
    ).hexdigest()


def create_config_dir():
    os.makedirs(
        CONFIG_DIR,
        mode=0o700,
        exist_ok=True,
    )


def register_pin():
    create_config_dir()

    if os.path.exists(PIN_FILE):
        print("A PIN is already registered.")
        print("Use: vpn-tool auth reset")
        return 1

    pin = getpass.getpass(
        "Enter new PIN: "
    )

    confirm = getpass.getpass(
        "Confirm new PIN: "
    )

    if not pin:
        print("PIN cannot be empty.")
        return 1

    if pin != confirm:
        print("PINs do not match.")
        return 1

    with open(
        PIN_FILE,
        "w",
        encoding="utf-8",
    ) as file:
        file.write(hash_pin(pin))

    os.chmod(PIN_FILE, 0o600)

    print("PIN registered successfully.")

    return 0


def verify_pin(prompt="Enter PIN: "):
    if not os.path.exists(PIN_FILE):
        print("No PIN is registered.")
        print("Run: vpn-tool auth register")
        return False

    pin = getpass.getpass(prompt)

    with open(
        PIN_FILE,
        "r",
        encoding="utf-8",
    ) as file:
        stored = file.read().strip()

    return secrets.compare_digest(
        hash_pin(pin),
        stored,
    )


def login():
    if verify_pin():
        print("Login successful.")
        return 0

    print("Invalid PIN.", file=sys.stderr)
    return 1


def logout():
    if verify_pin("Enter PIN to logout: "):
        print("Logout successful.")
        return 0

    print("Invalid PIN.", file=sys.stderr)
    return 1


def reset_pin():
    if not verify_pin("Enter PIN to reset: "):
        print("Invalid PIN.", file=sys.stderr)
        return 1

    new_pin = getpass.getpass(
        "Enter new PIN: "
    )

    confirm = getpass.getpass(
        "Confirm new PIN: "
    )

    if not new_pin:
        print("PIN cannot be empty.")
        return 1

    if new_pin != confirm:
        print("PINs do not match.")
        return 1

    create_config_dir()

    with open(
        PIN_FILE,
        "w",
        encoding="utf-8",
    ) as file:
        file.write(hash_pin(new_pin))

    os.chmod(PIN_FILE, 0o600)

    print("PIN reset successfully.")

    return 0


def remove_pin():
    if not verify_pin("Enter PIN to remove: "):
        print("Invalid PIN.", file=sys.stderr)
        return 1

    try:
        os.remove(PIN_FILE)
    except FileNotFoundError:
        pass

    print("PIN removed successfully.")

    return 0


def auth_help():
    print(
        """
Authentication commands:

  vpn-tool auth register
      Enter new PIN and confirm new PIN.

  vpn-tool auth login
      Enter PIN to login.

  vpn-tool auth logout
      Enter PIN to logout.

  vpn-tool auth reset
      Enter current PIN and then enter new PIN.

  vpn-tool auth remove
      Enter PIN to remove the local PIN.

  vpn-tool auth help
      Show authentication help.
"""
    )

    return 0


# ============================================================
# API command functions
# ============================================================

def command_healthz(args):
    return api_request(
        "GET",
        "/healthz",
    )


def command_countries(args):
    return api_request(
        "GET",
        "/vpn/countries",
    )


def command_create(args):
    return api_request(
        "POST",
        "/vpn/create",
        {
            "countryCode": args.country,
        },
    )


def command_connect(args):
    return api_request(
        "POST",
        "/vpn/connect",
        {
            "countryCode": args.country,
        },
    )


def command_disconnect(args):
    return api_request(
        "POST",
        "/vpn/disconnect",
        {
            "countryCode": args.country,
        },
    )


def command_status(args):
    return api_request(
        "GET",
        "/vpn/status",
        {
            "countryCode": args.country,
        },
    )


def command_test(args):
    return api_request(
        "GET",
        "/vpn/test/sleep",
        {
            "ms": args.ms,
        },
    )


def command_ip(args):
    return api_request(
        "POST",
        "/vpn/ip",
        {
            "countryCode": args.country,
            "count": args.count,
        },
    )


# ============================================================
# Argparse
# ============================================================

def build_parser():

    parser = argparse.ArgumentParser(
        prog="vpn-tool",
        description="VPN Gateway Manager CLI",
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"vpn-tool {VERSION}",
    )

    subparsers = parser.add_subparsers(
        dest="command",
    )

    # --------------------------------------------------------
    # auth
    # --------------------------------------------------------

    auth = subparsers.add_parser(
        "auth",
        help="Authentication commands",
    )

    auth_sub = auth.add_subparsers(
        dest="auth_command",
    )

    auth_sub.add_parser(
        "register",
        help="Register a new PIN",
    ).set_defaults(
        handler=lambda args: register_pin()
    )

    auth_sub.add_parser(
        "login",
        help="Login using PIN",
    ).set_defaults(
        handler=lambda args: login()
    )

    auth_sub.add_parser(
        "logout",
        help="Logout using PIN",
    ).set_defaults(
        handler=lambda args: logout()
    )

    auth_sub.add_parser(
        "reset",
        help="Reset PIN",
    ).set_defaults(
        handler=lambda args: reset_pin()
    )

    auth_sub.add_parser(
        "remove",
        help="Remove PIN",
    ).set_defaults(
        handler=lambda args: remove_pin()
    )

    auth_sub.add_parser(
        "help",
        help="Authentication help",
    ).set_defaults(
        handler=lambda args: auth_help()
    )

    # --------------------------------------------------------
    # healthz
    # --------------------------------------------------------

    subparsers.add_parser(
        "healthz",
        help="GET /api/healthz",
    ).set_defaults(
        handler=command_healthz
    )

    # --------------------------------------------------------
    # countries
    # --------------------------------------------------------

    subparsers.add_parser(
        "countries",
        help="GET /api/vpn/countries",
    ).set_defaults(
        handler=command_countries
    )

    # --------------------------------------------------------
    # create
    # --------------------------------------------------------

    create = subparsers.add_parser(
        "create",
        help="POST /api/vpn/create",
    )

    create.add_argument(
        "--country",
        required=True,
        help="Country code, e.g. US",
    )

    create.set_defaults(
        handler=command_create
    )

    # --------------------------------------------------------
    # connect
    # --------------------------------------------------------

    connect = subparsers.add_parser(
        "connect",
        help="POST /api/vpn/connect",
    )

    connect.add_argument(
        "--country",
        required=True,
        help="Country code, e.g. US",
    )

    connect.set_defaults(
        handler=command_connect
    )

    # --------------------------------------------------------
    # disconnect
    # --------------------------------------------------------

    disconnect = subparsers.add_parser(
        "disconnect",
        help="POST /api/vpn/disconnect",
    )

    disconnect.add_argument(
        "--country",
        required=True,
        help="Country code, e.g. US",
    )

    disconnect.set_defaults(
        handler=command_disconnect
    )

    # --------------------------------------------------------
    # status
    # --------------------------------------------------------

    status = subparsers.add_parser(
        "status",
        help="GET /api/vpn/status",
    )

    status.add_argument(
        "--country",
        required=True,
        help="Country code, e.g. US",
    )

    status.set_defaults(
        handler=command_status
    )

    # --------------------------------------------------------
    # test
    # --------------------------------------------------------

    test = subparsers.add_parser(
        "test",
        help="GET /api/vpn/test/sleep",
    )

    test.add_argument(
        "--ms",
        type=int,
        default=100,
        help="Milliseconds, default: 100",
    )

    test.set_defaults(
        handler=command_test
    )

    # --------------------------------------------------------
    # ip
    # --------------------------------------------------------

    ip = subparsers.add_parser(
        "ip",
        help="POST /api/vpn/ip",
    )

    ip.add_argument(
        "--country",
        required=True,
        help="Country code, e.g. US",
    )

    ip.add_argument(
        "--count",
        type=int,
        default=10,
        help="Number of IPs, default: 10",
    )

    ip.set_defaults(
        handler=command_ip
    )

    return parser


# ============================================================
# Main
# ============================================================

def main():

    parser = build_parser()

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 0

    # Auth commands do not require an existing PIN.
    if args.command == "auth":

        if not args.auth_command:
            return auth_help()

        return args.handler(args)

    # Protect VPN/API commands with the local PIN.
    if not verify_pin():
        print(
            "Authentication failed.",
            file=sys.stderr,
        )
        return 1

    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
