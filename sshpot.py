#!/usr/bin/env python3
"""
SSHPot - SSH Honeypot
Emulates an SSH server to capture attacker credentials, behavior, and
commands. Logs all activity to JSON for analysis and threat intelligence.
"""

import argparse
import base64
import json
import logging
import os
import socket
import sys
import threading
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

try:
    import paramiko
except ImportError:
    print("[!] Missing dependency: pip install paramiko")
    sys.exit(1)


LOG_FILE = "sshpot.json"
KEY_FILE = "sshpot_host.key"

logging.getLogger("paramiko").setLevel(logging.CRITICAL)

sessions = []
sessions_lock = threading.Lock()


# ── RSA Host Key ──────────────────────────────────────────────────────────────

def get_host_key(key_path):
    if os.path.exists(key_path):
        return paramiko.RSAKey(filename=key_path)
    print(f"  [*] Generating RSA host key → {key_path}")
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(key_path)
    return key


# ── Fake SSH Server Interface ─────────────────────────────────────────────────

class HoneypotServer(paramiko.ServerInterface):
    def __init__(self, client_ip, client_port, log_path):
        self.client_ip   = client_ip
        self.client_port = client_port
        self.log_path    = log_path
        self.username    = None
        self.event       = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "src_ip":    self.client_ip,
            "src_port":  self.client_port,
            "username":  username,
            "password":  password,
            "auth_type": "password",
        }
        self._log(entry)
        self.username = username
        # Always deny — we're a honeypot
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        key_b64 = base64.b64encode(key.asbytes()).decode()
        entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "src_ip":    self.client_ip,
            "src_port":  self.client_port,
            "username":  username,
            "pubkey":    key_b64[:64] + "...",
            "key_type":  key.get_name(),
            "auth_type": "publickey",
        }
        self._log(entry)
        return paramiko.AUTH_FAILED

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_exec_request(self, channel, command):
        cmd = command.decode("utf-8", errors="replace")
        entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "src_ip":    self.client_ip,
            "src_port":  self.client_port,
            "username":  self.username or "unknown",
            "command":   cmd,
            "auth_type": "exec",
        }
        self._log(entry)
        return True

    def get_allowed_auths(self, username):
        return "password,publickey"

    def _log(self, entry):
        with sessions_lock:
            sessions.append(entry)
            with open(self.log_path, "a") as f:
                f.write(json.dumps(entry) + "\n")
        ts = entry["timestamp"][11:19]
        ip = entry["src_ip"]
        user = entry.get("username", "")
        pw   = entry.get("password", "")
        if pw:
            print(f"  [{ts}] {ip:<18} user={user:<20} pass={pw}")
        else:
            print(f"  [{ts}] {ip:<18} user={user:<20} pubkey auth attempt")


# ── Connection Handler ────────────────────────────────────────────────────────

def handle_client(client_sock, client_addr, host_key, log_path):
    ip, port = client_addr
    transport = None
    try:
        transport = paramiko.Transport(client_sock)
        transport.local_version = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
        transport.add_server_key(host_key)

        server = HoneypotServer(ip, port, log_path)
        transport.start_server(server=server)

        # Keep alive briefly to capture more auth attempts
        chan = transport.accept(20)
        if chan:
            chan.close()

    except (paramiko.SSHException, EOFError, ConnectionResetError):
        pass
    except Exception:
        pass
    finally:
        if transport:
            try:
                transport.close()
            except Exception:
                pass
        try:
            client_sock.close()
        except Exception:
            pass


# ── Honeypot Server ───────────────────────────────────────────────────────────

def run_honeypot(host, port, log_path, key_path):
    host_key = get_host_key(key_path)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((host, port))
    except PermissionError:
        print(f"[!] Permission denied binding to port {port}.")
        print(f"    Try a port above 1024, or run with sudo.")
        sys.exit(1)
    except OSError as e:
        print(f"[!] Cannot bind to {host}:{port} — {e}")
        sys.exit(1)

    sock.listen(100)
    print(f"  Listening on {host}:{port}")
    print(f"  Logging to   {log_path}")
    print(f"  Press Ctrl+C to stop\n")
    print(f"  {'TIME':<10} {'SRC IP':<18} {'CREDENTIALS'}")
    print(f"  {'-'*10} {'-'*18} {'-'*40}")

    try:
        while True:
            try:
                client_sock, client_addr = sock.accept()
                t = threading.Thread(
                    target=handle_client,
                    args=(client_sock, client_addr, host_key, log_path),
                    daemon=True,
                )
                t.start()
            except KeyboardInterrupt:
                raise
            except Exception:
                pass
    except KeyboardInterrupt:
        print(f"\n\n  Honeypot stopped. {len(sessions)} attempt(s) captured.")
        print(f"  Run 'python sshpot.py report' to analyze.\n")
    finally:
        sock.close()


# ── Report / Analysis ─────────────────────────────────────────────────────────

def load_log(log_path):
    if not os.path.exists(log_path):
        print(f"[!] No log file found at {log_path}")
        print(f"    Run the honeypot first: python sshpot.py listen")
        sys.exit(1)
    entries = []
    with open(log_path) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return entries


def generate_report(log_path, top_n=10):
    entries = load_log(log_path)
    if not entries:
        print("  No entries in log.")
        return

    pw_entries  = [e for e in entries if e.get("auth_type") == "password"]
    key_entries = [e for e in entries if e.get("auth_type") == "publickey"]
    cmd_entries = [e for e in entries if e.get("auth_type") == "exec"]

    ips       = Counter(e["src_ip"] for e in entries)
    usernames = Counter(e.get("username", "") for e in pw_entries)
    passwords = Counter(e.get("password", "") for e in pw_entries)
    combos    = Counter(
        f"{e.get('username','')}:{e.get('password','')}" for e in pw_entries
    )

    # Timeline — attempts per hour
    hourly = defaultdict(int)
    for e in entries:
        try:
            hour = e["timestamp"][:13]
            hourly[hour] += 1
        except Exception:
            pass

    print("\n" + "=" * 60)
    print("  SSHPOT THREAT INTELLIGENCE REPORT")
    print("=" * 60)
    print(f"  Log file       : {log_path}")
    print(f"  Total attempts : {len(entries)}")
    print(f"  Password auth  : {len(pw_entries)}")
    print(f"  Pubkey auth    : {len(key_entries)}")
    print(f"  Command exec   : {len(cmd_entries)}")
    print(f"  Unique IPs     : {len(ips)}")
    print(f"  Unique users   : {len(usernames)}")
    print(f"  Unique passwords: {len(passwords)}")

    print(f"\n  TOP {top_n} SOURCE IPs:")
    for ip, count in ips.most_common(top_n):
        bar = "█" * min(count, 40)
        print(f"    {ip:<20} {count:>5}  {bar}")

    print(f"\n  TOP {top_n} USERNAMES:")
    for user, count in usernames.most_common(top_n):
        print(f"    {user:<30} {count:>5}")

    print(f"\n  TOP {top_n} PASSWORDS:")
    for pw, count in passwords.most_common(top_n):
        display = pw[:40] + "..." if len(pw) > 40 else pw
        print(f"    {display:<43} {count:>5}")

    print(f"\n  TOP {top_n} CREDENTIAL COMBOS:")
    for combo, count in combos.most_common(top_n):
        display = combo[:50] + "..." if len(combo) > 50 else combo
        print(f"    {display:<53} {count:>5}")

    if cmd_entries:
        print(f"\n  COMMANDS ATTEMPTED:")
        for e in cmd_entries[:20]:
            print(f"    [{e['timestamp'][11:19]}] {e['src_ip']:<18} $ {e.get('command','')[:60]}")

    if hourly:
        print(f"\n  ACTIVITY TIMELINE (hourly):")
        for hour in sorted(hourly)[-24:]:
            count = hourly[hour]
            bar   = "█" * min(count // max(1, max(hourly.values()) // 30), 30)
            print(f"    {hour}  {count:>5}  {bar}")

    print("\n" + "=" * 60)


def export_iocs(log_path, output_path):
    """Export attacker IPs as a simple IOC list."""
    entries = load_log(log_path)
    ips = sorted(set(e["src_ip"] for e in entries))
    with open(output_path, "w") as f:
        f.write(f"# SSHPot IOC Export — {datetime.utcnow().isoformat()}Z\n")
        f.write(f"# {len(ips)} unique attacker IP(s)\n\n")
        for ip in ips:
            f.write(ip + "\n")
    print(f"  [+] {len(ips)} attacker IP(s) exported → {output_path}")


# ── CLI ───────────────────────────────────────────────────────────────────────

def print_banner():
    print("""
  ____  ____  _   _ ____        _
 / ___||  _ \\| | | |  _ \\ ___ | |_
 \\___ \\| |_) | |_| | |_) / _ \\| __|
  ___) |  __/|  _  |  __/ (_) | |_
 |____/|_|   |_| |_|_|   \\___/ \\__|

  SSH Honeypot & Threat Intelligence Tool  |  github.com
""")


def main():
    parser = argparse.ArgumentParser(
        description="SSHPot - SSH honeypot with threat intelligence reporting",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  listen    Start the SSH honeypot
  report    Analyze captured credentials and generate a report
  export    Export attacker IPs as an IOC list

Examples:
  python sshpot.py listen
  python sshpot.py listen --port 2222 --host 0.0.0.0
  python sshpot.py report
  python sshpot.py report --top 20
  python sshpot.py export --output attacker_ips.txt
        """
    )
    parser.add_argument("command", choices=["listen", "report", "export"])
    parser.add_argument("--host",    default="0.0.0.0",   help="Bind address (default: 0.0.0.0)")
    parser.add_argument("--port",    type=int, default=22, help="Listen port (default: 22, use 2222 without root)")
    parser.add_argument("--log",     default=LOG_FILE,     help=f"Log file path (default: {LOG_FILE})")
    parser.add_argument("--key",     default=KEY_FILE,     help=f"Host key path (default: {KEY_FILE})")
    parser.add_argument("--top",     type=int, default=10, help="Top N results in report (default: 10)")
    parser.add_argument("--output",  default="iocs.txt",   help="IOC export output file (default: iocs.txt)")
    args = parser.parse_args()

    print_banner()

    if args.command == "listen":
        print(f"  Starting SSH honeypot...")
        run_honeypot(args.host, args.port, args.log, args.key)

    elif args.command == "report":
        generate_report(args.log, args.top)

    elif args.command == "export":
        export_iocs(args.log, args.output)


if __name__ == "__main__":
    main()
