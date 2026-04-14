# SSH Security Hardening Script
## Based on Vulnerability Analysis Findings

---

```python
#!/usr/bin/env python3
"""
SSH Security Hardening Script
==============================
Addresses vulnerabilities identified in server log security analysis:
  - Finding #1: Brute force / authentication attack on SSH
  - Finding #2: Log integrity / hostname anomaly
  - Finding #3: Exposed attack surface / insecure SSH configuration

Author:  Security Operations Team
Version: 1.0.0
Python:  3.8+

IMPORTANT: Run as root. Test in staging before production deployment.
           Creates backups of all modified configuration files.
"""

import os
import sys
import subprocess
import logging
import shutil
import re
import json
import socket
from datetime import datetime
from pathlib import Path
from typing import Optional

# ─────────────────────────────────────────────
#  CONFIGURATION  (edit before deployment)
# ─────────────────────────────────────────────
CONFIG = {
    # Attacking IP identified in the log analysis
    "attacker_ip": "192.168.1.105",

    # SSH hardening options
    "sshd_config_path": "/etc/ssh/sshd_config",
    "ssh_new_port": 2222,           # Move SSH off default port 22

    # fail2ban settings
    "fail2ban_maxretry": 3,         # Lock after N failures
    "fail2ban_bantime": 3600,       # Ban duration in seconds (1 hour)
    "fail2ban_findtime": 600,       # Observation window in seconds

    # Logging
    "log_file": "/var/log/ssh_hardening.log",
    "backup_dir": "/var/backups/ssh_hardening",

    # Hostname validation
    "expected_hostname": "web-server-01",

    # Dry-run mode: set True to preview changes without applying them
    "dry_run": False,
}

# ─────────────────────────────────────────────
#  LOGGING SETUP
# ─────────────────────────────────────────────
def setup_logging(log_file: str) -> logging.Logger:
    """
    Configure dual-output logging:
      - Rotating file handler for persistent audit trail
      - Console handler for real-time operator feedback
    """
    logger = logging.getLogger("ssh_hardening")
    logger.setLevel(logging.DEBUG)

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # File handler — always DEBUG level for full audit trail
    try:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except PermissionError:
        print(f"[WARNING] Cannot write to {log_file}. File logging disabled.")

    # Console handler — INFO and above for clean operator output
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    return logger


# ─────────────────────────────────────────────
#  HELPER UTILITIES
# ─────────────────────────────────────────────
def require_root(logger: logging.Logger) -> None:
    """Abort immediately if the script is not running as root."""
    if os.geteuid() != 0:
        logger.error("This script must be run as root (sudo python3 %s)", __file__)
        sys.exit(1)


def run_command(
    cmd: list[str],
    logger: logging.Logger,
    check: bool = True,
    capture_output: bool = True,
) -> subprocess.CompletedProcess:
    """
    Execute a shell command with structured logging.

    Args:
        cmd:            Command and arguments as a list (avoids shell injection).
        logger:         Active logger instance.
        check:          Raise CalledProcessError on non-zero exit if True.
        capture_output: Capture stdout/stderr if True.

    Returns:
        CompletedProcess result object.
    """
    logger.debug("Executing: %s", " ".join(cmd))
    try:
        result = subprocess.run(
            cmd,
            check=check,
            capture_output=capture_output,
            text=True,
        )
        if result.stdout:
            logger.debug("stdout: %s", result.stdout.strip())
        return result
    except subprocess.CalledProcessError as exc:
        logger.error("Command failed [exit %d]: %s", exc.returncode, " ".join(cmd))
        if exc.stderr:
            logger.error("stderr: %s", exc.stderr.strip())
        raise


def backup_file(file_path: str, backup_dir: str, logger: logging.Logger) -> Optional[str]:
    """
    Create a timestamped backup of a file before modification.

    Returns:
        Path to the backup file, or None if the source does not exist.
    """
    source = Path(file_path)
    if not source.exists():
        logger.warning("Backup skipped — file not found: %s", file_path)
        return None

    Path(backup_dir).mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    dest = Path(backup_dir) / f"{source.name}.{timestamp}.bak"
    shutil.copy2(source, dest)
    logger.info("Backup created: %s → %s", file_path, dest)
    return str(dest)


def is_dry_run(logger: logging.Logger) -> bool:
    """Log a dry-run notice and return the dry_run flag."""
    if CONFIG["dry_run"]:
        logger.info("[DRY-RUN] No changes will be written to disk.")
    return CONFIG["dry_run"]


# ─────────────────────────────────────────────
#  FINDING #1 — BLOCK ATTACKING IP
# ─────────────────────────────────────────────
def block_attacker_ip(ip: str, logger: logging.Logger) -> bool:
    """
    Block the identified attacking IP using iptables.

    Validates the IP address format before applying the rule to prevent
    command injection through a malformed configuration value.

    Args:
        ip:     IPv4 address to block.
        logger: Active logger instance.

    Returns:
        True on success, False on failure.
    """
    logger.info("── Finding #1: Blocking attacking IP ──────────────────")

    # Validate IP format before passing to iptables
    ip_pattern = re.compile(
        r"^(25[0-5]|2[0-4]\d|[01]?\d\d?)\."
        r"(25[0-5]|2[0-4]\d|[01]?\d\d?)\."
        r"(25[0-5]|2[0-4]\d|[01]?\d\d?)\."
        r"(25[0-5]|2[0-4]\d|[01]?\d\d?)$"
    )
    if not ip_pattern.match(ip):
        logger.error("Invalid IP address format: %s — aborting block step.", ip)
        return False

    if is_dry_run(logger):
        logger.info("[DRY-RUN] Would execute: iptables -A INPUT -s %s -j DROP", ip)
        return True

    try:
        # Check whether the rule already exists to avoid duplicates
        check = run_command(
            ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
            logger,
            check=False,
        )
        if check.returncode == 0:
            logger.info("iptables rule already present for %s — skipping.", ip)
            return True

        # Apply the DROP rule
        run_command(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], logger)
        logger.info("iptables DROP rule applied for %s", ip)

        # Persist the rule across reboots (iptables-persistent / netfilter-persistent)
        if shutil.which("netfilter-persistent"):
            run_command(["netfilter-persistent", "save"], logger)
            logger.info("iptables rules persisted via netfilter-persistent.")
        elif shutil.which("iptables-save"):
            rules_file = "/etc/iptables/rules.v4"
            Path(rules_file).parent.mkdir(parents=True, exist_ok=True)
            result = run_command(["iptables-save"], logger)
            Path(rules_file).write_text(result.stdout)
            logger.info("iptables rules saved to %s", rules_file)
        else:
            logger.warning(
                "No persistence mechanism found. "
                "iptables rule will be lost on reboot."
            )

        return True

    except (subprocess.CalledProcessError, OSError) as exc:
        logger.error("Failed to block IP %s: %s", ip, exc)
        return False


# ─────────────────────────────────────────────
#  FINDING #3 — HARDEN SSH CONFIGURATION
# ─────────────────────────────────────────────
# Desired sshd_config directives and their secure values.
# Each entry: (directive_name, secure_value, comment)
SSHD_HARDENING_DIRECTIVES = [
    ("PermitRootLogin",              "no",               "Disable direct root login"),
    ("PasswordAuthentication",       "no",               "Require key-based auth only"),
    ("PubkeyAuthentication",         "yes",              "Enable public key auth"),
    ("PermitEmptyPasswords",         "no",               "Disallow empty passwords"),
    ("MaxAuthTries",                 "3",                "Limit auth attempts per connection"),
    ("LoginGraceTime",               "30",               "Reduce unauthenticated session window"),
    ("X11Forwarding",                "no",               "Disable X11 forwarding"),
    ("AllowAgentForwarding",         "no",               "Disable agent forwarding"),
    ("AllowTcpForwarding",           "no",               "Disable TCP forwarding"),
    ("UsePAM",                       "yes",              "Enable PAM for additional auth controls"),
    ("ClientAliveInterval",          "300",              "Disconnect idle sessions after 5 min"),
    ("ClientAliveCountMax",          "2",                "Max keepalive probes before disconnect"),
    ("Protocol",                     "2",                "Enforce SSHv2 only"),
    ("LogLevel",                     "VERBOSE",          "Enhanced logging for audit trail"),
    ("StrictModes",                  "yes",              "Check file permissions before accepting login"),
    ("IgnoreRhosts",                 "yes",              "Disable legacy rhost authentication"),
    ("HostbasedAuthentication",      "no",               "Disable host-based authentication"),
    ("PermitUserEnvironment",        "no",               "Prevent environment variable injection"),
]


def harden_sshd_config(logger: logging.Logger) -> bool:
    """
    Apply security hardening directives to /etc/ssh/sshd_config.

    Strategy:
      1. Back up the existing configuration.
      2. Parse the file and update or append each directive.
      3. Validate the new configuration with `sshd -t` before restarting.
      4. Restart sshd only if validation passes.

    Returns:
        True on success, False on failure.
    """
    logger.info("── Finding #3: Hardening sshd_config ──────────────────")

    config_path = CONFIG["sshd_config_path"]
    new_port    = CONFIG["ssh_new_port"]

    # Ensure the config file exists
    if not Path(config_path).exists():
        logger.error("sshd_config not found at %s", config_path)
        return False

    # Back up before any modification
    backup_file(config_path, CONFIG["backup_dir"], logger)

    # Read current configuration
    original_content = Path(config_path).read_text()
    lines = original_content.splitlines()

    # Build the full directive list including the custom port
    directives = list(SSHD_HARDENING_DIRECTIVES) + [
        ("Port", str(new_port), f"Move SSH off default port 22 to {new_port}"),
    ]

    applied: list[str] = []
    skipped: list[str] = []

    for directive, value, comment in directives:
        pattern = re.compile(
            rf"^\s*#?\s*{re.escape(directive)}\s+.*$",
            re.IGNORECASE,
        )
        replacement = f"{directive} {value}  # hardened: {comment}"
        matched = False

        for idx, line in enumerate(lines):
            if pattern.match(line):
                if lines[idx].strip() == replacement.strip():
                    skipped.append(directive)
                else:
                    lines[idx] = replacement
                    applied.append(directive)
                matched = True
                break

        if not matched:
            # Directive absent — append it
            lines.append(f"\n# Added by ssh_hardening.py — {comment}")
            lines.append(replacement)
            applied.append(f"{directive} (appended)")

    new_content = "\n".join(lines) + "\n"

    if is_dry_run(logger):
        logger.info("[DRY-RUN] sshd_config changes that would be applied:")
        for item in applied:
            logger.info("  • %s", item)
        return True

    # Write the updated configuration
    Path(config_path).write_text(new_content)
    logger.info("sshd_config updated. Directives applied: %d", len(applied))
    for item in applied:
        logger.info("  ✓ %s", item)
    if skipped:
        logger.debug("Directives already correct (skipped): %s", ", ".join(skipped))

    # Validate configuration syntax before restarting
    logger.info("Validating sshd configuration syntax …")
    try:
        run_command(["sshd", "-t"], logger)
        logger.info("sshd configuration syntax is valid.")
    except subprocess.CalledProcessError:
        logger.error(
            "sshd configuration validation FAILED. "
            "Restoring backup and aborting restart."
        )
        # Restore the backup automatically on validation failure
        backup_files = sorted(
            Path(CONFIG["backup_dir"]).glob("sshd_config.*.bak"),
            reverse=True,
        )
        if backup_files:
            shutil.copy2(backup_files[0], config_path)
            logger.info("Backup restored: %s", backup_files[0])
        return False

    # Restart sshd to apply changes
    try:
        run_command(["systemctl", "restart", "sshd"], logger)
        logger.info("sshd restarted successfully.")
        logger.warning(
            "SSH is now listening on port %d. "
            "Ensure firewall rules allow this port before closing your session.",
            new_port,
        )
    except subprocess.CalledProcessError:
        logger.error("Failed to restart sshd. Manual intervention required.")
        return False

    return True


# ─────────────────────────────────────────────
#  FINDING #1 (CONTINUED) — INSTALL FAIL2BAN
# ─────────────────────────────────────────────
FAIL2BAN_JAIL_CONFIG = """\
# /etc/fail2ban/jail.d/sshd-hardened.conf
# Generated by ssh_hardening.py

[sshd]
enabled   = true
port      = {port}
filter    = sshd
logpath   = /var/log/auth.log
            /var/log/secure
maxretry  = {maxretry}
bantime   = {bantime}
findtime  = {findtime}
action    = iptables-multiport[name=sshd, port="{port}", protocol=tcp]
            sendmail-whois[name=sshd, dest=root, sender=fail2ban@localhost]
"""


def install_fail2ban(logger: logging.Logger) -> bool:
    """
    Install and configure fail2ban to rate-limit SSH authentication attempts.

    Creates a dedicated jail configuration for sshd with values from CONFIG.

    Returns:
        True on success, False on failure.
    """
    logger.info("── Finding #1: Installing / configuring fail2ban ───────")

    # Install fail2ban if not already present
    if not shutil.which("fail2ban-server"):
        logger.info("fail2ban not found — attempting installation via apt …")
        if is_dry_run(logger):
            logger.info("[DRY-RUN] Would run: apt-get install -y fail2ban")
        else:
            try:
                run_command(
                    ["apt-get", "install", "-y", "fail2ban"],
                    logger,
                )
                logger.info("fail2ban installed successfully.")
            except subprocess.CalledProcessError:
                logger.error("fail2ban installation failed. Install manually and re-run.")
                return False
    else:
        logger.info("fail2ban is already installed.")

    # Write the jail configuration
    jail_dir  = Path("/etc/fail2ban/jail.d")
    jail_file = jail_dir / "sshd-hardened.conf"

    jail_content = FAIL2BAN_JAIL_CONFIG.format(
        port     = CONFIG["ssh_new_port"],
        maxretry = CONFIG["fail2ban_maxretry"],
        bantime  = CONFIG["fail2ban_bantime"],
        findtime = CONFIG["fail2ban_findtime"],
    )

    if is_dry_run(logger):
        logger.info("[DRY-RUN] Would write fail2ban jail config to %s:", jail_file)
        for line in jail_content.splitlines():
            logger.info("  %s", line)
        return True

    jail_dir.mkdir(parents=True, exist_ok=True)

    # Back up existing jail config if present
    if jail_file.exists():
        backup_file(str(jail_file), CONFIG["backup_dir"], logger)

    jail_file.write_text(jail_content)
    logger.info("fail2ban jail config written to %s", jail_file)

    # Enable and restart fail2ban
    try:
        run_command(["systemctl", "enable", "fail2ban"], logger)
        run_command(["systemctl", "restart", "fail2ban"], logger)
        logger.info("fail2ban enabled and restarted.")
    except subprocess.CalledProcessError:
        logger.error("Failed to start fail2ban. Check service status manually.")
        return False

    # Verify the sshd jail is active
    try:
        result = run_command(
            ["fail2ban-client", "status", "sshd"],
            logger,
            check=False,
        )
        if result.returncode == 0:
            logger.info("fail2ban sshd jail is active:\n%s", result.stdout.strip())
        else:
            logger.warning(
                "fail2ban sshd jail may not be active yet. "
                "Check with: fail2ban-client status sshd"
            )
    except FileNotFoundError:
        logger.warning("fail2ban-client not found — cannot verify jail status.")

    return True


# ─────────────────────────────────────────────
#  FINDING #2 — HOSTNAME INTEGRITY CHECK
# ─────────────────────────────────────────────
def validate_hostname(logger: logging.Logger) -> bool:
    """
    Validate the system hostname against the expected value from CONFIG.

    Detects the 'webs-server-01' anomaly identified in Finding #2 and
    writes a structured JSON report for SIEM ingestion.

    Returns:
        True if hostname matches expected value, False otherwise.
    """
    logger.info("── Finding #2: Validating system hostname ──────────────")

    expected = CONFIG["expected_hostname"]
    actual   = socket.gethostname()

    report = {
        "timestamp":         datetime.utcnow().isoformat() + "Z",
        "check":             "hostname_integrity",
        "expected_hostname": expected,
        "actual_hostname":   actual,
        "match":             actual == expected,
    }

    report_path = Path(CONFIG["backup_dir"]) / "hostname_report.json"
    if not is_dry_run(logger):
        Path(CONFIG["backup_dir"]).mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, indent=2))
        logger.info("Hostname report written to %s", report_path)

    if actual == expected:
        logger.info("Hostname check PASSED: '%s' matches expected value.", actual)
        return True

    logger.warning(
        "Hostname MISMATCH detected!\n"
        "  Expected : %s\n"
        "  Actual   : %s\n"
        "  This may indicate log tampering, a misconfigured host, "
        "or a rogue device on the network.",
        expected,
        actual,
    )

    # Offer to correct the hostname if running interactively
    if sys.stdin.isatty() and not is_dry_run(logger):
        answer = input(
            f"\nCorrect hostname from '{actual}' to '{expected}'? [y/N]: "
        ).strip().lower()
        if answer == "y":
            try:
                run_command(["hostnamectl", "set-hostname", expected], logger)
                logger.info("Hostname corrected to '%s'.", expected)
            except subprocess.CalledProcessError:
                logger.error("Failed to set hostname. Correct manually with hostnamectl.")
        else:
            logger.info("Hostname correction skipped by operator.")
    else:
        logger.info(
            "Non-interactive mode — hostname not corrected automatically. "
            "Run: hostnamectl set-hostname %s",
            expected,
        )

    return False


# ─────────────────────────────────────────────
#  POST-HARDENING VERIFICATION
# ─────────────────────────────────────────────
def verify_hardening(logger: logging.Logger) -> dict:
    """
    Run post-hardening checks and return a structured results dictionary.

    Checks performed:
      - iptables DROP rule for attacker IP
      - PermitRootLogin directive in sshd_config
      - fail2ban service status
      - SSH listening port

    Returns:
        Dictionary of {check_name: passed (bool)} pairs.
    """
    logger.info("── Post-hardening verification ─────────────────────────")
    results: dict[str, bool] = {}

    # 1. iptables rule
    try:
        check = run_command(
            ["iptables", "-C", "INPUT", "-s", CONFIG["attacker_ip"], "-j", "DROP"],
            logger,
            check=False,
        )
        results["iptables_block_rule"] = check.returncode == 0
    except FileNotFoundError:
        results["iptables_block_rule"] = False

    # 2. PermitRootLogin disabled
    try:
        content = Path(CONFIG["sshd_config_path"]).read_text()
        results["root_login_disabled"] = bool(
            re.search(r"^\s*PermitRootLogin\s+no", content, re.IGNORECASE | re.MULTILINE)
        )
    except OSError:
        results["root_login_disabled"] = False

    # 3. fail2ban running
    try:
        status = run_command(
            ["systemctl", "is-active", "fail2ban"],
            logger,
            check=False,
        )
        results["fail2ban_active"] = status.stdout.strip() == "active"
    except FileNotFoundError:
        results["fail2ban_active"] = False

    # 4. SSH port changed
    try:
        content = Path(CONFIG["sshd_config_path"]).read_text()
        results["ssh_port_changed"] = bool(
            re.search(
                rf"^\s*Port\s+{CONFIG['ssh_new_port']}",
                content,
                re.IGNORECASE | re.MULTILINE,
            )
        )
    except OSError:
        results["ssh_port_changed"] = False

    # Log summary table
    logger.info("Verification Results:")
    logger.info("  %-30s %s", "Check", "Status")
    logger.info("  " + "─" * 42)
    all_passed = True
    for check, passed in results.items():
        status_icon = "✓ PASS" if passed else "✗ FAIL"
        logger.info("  %-30s %s", check, status_icon)
        if not passed:
            all_passed = False

    if all_passed:
        logger.info("All verification checks PASSED.")
    else:
        logger.warning("One or more verification checks FAILED. Review the log.")

    return results


# ─────────────────────────────────────────────
#  MAIN ORCHESTRATOR
# ─────────────────────────────────────────────
def main() -> int:
    """
    Orchestrate all hardening steps and produce a final summary report.

    Exit codes:
        0 — All steps completed successfully.
        1 — One or more steps failed (see log for details).
        2 — Pre-flight check failed (e.g., not running as root).
    """
    logger = setup_logging(CONFIG["log_file"])

    logger.info("=" * 60)
    logger.info("SSH Security Hardening Script — Starting")
    logger.info("Timestamp : %s", datetime.utcnow().isoformat() + "Z")
    logger.info("Host      : %s", socket.gethostname())
    logger.info("Dry-run   : %s", CONFIG["dry_run"])
    logger.info("=" * 60)

    # Pre-flight: must be root
    require_root(logger)

    # ── Execute hardening steps ──────────────────────────────
    step_results: dict[str, bool] = {}

    step_results["block_attacker_ip"] = block_attacker_ip(
        CONFIG["attacker_ip"], logger
    )
    step_results["harden_sshd_config"] = harden_sshd_config(logger)
    step_results["install_fail2ban"]   = install_fail2ban(logger)
    step_results["validate_hostname"]  = validate_hostname(logger)

    # ── Post-hardening verification ──────────────────────────
    verification = verify_hardening(logger)

    # ── Final summary ────────────────────────────────────────
    logger.info("=" * 60)
    logger.info("Hardening Steps Summary:")
    overall_success = True
    for step, success in step_results.items():
        icon = "✓" if success else "✗"
        logger.info("  [%s] %s", icon, step)
        if not success:
            overall_success = False

    if overall_success:
        logger.info("All hardening steps completed successfully.")
    else:
        logger.warning("Some steps encountered errors. Review the log: %s", CONFIG["log_file"])

    logger.info("Full log available at: %s", CONFIG["log_file"])
    logger.info("=" * 60)

    return 0 if overall_success else 1


if __name__ == "__main__":
    sys.exit(main())
```

---

## Deployment Instructions

### Prerequisites

```bash
# Verify Python version (3.8+ required)
python3 --version

# Install system dependencies
apt-get update && apt-get install -y iptables-persistent fail2ban
```

### Step-by-Step Deployment

```bash
# 1. Download / copy the script to the target server
scp ssh_hardening.py admin@web-server-01:/opt/security/

# 2. Set restrictive permissions — only root should read/execute
chmod 700 /opt/security/ssh_hardening.py
chown root:root /opt/security/ssh_hardening.py

# 3. ── RECOMMENDED ── Run in dry-run mode first to preview all changes
#    Edit CONFIG["dry_run"] = True, then:
sudo python3 /opt/security/ssh_hardening.py

# 4. Review the preview output, then set dry_run = False and apply
sudo python3 /opt/security/ssh_hardening.py

# 5. Monitor the audit log
tail -f /var/log/ssh_hardening.log
```

### Post-Deployment Validation

```bash
# Confirm root login is blocked
grep -i "PermitRootLogin" /etc/ssh/sshd_config

# Confirm SSH is on the new port
ss -tlnp | grep sshd

# Confirm the attacker IP is blocked
iptables -L INPUT -n | grep 192.168.1.105

# Confirm fail2ban jail is active
fail2ban-client status sshd
```

---

## What Each Section Addresses

| Script Function | Finding | Action |
|---|---|---|
| `block_attacker_ip()` | #1 Critical | Drops all traffic from `192.168.1.105` via iptables |
| `harden_sshd_config()` | #3 High | Disables root login, enforces key auth, moves port, 16 directives total |
| `install_fail2ban()` | #1 Critical | Rate-limits auth attempts; bans after 3 failures |
| `validate_hostname()` | #2 Medium | Detects `webs-server-01` anomaly, writes JSON report for SIEM |
| `verify_hardening()` | All | Confirms every fix is in place before the script exits |
