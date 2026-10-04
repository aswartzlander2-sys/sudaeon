"""Version and identity constants for Sudaeon."""

APP_NAME = "Sudaeon"
APP_SUMMARY = "Parental controls and master-password policy enforcement for Ubuntu"
APP_VERSION = "1.0.0"
SCHEMA_VERSION = 1

# Reverse-DNS style identifiers (freedesktop naming).
APP_ID = "com.sudaeon.Sudaeon"          # dashboard / manager window
SETUP_ID = "com.sudaeon.Setup"          # first run wizard
PROMPT_ID = "com.sudaeon.Permission"    # permission manager dialog
AGENT_ID = "com.sudaeon.Agent"          # per-session prompt agent

# polkit action used for installing / uninstalling / administrative helper runs
POLKIT_ACTION = "com.sudaeon.manage"

# D-Bus / socket names
SENTINEL_SOCKET = "sentinel.sock"
AGENT_SOCKET_FMT = "agent.%d.sock"

# System group whose members may talk to the helper without a password (the
# helper still requires the master password for anything that changes policy).
ADMIN_GROUP = "sudaeon-admins"
SERVICE_USER = "sudaeon"      # unused by default (helper runs via sudo/pkexec)
SENTINEL_USER = "root"


def version_string() -> str:
    return f"{APP_NAME} {APP_VERSION}"
