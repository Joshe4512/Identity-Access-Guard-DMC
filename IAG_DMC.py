from datetime import datetime

# ==========================================
# 1. USER DATABASE & DAILY TASKS
# ==========================================
USER_DATABASE = {
    "Dante": "DevilMayCry123",
    "Nero": "Kyrie4",
    "Vergil": "Yamato",
    "Admin": "SuperSecret99",
}

USER_TASKS = {
    "Dante": [
        "Investigate demon activity near the docks",
        "Clean Ebony and Ivory",
        "Pay electric bill (overdue)",
    ],
    "Nero": [
        "Inspect Devil Breaker arm attachments",
        "Tune up the patrol van",
        "Deliver supplies to the orphanage",
    ],
    "Vergil": [
        "Read poetry collection",
        "Polish the Yamato",
        "Seek more power",
    ],
}

MAX_FAILED_ATTEMPTS = 3

# File paths for persistent storage
LOGIN_LOG_FILE = "login_history.txt"
INCIDENT_LOG_FILE = "security_incidents.txt"
LOCKED_ACCOUNTS_FILE = "locked_accounts.txt"

# In-memory tracking
failed_attempts = {}
login_counts = {}


# ==========================================
# 2. FILE PERSISTENCE & HELPERS
# ==========================================
def load_locked_accounts() -> set:
    """Reads locked accounts from disk on program startup."""
    locked = set()
    try:
        with open(LOCKED_ACCOUNTS_FILE, "r", encoding="utf-8") as file:
            for line in file:
                cleaned_name = line.strip()
                if cleaned_name:
                    locked.add(cleaned_name)
    except FileNotFoundError:
        # File will be created automatically when the first lockout happens
        pass
    return locked


def save_locked_accounts(locked_set: set):
    """Overwrites the locked accounts file with the current active set."""
    with open(LOCKED_ACCOUNTS_FILE, "w", encoding="utf-8") as file:
        for username in sorted(locked_set):
            file.write(f"{username}\n")


def append_log(filename: str, log_line: str):
    """Appends a new event line to a log file on disk."""
    with open(filename, "a", encoding="utf-8") as file:
        file.write(log_line + "\n")


def display_log_file(filename: str, title: str):
    """Reads and prints all lines from a log file."""
    print(f"\n--- {title} ---")
    try:
        with open(filename, "r", encoding="utf-8") as file:
            lines = file.readlines()
            if not lines:
                print("Log file exists, but has no records.")
            else:
                for line in lines:
                    print(line.strip())
    except FileNotFoundError:
        print(f"No records found yet ({filename} has not been created).")


def get_canonical_user(raw_input: str):
    """Matches user input case-insensitively to the registered names."""
    cleaned = raw_input.strip()
    for registered_user in USER_DATABASE:
        if registered_user.lower() == cleaned.lower():
            return registered_user
    return cleaned.capitalize() if cleaned else None


# Initialize locked accounts directly from the file
locked_accounts = load_locked_accounts()


# ==========================================
# 3. AUTHENTICATION & INCIDENT REPORTING
# ==========================================
def login():
    """Authenticates the user and tracks access."""
    print("\n--- AUTHENTICATION REQUIRED ---")
    raw_user = input("Enter username: ")
    password = input("Enter password: ").strip()

    username = get_canonical_user(raw_user)
    if not username:
        print("\n[-] Error: Username cannot be blank.")
        return

    # Check if account is locked (verified against persistent set)
    if username in locked_accounts:
        print(
            f"\n[!] ACCESS DENIED: Account '{username}' is LOCKED."
        )
        print("    Contact an administrator to restore access.")
        return

    # Check credentials
    if username in USER_DATABASE and USER_DATABASE[username] == password:
        print(f"\n[+] Credentials verified!")
        failed_attempts[username] = 0

        # Update login metrics
        login_counts[username] = login_counts.get(username, 0) + 1
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Save to login_history.txt
        log_entry = f"[{timestamp}] User: {username:<10} | Login #{login_counts[username]}"
        append_log(LOGIN_LOG_FILE, log_entry)

        # Route by role
        if username == "Admin":
            admin_portal()
        else:
            user_portal(username)
    else:
        failed_attempts[username] = failed_attempts.get(username, 0) + 1
        fails = failed_attempts[username]
        print(
            f"\n[-] FAILED: Invalid username or password. ({fails}/{MAX_FAILED_ATTEMPTS})"
        )

        if fails >= MAX_FAILED_ATTEMPTS:
            flag_account(username)


def flag_account(username):
    """Locks account, persists the lock to disk, and logs the incident."""
    locked_accounts.add(username)
    save_locked_accounts(locked_accounts)  # Save lock status to disk

    incident_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    incident_entry = (
        f"[{incident_time}] [LOCKOUT] User: {username:<10} | "
        f"Reason: Exceeded {MAX_FAILED_ATTEMPTS} failed attempts"
    )
    append_log(INCIDENT_LOG_FILE, incident_entry)

    print(
        f"\n[ALERT] Account '{username}' has been flagged and locked at {incident_time}."
    )
    print(f"        Lock status saved to '{LOCKED_ACCOUNTS_FILE}'.")


# ==========================================
# 4. REGULAR USER PORTAL
# ==========================================
def user_portal(username):
    """Standard user menu with daily tasks."""
    while True:
        print("\n" + "=" * 45)
        print(f"       Welcome, {username}!")
        print("=" * 45)
        print("1. View Daily Tasks")
        print("2. View My Account Status")
        print("3. Log Out")

        choice = input("Select an option (1-3): ").strip()

        if choice == "1":
            print(f"\n--- Daily Tasks for {username} ---")
            tasks = USER_TASKS.get(username, ["No assigned tasks."])
            for idx, task in enumerate(tasks, start=1):
                print(f"  {idx}. [ ] {task}")

        elif choice == "2":
            print(f"\n--- Account Status ---")
            print(f"User: {username}")
            print(f"Session Logins: {login_counts.get(username, 0)}")
            print("Status: Active / In Good Standing")

        elif choice == "3":
            print(f"\nLogging out of session for {username}...")
            break
        else:
            print("Invalid selection. Please choose 1, 2, or 3.")


# ==========================================
# 5. ADMIN AUDIT & LOGS PORTAL
# ==========================================
def unlock_account():
    """Allows admin to unlock accounts and updates the persistent locked list."""
    print("\n--- UNLOCK USER ACCOUNT ---")
    if not locked_accounts:
        print("No accounts are currently locked.")
        return

    print(f"Currently locked accounts: {', '.join(sorted(locked_accounts))}")
    raw_target = input("Enter username to unlock: ")
    target_user = get_canonical_user(raw_target)

    if target_user in locked_accounts:
        # Remove from memory set and rewrite disk file
        locked_accounts.remove(target_user)
        save_locked_accounts(locked_accounts)
        failed_attempts[target_user] = 0

        unlock_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        unlock_entry = (
            f"[{unlock_time}] [RESTORE] User: {target_user:<10} | "
            f"Reason: Administrative manual unlock"
        )
        append_log(INCIDENT_LOG_FILE, unlock_entry)

        print(
            f"[+] Success: '{target_user}' has been unlocked and removed from disk."
        )
    else:
        print(f"[-] '{target_user}' is not in the locked list.")


def admin_portal():
    """Exclusive portal for admin to view logs and manage access."""
    while True:
        print("\n" + "#" * 55)
        print("            ADMINISTRATOR SECURITY PORTAL            ")
        print("#" * 55)
        print("1. View User Login History (From File)")
        print("2. View Flagged Security Incidents (From File)")
        print("3. View Currently Locked Accounts")
        print("4. Unlock an Account")
        print("5. Log Out")

        choice = input("Select an option (1-5): ").strip()

        if choice == "1":
            display_log_file(LOGIN_LOG_FILE, "PERSISTENT LOGIN AUDIT TRAIL")
        elif choice == "2":
            display_log_file(INCIDENT_LOG_FILE, "PERSISTENT SECURITY INCIDENTS")
        elif choice == "3":
            print("\n--- CURRENTLY LOCKED USERS ---")
            if not locked_accounts:
                print("No accounts are locked.")
            else:
                for user in sorted(locked_accounts):
                    print(f" - {user}")
        elif choice == "4":
            unlock_account()
        elif choice == "5":
            print("\nLogging out of Administrator session...")
            break
        else:
            print("Invalid selection. Please choose 1-5.")


# ==========================================
# 6. ENTRY POINT
# ==========================================
def main():
    while True:
        print("\n=================================")
        print("      CENTRAL ACCESS GATEWAY     ")
        print("=================================")
        print("1. Log In")
        print("2. Shut Down System")

        choice = input("Select an option (1-2): ").strip()

        if choice == "1":
            login()
        elif choice == "2":
            print("\nShutting down gateway. Goodbye!")
            break
        else:
            print("Invalid choice. Enter 1 or 2.")


if __name__ == "__main__":
    main()