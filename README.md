# Identity-Access-Guard-DMC

A Python-based Identity & Access Management (IAM) simulation demonstrating Role-Based Access Control (RBAC), persistent brute-force lockout policies, and non-volatile security audit trails.

---

## Project Summary

**Identity Access Guard** is a terminal-based Identity and Access Management (IAM) simulation developed in Python. It enforces Role-Based Access Control (RBAC), prevents brute-force credential stuffing via automated account lockouts, and writes non-volatile audit trails directly to local disk. 

The project models the interaction between client gateways, identity stores, and administrative auditing consoles, demonstrating core security architecture principles without relying on third-party libraries.

---

## Line-by-Line Code Walkthrough

This section breaks down `IAG_DMC.py` from top to bottom, detailing the exact Python mechanics and cybersecurity purpose of every line.

### Section 1: Modules & Authoritative Data

```python
from datetime import datetime
Line 1: Imports the datetime class from Python’s built-in datetime library. Used to generate ISO-style timestamps for auditing and non-repudiation in log records.Python# ==========================================
# 1. USER DATABASE & DAILY TASKS
# ==========================================
USER_DATABASE = {
    "Dante": "DevilMayCry123",
    "Nero": "Kyrie4",
    "Vergil": "Yamato",
    "Admin": "SuperSecret99",
}
Lines 3–5: Structural comments organizing global configuration variables.Lines 6–11: Defines USER_DATABASE, a dictionary acting as the system's authoritative identity store. Keys represent registered usernames; values represent credentials. Usernames are stored with canonical capitalization.PythonUSER_TASKS = {
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
Lines 13–29: Defines USER_TASKS, a nested dictionary containing role-specific lists. Enforces the Principle of Least Privilege by giving standard users access only to their own operational data, while preventing them from reading other profiles.PythonMAX_FAILED_ATTEMPTS = 3
Line 31: Defines the brute-force security threshold constant. If consecutive failed logins reach 3, the account is locked out.Python# File paths for persistent storage
LOGIN_LOG_FILE = "login_history.txt"
INCIDENT_LOG_FILE = "security_incidents.txt"
LOCKED_ACCOUNTS_FILE = "locked_accounts.txt"
Lines 33–36: String constants for storage filenames. Hardcoding paths into named constants makes file operations maintainable from a single location.Python# In-memory tracking
failed_attempts = {}
login_counts = {}
Lines 38–40: In-memory state tracking. failed_attempts maps {username: int} to track consecutive failed logins. login_counts maps {username: int} to record how many successful logins occur during the runtime session.Section 2: File Persistence & Helper RoutinesPythondef load_locked_accounts() -> set:
    """Reads locked accounts from disk on program startup."""
    locked = set()
    try:
        with open(LOCKED_ACCOUNTS_FILE, "r", encoding="utf-8") as file:
            for line in file:
                cleaned_name = line.strip()
                if cleaned_name:
                    locked.add(cleaned_name)
    except FileNotFoundError:
        pass
    return locked
Line 42: Defines load_locked_accounts(), returning a set.Line 44: Initializes an empty set locked. Sets provide $O(1)$ constant-time lookup performance for membership checks.Line 45: Starts a try block to handle missing files on first run.Line 46: Opens locked_accounts.txt in read mode ("r"). The with statement ensures the file handle closes automatically even if an exception occurs.Lines 47–50: Loops through each line, strips newline characters (\n), checks that the line is not blank, and adds the username into the locked set.Lines 51–52: Catches FileNotFoundError. If the file has not been created yet, it suppresses the error and continues.Line 53: Returns the populated or empty set.Pythondef save_locked_accounts(locked_set: set):
    """Overwrites the locked accounts file with the current active set."""
    with open(LOCKED_ACCOUNTS_FILE, "w", encoding="utf-8") as file:
        for username in sorted(locked_set):
            file.write(f"{username}\n")
Line 55: Defines save_locked_accounts(), accepting the current set of locked usernames.Line 57: Opens locked_accounts.txt in write mode ("w"), truncating and overwriting existing contents.Lines 58–59: Iterates through the sorted set and writes each locked username on a separate line. When an admin unlocks an account, this ensures the removed user is cleared from disk.Pythondef append_log(filename: str, log_line: str):
    """Appends a new event line to a log file on disk."""
    with open(filename, "a", encoding="utf-8") as file:
        file.write(log_line + "\n")
Line 61: Defines append_log(), accepting the target filename and string payload.Lines 63–64: Opens the log file in append mode ("a"). Appending preserves all historical lines without overwriting, maintaining an append-only audit trail.Pythondef display_log_file(filename: str, title: str):
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
Line 66: Defines display_log_file() to safely output file contents.Lines 68–71: Prints the header banner, opens the target log in read mode, and reads all lines into a list.Lines 72–76: Checks if the file is empty; if entries exist, prints each stripped of trailing whitespace.Lines 77–78: Catches FileNotFoundError if the log file has not yet been initialized.Pythondef get_canonical_user(raw_input: str):
    """Matches user input case-insensitively to the registered names."""
    cleaned = raw_input.strip()
    for registered_user in USER_DATABASE:
        if registered_user.lower() == cleaned.lower():
            return registered_user
    return cleaned.capitalize() if cleaned else None
Line 80: Defines get_canonical_user() for username normalization.Line 82: Strips accidental leading and trailing whitespace from terminal input.Lines 83–85: Iterates through canonical database keys, comparing both strings in lowercase. If "dante" is entered, it returns "Dante".Line 86: Fallback: Capitalizes unrecognized input or returns None if the input was empty.Python# Initialize locked accounts directly from the file
locked_accounts = load_locked_accounts()
Lines 88–89: Runs load_locked_accounts() at startup. Restores persistent lockout state into memory before the user sees the gateway.Section 3: Authentication & Incident HandlingPythondef login():
    """Authenticates the user and tracks access."""
    print("\n--- AUTHENTICATION REQUIRED ---")
    raw_user = input("Enter username: ")
    password = input("Enter password: ").strip()
Lines 91–95: Collects authentication credentials and strips whitespace from the entered password.Python    username = get_canonical_user(raw_user)
    if not username:
        print("\n[-] Error: Username cannot be blank.")
        return
Lines 97–100: Resolves the username to its canonical form. If blank, prints an error and exits the login sequence.Python    if username in locked_accounts:
        print(
            f"\n[!] ACCESS DENIED: Account '{username}' is LOCKED."
        )
        print("    Contact an administrator to restore access.")
        return
Lines 102–107: Lockout gate check. Checks whether the identity is present in locked_accounts. If locked, access is denied immediately without checking the password.Python    if username in USER_DATABASE and USER_DATABASE[username] == password:
        print(f"\n[+] Credentials verified!")
        failed_attempts[username] = 0
Line 109: Validates authentication: checks if the username exists in the identity database and if the provided password matches.Lines 110–111: Prints verification confirmation and resets the consecutive failure counter for this user back to 0.Python        login_counts[username] = login_counts.get(username, 0) + 1
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] User: {username:<10} | Login #{login_counts[username]}"
        append_log(LOGIN_LOG_FILE, log_entry)
Line 113: Increments the user's successful login counter in memory, using dict.get() to default to 0 if this is their first login.Line 114: Formats the current date and time into a readable timestamp string.Lines 115–116: Formats the audit log entry (padding the username to 10 characters for table-like alignment) and appends it to login_history.txt.Python        if username == "Admin":
            admin_portal()
        else:
            user_portal(username)
Lines 118–121: RBAC Authorization Router. Evaluates role identity: routes "Admin" to administrative monitoring, and all other identities to their personalized user dashboard.Python    else:
        failed_attempts[username] = failed_attempts.get(username, 0) + 1
        fails = failed_attempts[username]
        print(
            f"\n[-] FAILED: Invalid username or password. ({fails}/{MAX_FAILED_ATTEMPTS})"
        )
        if fails >= MAX_FAILED_ATTEMPTS:
            flag_account(username)
Lines 122–126: Failed login branch. Increments the user's failure counter and displays their current failure count against the maximum allowed.Lines 128–129: Triggers flag_account(username) if failed attempts reach or exceed MAX_FAILED_ATTEMPTS.Pythondef flag_account(username):
    """Locks account, persists the lock to disk, and logs the incident."""
    locked_accounts.add(username)
    save_locked_accounts(locked_accounts)
Line 131: Defines flag_account(), the automated incident responder.Lines 133–134: Adds the username to the active in-memory lockout set and immediately overwrites locked_accounts.txt so the lockout persists across restarts.Python    incident_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    incident_entry = (
        f"[{incident_time}] [LOCKOUT] User: {username:<10} | "
        f"Reason: Exceeded {MAX_FAILED_ATTEMPTS} failed attempts"
    )
    append_log(INCIDENT_LOG_FILE, incident_entry)
    print(
        f"\n[ALERT] Account '{username}' has been flagged and locked at {incident_time}."
    )
    print(f"        Lock status saved to '{LOCKED_ACCOUNTS_FILE}'.")
Lines 136–141: Generates an incident timestamp, constructs a [LOCKOUT] log entry, and appends it to security_incidents.txt.Lines 142–145: Prints an alert confirming the account is locked and written to disk.Section 4: End-User Portal (Principle of Least Privilege)Pythondef user_portal(username):
    """Standard user menu with daily tasks."""
    while True:
        print("\n" + "=" * 45)
        print(f"       Welcome, {username}!")
        print("=" * 45)
        print("1. View Daily Tasks")
        print("2. View My Account Status")
        print("3. Log Out")
        choice = input("Select an option (1-3): ").strip()
Lines 147–156: Starts an interactive navigation loop for authenticated non-admin users, presenting a personalized greeting and available actions.Python        if choice == "1":
            print(f"\n--- Daily Tasks for {username} ---")
            tasks = USER_TASKS.get(username, ["No assigned tasks."])
            for idx, task in enumerate(tasks, start=1):
                print(f"  {idx}. [ ] {task}")
Lines 158–162: Option 1. Fetches only the tasks associated with the current user via USER_TASKS.get(). Formats them as an enumerated task list.Python        elif choice == "2":
            print(f"\n--- Account Status ---")
            print(f"User: {username}")
            print(f"Session Logins: {login_counts.get(username, 0)}")
            print("Status: Active / In Good Standing")
Lines 164–168: Option 2. Displays identity status and total successful logins recorded during this session.Python        elif choice == "3":
            print(f"\nLogging out of session for {username}...")
            break
        else:
            print("Invalid selection. Please choose 1, 2, or 3.")
Lines 170–174: Option 3 exits the loop, terminating the user session and returning to the main gateway. Includes validation for unrecognized input.Section 5: Administrator Portal & Override ControlsPythondef unlock_account():
    """Allows admin to unlock accounts and updates the persistent locked list."""
    print("\n--- UNLOCK USER ACCOUNT ---")
    if not locked_accounts:
        print("No accounts are currently locked.")
        return
Lines 176–181: Defines administrative unlock flow. Checks if locked_accounts is empty; if so, exits early.Python    print(f"Currently locked accounts: {', '.join(sorted(locked_accounts))}")
    raw_target = input("Enter username to unlock: ")
    target_user = get_canonical_user(raw_target)
Lines 183–185: Displays active locked accounts and normalizes the entered target username.Python    if target_user in locked_accounts:
        locked_accounts.remove(target_user)
        save_locked_accounts(locked_accounts)
        failed_attempts[target_user] = 0
Lines 187–190: If the target is locked:Removes the username from the in-memory set.Overwrites locked_accounts.txt via save_locked_accounts().Resets failed_attempts back to 0 so the user is not locked again on a single typo.Python        unlock_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        unlock_entry = (
            f"[{unlock_time}] [RESTORE] User: {target_user:<10} | "
            f"Reason: Administrative manual unlock"
        )
        append_log(INCIDENT_LOG_FILE, unlock_entry)
        print(f"[+] Success: '{target_user}' has been unlocked and removed from disk.")
    else:
        print(f"[-] '{target_user}' is not in the locked list.")
Lines 192–198: Records an administrative [RESTORE] entry in security_incidents.txt for audit logging, then prints confirmation.Lines 199–200: Prints an error if the user was not found in the locked set.Pythondef admin_portal():
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
Lines 202–213: Starts the admin console loop, presenting monitoring and administrative actions.Python        if choice == "1":
            display_log_file(LOGIN_LOG_FILE, "PERSISTENT LOGIN AUDIT TRAIL")
        elif choice == "2":
            display_log_file(INCIDENT_LOG_FILE, "PERSISTENT SECURITY INCIDENTS")
Lines 215–218: Options 1 and 2 read and display historical logs directly from login_history.txt and security_incidents.txt.Python        elif choice == "3":
            print("\n--- CURRENTLY LOCKED USERS ---")
            if not locked_accounts:
                print("No accounts are locked.")
            else:
                for user in sorted(locked_accounts):
                    print(f" - {user}")
Lines 219–225: Option 3 iterates through locked_accounts and prints every identity currently locked out.Python        elif choice == "4":
            unlock_account()
        elif choice == "5":
            print("\nLogging out of Administrator session...")
            break
        else:
            print("Invalid selection. Please choose 1-5.")
Lines 226–232: Option 4 calls the unlock workflow; Option 5 breaks out of the loop to log out. Handles invalid selections.Section 6: Central Gateway & Entry PointPythondef main():
    while True:
        print("\n=================================")
        print("      CENTRAL ACCESS GATEWAY     ")
        print("=================================")
        print("1. Log In")
        print("2. Shut Down System")
        choice = input("Select an option (1-2): ").strip()
Lines 234–241: Defines main(), the public entry gateway shown to unauthenticated users.Python        if choice == "1":
            login()
        elif choice == "2":
            print("\nShutting down gateway. Goodbye!")
            break
        else:
            print("Invalid choice. Enter 1 or 2.")
Lines 243–249: Routes selection: 1 starts login(); 2 exits the loop to terminate the program cleanly.Pythonif __name__ == "__main__":
    main()
Lines 251–252: Python standard execution boilerplate. Ensures main() runs only when IAG_DMC.py is executed directly via terminal, not when imported as a module in other scripts.Key Cybersecurity ConceptsIdentity Verification (Authentication): Enforces credential validation against a canonical registry with case-insensitive normalization.Brute-Force Mitigation (Lockout Policy): Tracks failed login attempts per identity. At threshold (MAX_FAILED_ATTEMPTS = 3), access is revoked immediately.Role-Based Access Control (RBAC): Restricts interface access by role—regular users see personal tasks; administrators access system audit trails.Non-Repudiation & Audit Logging: Writes system actions to append-only disk files (login_history.txt and security_incidents.txt) with exact timestamps.Persistent State Synchronization: Uses locked_accounts.txt so lockouts persist even if the application is restarted.
