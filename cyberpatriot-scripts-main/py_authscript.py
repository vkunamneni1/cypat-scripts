import os, re, subprocess

# --- Configuration ---
TARGET_MAX_DAYS = 90
TARGET_INACTIVE_DAYS = 30

# --- Helper Functions ---
def get_os_name():
    try:
        with open("/etc/os-release", "r") as f:
            for line in f:
                if line.startswith("NAME="):
                    return line.split("=")[1].strip().strip('"')
    except:
        return "Unknown"
    return "Unknown"

def run_command(command):
    try:
        subprocess.run(command, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        return False

# --- Root Check ---
if os.geteuid() != 0:
    print("Please run as root...")
    exit()

OS_NAME = get_os_name()
print(f"--- Starting Authentication Hardening for {OS_NAME} ---")

# =============================================================================
# 1. LOGIN.DEFS (Common to both)
# =============================================================================
print("\n[+] Configuring /etc/login.defs...")
try:
    with open("/etc/login.defs", 'r+') as f:
        contents = f.read()
        
        # Set password ages
        contents = re.sub(r"^\s*PASS_MIN_DAYS\s+(\d+)", "PASS_MIN_DAYS   2", contents, flags=re.MULTILINE)
        contents = re.sub(r"^\s*PASS_MAX_DAYS\s+(\d+)", f"PASS_MAX_DAYS   {TARGET_MAX_DAYS}", contents, flags=re.MULTILINE)
        contents = re.sub(r"^\s*PASS_WARN_AGE\s+(\d+)", "PASS_WARN_AGE   14", contents, flags=re.MULTILINE)
        print("Set PASS_MIN_DAYS to 2")
        print(f"Set PASS_MAX_DAYS to {TARGET_MAX_DAYS}")
        
        # Set inactive lock
        if re.search(r"^\s*INACTIVE\s+", contents, re.MULTILINE):
            contents = re.sub(r"^\s*INACTIVE\s+(-?\d+)", f"INACTIVE\t{TARGET_INACTIVE_DAYS}", contents, flags=re.MULTILINE)
        else:
            contents += f"\nINACTIVE\t{TARGET_INACTIVE_DAYS}\n"
        print(f"Set INACTIVE to {TARGET_INACTIVE_DAYS}")

        # Set stronger hashing
        contents = re.sub(r"^\s*ENCRYPT_METHOD\s+\S+", "ENCRYPT_METHOD SHA512", contents, flags=re.MULTILINE)
        
        # Enable logging
        contents = re.sub(r"^\s*FAILLOG_ENAB\s+(yes|no)", "FAILLOG_ENAB yes", contents, flags=re.MULTILINE)
        contents = re.sub(r"^\s*LOG_UNKFAIL_ENAB\s+(yes|no)", "LOG_UNKFAIL_ENAB yes", contents, flags=re.MULTILINE)
        contents = re.sub(r"^\s*SYSLOG_SU_ENAB\s+(yes|no)", "SYSLOG_SU_ENAB yes", contents, flags=re.MULTILINE)
        contents = re.sub(r"^\s*SYSLOG_SG_ENAB\s+(yes|no)", "SYSLOG_SG_ENAB yes", contents, flags=re.MULTILINE)
        
        f.seek(0)
        f.truncate()
        f.write(contents)
except Exception as e:
    print(f"Error modifying /etc/login.defs: {e}")

# =============================================================================
# 2. Enforce Policy on Existing Users (Common)
# =============================================================================
print(f"\n[+] Enforcing PASS_MAX_DAYS ({TARGET_MAX_DAYS}) for existing users...")
try:
    user_list = subprocess.check_output("awk -F: '($3 >= 1000) && ($1 != \"nobody\") { print $1 }' /etc/passwd", shell=True, text=True).strip().split('\n')
    for user in user_list:
        if not user: continue
        subprocess.run(["chage", "-M", str(TARGET_MAX_DAYS), user], check=False)
    print("Policy enforced on all users.")
except Exception as e:
    print(f"Error checking users: {e}")

# =============================================================================
# 3. PAM Configuration (OS Specific)
# =============================================================================

print("\n[+] Configuring PAM...")

# --- Common Task: Remove 'nullok' ---
try:
    with open("/etc/pam.d/common-auth", 'r+') as f:
        contents = f.read()
        if "nullok" in contents:
            contents = re.sub(r"\s+nullok", "", contents)
            print("Removed 'nullok' from common-auth")
            f.seek(0)
            f.truncate()
            f.write(contents)
except Exception as e:
    print(f"Error removing nullok: {e}")

# --- Common Task: Set Minlen = 10 ---
try:
    with open("/etc/pam.d/common-password", 'r+') as f:
        contents = f.read()
        if re.search(r"pam_pwquality\.so", contents):
            if not re.search(r"minlen=", contents):
                contents = re.sub(r"(pam_pwquality\.so.*)", r"\1 minlen=10", contents)
                print("Added minlen=10 to pam_pwquality.so")
                f.seek(0)
                f.truncate()
                f.write(contents)
except Exception as e:
    print(f"Error setting minlen: {e}")


if "Mint" in OS_NAME:
    print("\n[!] Detected Linux Mint. Applying Mint-specific PAM fixes...")
    
    # Mint Key Item #12: Previous passwords are remembered (3)
    # Mint Key Item #13: Account lockout policy
    
    try:
        # Set remember=3 (Mint specific)
        with open("/etc/pam.d/common-password", 'r+') as f:
            contents = f.read()
            if re.search(r"pam_unix\.so", contents):
                if not re.search(r"remember=", contents):
                    contents = re.sub(r"(pam_unix\.so.*)", r"\1 remember=3", contents)
                    print("Added remember=3 to pam_unix.so (Mint Policy)")
                    f.seek(0)
                    f.truncate()
                    f.write(contents)
    except Exception as e:
        print(f"Error setting remember=3: {e}")

    # Create Mint-specific faillock configs (Item #13)
    try:
        os.makedirs('/usr/share/pam-configs', exist_ok=True)
        
        # File 1: faillock (Lockout on failed logins)
        with open('/usr/share/pam-configs/faillock', 'w') as f:
            f.write("""Name: Lockout on failed logins
Default: no
Priority: 0
Auth-Type: Primary
Auth:
    [default=die] pam_faillock.so authfail
    sufficient pam_faillock.so authsucc
""")
        
        # File 2: faillock_notify (Notify on account lockout)
        with open('/usr/share/pam-configs/faillock_notify', 'w') as f:
            f.write("""Name: Notify on account lockout
Default: no
Priority: 1024
Auth-Type: Primary
Auth:
    requisite pam_faillock.so preauth
""")
        
        # File 3: faillock_reset (Reset lockout on success)
        with open('/usr/share/pam-configs/faillock_reset', 'w') as f:
            f.write("""Name: Reset lockout on success
Default: no
Priority: 0
Auth-Type: Additional
Auth:
    required pam_faillock.so authsucc
""")

        print("Mint PAM configs created.")
        print("Applying PAM updates...")
        # Enable the profiles specifically mentioned in Mint Answer Key
        subprocess.run(["pam-auth-update", "--enable", "faillock", "faillock_notify", "faillock_reset"], check=True)
        print("Mint PAM settings applied successfully.")

    except Exception as e:
        print(f"Error applying Mint PAM settings: {e}")


else: # UBUNTU (and others)
    print("\n[!] Detected Ubuntu. Applying Ubuntu-specific PAM fixes...")
    
    # Ubuntu Key Item #9: Account lockout policy
    
    try:
        # Set remember=5 (Ubuntu policy usually 5) and use pam_pwhistory
        with open("/etc/pam.d/common-password", 'r+') as f:
            contents = f.read()
            
            # Remove remember from pam_unix if present (to use pwhistory instead)
            if re.search(r"pam_unix\.so.*remember=", contents):
                contents = re.sub(r"\s+remember=\d+", "", contents)
                
            # Add pam_pwhistory if missing
            if not re.search(r"pam_pwhistory\.so", contents):
                print("Adding pam_pwhistory.so with remember=5")
                contents = re.sub(
                    r"(password\s+\[success=1 default=ignore\]\s+pam_unix\.so.*)",
                    "password requisite pam_pwhistory.so remember=5\n" + r"\1",
                    contents
                )
                f.seek(0)
                f.truncate()
                f.write(contents)
    except Exception as e:
        print(f"Error setting password history: {e}")

    # Create Ubuntu-style faillock configs
    try:
        os.makedirs('/usr/share/pam-configs', exist_ok=True)
        
        with open('/usr/share/pam-configs/faillock', 'w') as f:
            f.write("""Name: Enforce failed login attempt counter
Default: no
Priority: 0
Auth-Type: Primary
Auth:
    [default=die] pam_faillock.so authfail deny=5 unlock_time=900
    sufficient pam_faillock.so authsucc
""")

        with open('/usr/share/pam-configs/faillock_notify', 'w') as f:
            f.write("""Name: Notify on failed login attempts
Default: no
Priority: 1024
Auth-Type: Primary
Auth:
    requisite pam_faillock.so preauth
""")
        
        print("Ubuntu PAM configs created.")
        print("Applying PAM updates...")
        subprocess.run(["pam-auth-update", "--enable", "faillock", "faillock_notify"], check=True)
        print("Ubuntu PAM settings applied successfully.")

    except Exception as e:
        print(f"Error applying Ubuntu PAM settings: {e}")

print("\n--- Script Finished ---")
