import os, re, subprocess

# Define the target max days to enforce
TARGET_MAX_DAYS = 90
# Define the target inactive days (CIS 5.4.1.5)
TARGET_INACTIVE_DAYS = 30

# make sure running as admin
if os.geteuid() != 0:
    print("Please run as root...")
    exit()

print("--- Starting Authentication & Password Policy Hardening ---")

print("\n[+] Configuring /etc/login.defs...")
try:
    with open("/etc/login.defs", 'r+') as f:
        contents = f.read()
        
        # Set password ages (CIS 5.4.1.1, 5.4.1.3)
        contents = re.sub(r"^\s*PASS_MIN_DAYS\s+(\d+)", "PASS_MIN_DAYS   2", contents, flags=re.MULTILINE)
        contents = re.sub(r"^\s*PASS_MAX_DAYS\s+(\d+)", f"PASS_MAX_DAYS   {TARGET_MAX_DAYS}", contents, flags=re.MULTILINE)
        contents = re.sub(r"^\s*PASS_WARN_AGE\s+(\d+)", "PASS_WARN_AGE   14", contents, flags=re.MULTILINE)
        print("Set PASS_MIN_DAYS to 2")
        print(f"Set PASS_MAX_DAYS to {TARGET_MAX_DAYS}")
        print("Set PASS_WARN_AGE to 14")
        
        # NEW: Set inactive lock (CIS 5.4.1.5)
        if re.search(r"^\s*INACTIVE\s+", contents, re.MULTILINE):
            contents = re.sub(r"^\s*INACTIVE\s+(-?\d+)", f"INACTIVE\t{TARGET_INACTIVE_DAYS}", contents, flags=re.MULTILINE)
        else:
            contents += f"\nINACTIVE\t{TARGET_INACTIVE_DAYS}\n"
        print(f"Set INACTIVE to {TARGET_INACTIVE_DAYS}")


        # Set stronger hashing (CIS 5.4.1.4)
        contents = re.sub(r"^\s*ENCRYPT_METHOD\s+\S+", "ENCRYPT_METHOD SHA512", contents, flags=re.MULTILINE)
        print("Set ENCRYPT_METHOD to SHA512")
        
        # Enable logging
        contents = re.sub(r"^\s*FAILLOG_ENAB\s+(yes|no)", "FAILLOG_ENAB yes", contents, flags=re.MULTILINE)
        contents = re.sub(r"^\s*LOG_UNKFAIL_ENAB\s+(yes|no)", "LOG_UNKFAIL_ENAB yes", contents, flags=re.MULTILINE)
        contents = re.sub(r"^\s*SYSLOG_SU_ENAB\s+(yes|no)", "SYSLOG_SU_ENAB yes", contents, flags=re.MULTILINE)
        contents = re.sub(r"^\s*SYSLOG_SG_ENAB\s+(yes|no)", "SYSLOG_SG_ENAB yes", contents, flags=re.MULTILINE)
        
        f.seek(0)
        f.truncate()
        f.write(contents)
        f.close()
except FileNotFoundError:
    print("Could not find /etc/login.defs")
except Exception as e:
    print(f"Error modifying /etc/login.defs: {e}")

# --- Enforce policy on existing users ---

print(f"\n[+] Enforcing PASS_MAX_DAYS ({TARGET_MAX_DAYS}) for all existing human users...")
try:
    user_list_output = subprocess.check_output(
        "awk -F: '($3 >= 1000) && ($1 != \"nobody\") { print $1 }' /etc/passwd",
        shell=True,
        text=True
    ).strip()
    
    users_to_check = user_list_output.split('\n')
    
    for user in users_to_check:
        if not user: continue
        
        shadow_entry = subprocess.check_output(
            f"sudo chage -l {user} | grep 'Maximum number of days between password change'",
            shell=True,
            text=True
        ).strip()
        
        current_max_days_match = re.search(r":\s*(\d+)", shadow_entry)
        
        if current_max_days_match:
            current_max_days = int(current_max_days_match.group(1))
            
            if current_max_days > TARGET_MAX_DAYS:
                print(f"  -> User '{user}': Found max days = {current_max_days}. Fixing...")
                subprocess.run(
                    ["sudo", "chage", "-M", str(TARGET_MAX_DAYS), user], 
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                print(f"     SUCCESS: Set max days to {TARGET_MAX_DAYS} for '{user}'.")
            else:
                print(f"  -> User '{user}': Max days ({current_max_days}) is compliant. Skipping.")
        else:
            print(f"  WARN: Could not parse max days for user '{user}'. Skipping.")

except subprocess.CalledProcessError as e:
    print(f"ERROR: Failed to run user check command: {e}")
except Exception as e:
    print(f"ERROR: An unexpected error occurred during user policy enforcement: {e}")


print("\n[+] Configuring /etc/pam.d/common-password...")
try:
    with open("/etc/pam.d/common-password", 'r+') as f:
        contents = f.read()
        
        # CIS 5.3.3.2.2: Add minlen=10 to pam_pwquality
        if re.search(r"pam_pwquality\.so", contents):
            if not re.search(r"minlen=", contents):
                contents = re.sub(r"(pam_pwquality\.so.*)", r"\1 minlen=10", contents)
                print("Added minlen=10 to pam_pwquality.so")
        else:
            contents += "\npassword requisite pam_pwquality.so retry=3 minlen=10\n"
            print("Added pam_pwquality.so line with minlen=10")
            
        # CIS 5.3.3.4.2: Remove 'remember' from pam_unix (using pwhistory instead)
        if re.search(r"pam_unix\.so.*remember=", contents):
            print("Removing 'remember' from pam_unix.so (will use pam_pwhistory).")
            contents = re.sub(r"\s+remember=\d+", "", contents)
            
        # CIS 5.3.2.4: Add pam_pwhistory
        if not re.search(r"pam_pwhistory\.so", contents):
            print("Adding pam_pwhistory.so with remember=5.")
            # Insert pwhistory *before* pam_unix
            contents = re.sub(
                r"(password\s+\[success=1 default=ignore\]\s+pam_unix\.so.*)",
                "password requisite pam_pwhistory.so remember=5\n" + r"\1",
                contents
            )
        
        f.seek(0)
        f.truncate()
        f.write(contents)
        f.close()
except FileNotFoundError:
    print("Could not find /etc/pam.d/common-password")
except Exception as e:
    print(f"Error modifying /etc/pam.d/common-password: {e}")


print("\n[+] Configuring /etc/pam.d/common-auth (removing 'nullok')...")
try:
    # CIS 5.3.3.4.1: Remove nullok
    with open("/etc/pam.d/common-auth", 'r+') as f:
        contents = f.read()
        if "nullok" in contents:
            contents = re.sub(r"\s+nullok", "", contents)
            print("Removed 'nullok' from common-auth")
            f.seek(0)
            f.truncate()
            f.write(contents)
        else:
            print("'nullok' not found, no change needed.")
        f.close()
except FileNotFoundError:
    print("Could not find /etc/pam.d/common-auth")
except Exception as e:
    print(f"Error modifying /etc/pam.d/common-auth: {e}")


print("\n[+] Creating and enabling faillock PAM configs (CIS 5.3.2.2)...")
try:
    os.makedirs('/usr/share/pam-configs', exist_ok=True)
    
    with open('/usr/share/pam-configs/faillock', 'w+') as f:
        contents = """Name: Enforce failed login attempt counter
Default: no
Priority: 0
Auth-Type: Primary
Auth:
    [default=die] pam_faillock.so authfail deny=5 unlock_time=900
    sufficient pam_faillock.so authsucc
"""
        f.write(contents)
        f.close()

    with open('/usr/share/pam-configs/faillock_notify', 'w+') as f:
        contents = """Name: Notify on failed login attempts
Default: no
Priority: 1024
Auth-Type: Primary
Auth:
    requisite pam_faillock.so preauth
Account-Type: Primary
Account:
    required pam_faillock.so
"""
        f.write(contents)
        f.close()
    
    print("Faillock config files created with deny=5 and unlock_time=900.")
    print("Running 'pam-auth-update --enable faillock faillock_notify' to apply...")
    subprocess.run(["pam-auth-update", "--enable", "faillock", "faillock_notify"], check=True)
    
except Exception as e:
    print(f"Error creating PAM configs or running pam-auth-update: {e}")

print("\n--- Python auth script finished. ---")
