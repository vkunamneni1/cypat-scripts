import os, re, subprocess

# Define the target max days to enforce
TARGET_MAX_DAYS = 90

# make sure running as admin
if os.geteuid() != 0:
    print("Please run as root...")
    exit()

print("--- Starting Authentication & Password Policy Hardening ---")

print("\n[+] Configuring /etc/login.defs...")
try:
    with open("/etc/login.defs", 'r+') as f:
        contents = f.read()
        
        # Set password ages (Ubuntu Key #7, Mint Key #7)
        min_age_match = re.search(r"PASS_MIN_DAYS\s+(\d+)", contents)
        max_age_match = re.search(r"PASS_MAX_DAYS\s+(\d+)", contents)
        warn_age_match = re.search(r"PASS_WARN_AGE\s+(\d+)", contents)

        if min_age_match: print(f"Current min age: {min_age_match.group(1)}")
        if max_age_match: print(f"Current max age: {max_age_match.group(1)}")
        if warn_age_match: print(f"Current warn age: {warn_age_match.group(1)}")

        contents = re.sub(r"PASS_MIN_DAYS\s+(\d+)", "PASS_MIN_DAYS   2", contents) # (Ubuntu Key #7)
        contents = re.sub(r"PASS_MAX_DAYS\s+(\d+)", f"PASS_MAX_DAYS   {TARGET_MAX_DAYS}", contents) # Enforce 90 days
        contents = re.sub(r"PASS_WARN_AGE\s+(\d+)", "PASS_WARN_AGE   14", contents) # (Your script's value)
        print("Set PASS_MIN_DAYS to 2")
        print(f"Set PASS_MAX_DAYS to {TARGET_MAX_DAYS}")
        print("Set PASS_WARN_AGE to 14")

        # Set stronger hashing (CIS 5.4.1.4)
        contents = re.sub(r"ENCRYPT_METHOD\s+\S+", "ENCRYPT_METHOD SHA512", contents)
        print("Set ENCRYPT_METHOD to SHA512")
        
        # Enable logging (from your original script)
        contents = re.sub(r"FAILLOG_ENAB\s+(yes|no)", "FAILLOG_ENAB yes", contents)
        contents = re.sub(r"LOG_UNKFAIL_ENAB\s+(yes|no)", "LOG_UNKFAIL_ENAB yes", contents)
        contents = re.sub(r"SYSLOG_SU_ENAB\s+(yes|no)", "SYSLOG_SU_ENAB yes", contents)
        contents = re.sub(r"SYSLOG_SG_ENAB\s+(yes|no)", "SYSLOG_SG_ENAB yes", contents)
        
        f.seek(0)
        f.truncate()
        f.write(contents)
        f.close()
except FileNotFoundError:
    print("Could not find /etc/login.defs")
except Exception as e:
    print(f"Error modifying /etc/login.defs: {e}")

# --- NEW SECTION: Enforce policy on existing users ---

print(f"\n[+] Enforcing PASS_MAX_DAYS ({TARGET_MAX_DAYS}) for all existing human users...")
try:
    # Use awk on /etc/passwd to find users with UID >= 1000
    user_list_output = subprocess.check_output(
        "awk -F: '($3 >= 1000) && ($1 != \"nobody\") { print $1 }' /etc/passwd",
        shell=True,
        text=True
    ).strip()
    
    users_to_check = user_list_output.split('\n')
    
    for user in users_to_check:
        if not user: continue
        
        # Get the current shadow entry for the user
        shadow_entry = subprocess.check_output(
            f"sudo chage -l {user} | grep 'Maximum number of days between password change'",
            shell=True,
            text=True
        ).strip()
        
        # Extract the current max days
        current_max_days_match = re.search(r":\s*(\d+)", shadow_entry)
        
        if current_max_days_match:
            current_max_days = int(current_max_days_match.group(1))
            
            if current_max_days != TARGET_MAX_DAYS:
                print(f"  -> User '{user}': Found max days = {current_max_days}. Fixing...")
                # Run chage to set the maximum password age
                subprocess.run(
                    ["sudo", "chage", "-M", str(TARGET_MAX_DAYS), user], 
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                print(f"     SUCCESS: Set max days to {TARGET_MAX_DAYS} for '{user}'.")
            else:
                print(f"  -> User '{user}': Max days already set to {TARGET_MAX_DAYS}. Skipping.")
        else:
            print(f"  WARN: Could not parse max days for user '{user}'. Skipping.")

except subprocess.CalledProcessError as e:
    print(f"ERROR: Failed to run user check command: {e}")
except Exception as e:
    print(f"ERROR: An unexpected error occurred during user policy enforcement: {e}")

# --- End NEW SECTION ---


print("\n[+] Configuring /etc/pam.d/common-password...")
try:
    with open("/etc/pam.d/common-password", 'r+') as f:
        contents = f.read()
        
        # Ubuntu Key #8 / Mint Key #11: Add minlen=10 to pam_pwquality
        if re.search(r"pam_pwquality\.so", contents):
            if not re.search(r"minlen=", contents):
                # Correctly add minlen=10 to the pwquality line
                contents = re.sub(r"(pam_pwquality\.so.*)", r"\1 minlen=10", contents)
                print("Added minlen=10 to pam_pwquality.so")
        else:
            # If pwquality isn't present, add it (CIS 5.3.2.3)
            # The main bash script MUST install libpam-pwquality for this to work
            contents += "\npassword requisite pam_pwquality.so retry=3 minlen=10\n"
            print("Added pam_pwquality.so line with minlen=10")
            
        # Mint Key #12: Add remember=5 to pam_unix
        if re.search(r"pam_unix\.so", contents):
            if not re.search(r"remember=", contents):
                # Correctly add remember=5 to the unix line
                contents = re.sub(r"(pam_unix\.so.*)", r"\1 remember=5", contents)
                print("Added remember=5 to pam_unix.so")
        
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
    # Ubuntu Key #10 / Mint Key #14 / Practice Key #10: Remove nullok
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


print("\n[+] Creating and enabling faillock PAM configs (Ubuntu Key #9 / Mint Key #13)...")
try:
    os.makedirs('/usr/share/pam-configs', exist_ok=True)
    
    with open('/usr/share/pam-configs/faillock', 'w+') as f:
        contents = """Name: Enforce failed login attempt counter
Default: no
Priority: 0
Auth-Type: Primary
Auth:
    [default=die] pam_faillock.so authfail
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
"""
        f.write(contents)
        f.close()
    
    print("Faillock config files created.")
    print("Running 'pam-auth-update --enable faillock faillock_notify' to apply...")
    subprocess.run(["pam-auth-update", "--enable", "faillock", "faillock_notify"], check=True)
    
except Exception as e:
    print(f"Error creating PAM configs or running pam-auth-update: {e}")

print("\n--- Python auth script finished. ---")
