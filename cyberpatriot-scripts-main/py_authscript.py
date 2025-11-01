import os, re, subprocess

# make sure running as admin
if os.geteuid() != 0:
    print("Please run as root...")
    exit()

print("Setting a min/max/warn password age in /etc/login.defs...")
try:
    with open("/etc/login.defs", 'r+') as f:
        contents = f.read()
        
        # Set password ages (Ubuntu Key #7, Mint Key #7)
        contents = re.sub(r"PASS_MIN_DAYS\s+(\d+)", "PASS_MIN_DAYS   2", contents)
        contents = re.sub(r"PASS_MAX_DAYS\s+(\d+)", "PASS_MAX_DAYS   90", contents)
        contents = re.sub(r"PASS_WARN_AGE\s+(\d+)", "PASS_WARN_AGE   14", contents)
        print("Set PASS_MIN_DAYS to 2")
        print("Set PASS_MAX_DAYS to 90")
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

print("\nConfiguring /etc/pam.d/common-password...")
try:
    with open("/etc/pam.d/common-password", 'r+') as f:
        contents = f.read()
        
        # Ubuntu Key #8 / Mint Key #11: Add minlen=10 to pam_pwquality
        if re.search(r"pam_pwquality\.so", contents):
            if not re.search(r"minlen=", contents):
                contents = re.sub(r"(pam_pwquality\.so.*)", r"\1 minlen=10", contents)
                print("Added minlen=10 to pam_pwquality.so")
        else:
            print("pam_pwquality.so not found, skipping minlen.")
            
        # Mint Key #12: Add remember=5 to pam_unix
        if re.search(r"pam_unix\.so", contents):
            if not re.search(r"remember=", contents):
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

print("\nConfiguring /etc/pam.d/common-auth...")
try:
    # Ubuntu Key #10 / Mint Key #14: Remove nullok
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


print("\nCreating faillock PAM configs (Ubuntu Key #9 / Mint Key #13)...")
# This is idempotent, running it multiple times is safe.
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

print("\nPython auth script finished.")
