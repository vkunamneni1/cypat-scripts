import os, re, subprocess

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
        contents = re.sub(r"PASS_MAX_DAYS\s+(\d+)", "PASS_MAX_DAYS   90", contents) # (Mint Key #7)
        contents = re.sub(r"PASS_WARN_AGE\s+(\d+)", "PASS_WARN_AGE   14", contents) # (Your script's value)
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
