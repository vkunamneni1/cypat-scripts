import os, re, subprocess

# make sure running as admin
if os.geteuid() != 0:
    print("Please run as root...")
    exit()

print("Setting a min/max/warn password age...")
with open("/etc/login.defs", 'r+') as e:
    contents = e.read()
    min_age = re.search(r"PASS_MIN_DAYS\s+(\d+)", contents).group().split()[1]
    max_age = re.search(r"PASS_MAX_DAYS\s+(\d+)", contents).group().split()[1]
    warn_age = re.search(r"PASS_WARN_AGE\s+(\d+)", contents).group().split()[1]
    print(f"Current min age: {min_age}")
    print(f"Current max age: {max_age}")
    print(f"Current warn age: {warn_age}")
    contents = re.sub(r"PASS_MIN_DAYS\s+(\d+)", f"PASS_MIN_DAYS 7", contents)
    contents = re.sub(r"PASS_MAX_DAYS\s+(\d+)", f"PASS_MAX_DAYS 90", contents)
    contents = re.sub(r"PASS_WARN_AGE\s+(\d+)", f"PASS_WARN_AGE 14", contents)
    print(f"Changed min age to 7")
    print(f"Changed max age to 90")
    print(f"Changed min age to 14")
    print("\nAdding some more changes to login.defs...")
    contents = re.sub(r"FAILLOG_ENAB\s+(yes|no)", f"FAILLOG_ENAB yes", contents)
    contents = re.sub(r"LOG_UNKFAIL_ENAB\s+(yes|no)", f"LOG_UNKFAIL_ENAB yes", contents)
    contents = re.sub(r"SYSLOG_SU_ENAB\s+(yes|no)", f"SYSLOG_SU_ENAB yes", contents)
    contents = re.sub(r"SYSLOG_SG_ENAB\s+(yes|no)", f"SYSLOG_SG_ENAB yes", contents)
    print(contents)
    e.seek(0)
    e.write(contents)
    e.close()

print("Adding a minimum password length...")
with open("/etc/pam.d/common-password", 'r+') as e:
    contents = e.read()
    contents = re.sub(r"pam.pwquality\.so.*\n", f"pam_pwquality.so retry=3 minlen=10\n", contents)
    unix = re.search(r'(pam_unix\.so.*)', contents).group(0)
    contents = re.sub(r"(pam_unix\.so.*\n)", f"{unix} remember=5 minlen=10\n", contents)
    print("Adding cracklib... Please ensure that cracklib installs correctly.")
    e.seek(0)
    e.write(contents)
    e.close()


print("Adding a faillock cuz i hate myself...")
with open('/usr/share/pam-configs/faillock', 'w+') as e:
    contents = """Name: Enforce failed login attempt counter
Default: no
Priority: 0
Auth-Type: Primary
Auth:
    [default=die] pam_faillock.so authfail
    sufficient pam_faillock.so authsucc
"""
    e.write(contents)
    e.close()

with open('/usr/share/pam-configs/faillock_notify', 'w+') as e:
    contents = """Name: Notify on failed login attempts
Default: no
Priority: 1024
Auth-Type: Primary
Auth:
    requisite pam_faillock.so preauth
"""
    e.write(contents)
    e.close()
