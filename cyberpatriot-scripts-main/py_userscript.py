import re, os, subprocess

print("Copy-paste the text from the \"Authorized Administrators and Users\" section...(Ctrl+D to finish)")
contents = []
while True:
    try:
        line = input()
    except EOFError:
        break
    contents.append(line)

try:
    admin_index = contents.index("Authorized Administrators:")
    user_index = contents.index("Authorized Users:")
except ValueError:
    raise ValueError("Could not find the \"Authorized Administrators\" and \"Authorized Users\" sections in the input. Ensure you copied the correct section...")

# Handle potential empty lines between sections
admins_passwords_raw = contents[admin_index + 1:user_index]
admins_passwords = [line for line in admins_passwords_raw if line.strip()] # Remove empty lines

users_raw = contents[user_index + 1:]
users = [line for line in users_raw if line.strip()] # Remove empty lines

if not admins_passwords:
    raise ValueError("No administrators found under 'Authorized Administrators:'. Check your copy-paste.")

admins_passwords[0] = admins_passwords[0].removesuffix(" (you)")

admins = []
passwords = []
# Parse admins and passwords, skipping every other line
for i in range(0, len(admins_passwords), 2):
    admins.append(admins_passwords[i].strip())
    if i + 1 < len(admins_passwords):
        # Extract password
        pw_line = admins_passwords[i+1]
        pw_match = re.search(r"password:\s*(.*)", pw_line)
        if pw_match:
            passwords.append(pw_match.group(1).strip())
        else:
            passwords.append(None) # Handle case where password line is malformed
    else:
        passwords.append(None) # Handle case of missing password line

users.extend(admins)
# Clean up whitespace from user list
users = [user.strip() for user in users if user.strip()]
admins = [admin.strip() for admin in admins if admin.strip()]


print("\n--- Authorized User List ---")
print(users)
print("\n--- Authorized Admin List ---")
print(admins)


print("\n[+] Checking users on/off system...")
usernames = []
try:
    with open('/etc/passwd', 'r') as f:
        for line in f:
            parts = line.split(':')
            # Check for standard user UIDs (>= 1000)
            if len(parts) > 3 and parts[2].isdigit() and int(parts[2]) >= 1000:
                usernames.append(parts[0])
except FileNotFoundError:
    print("ERROR: Could not read /etc/passwd. Exiting.")
    exit(1)
except Exception as e:
    print(f"ERROR: An unexpected error occurred reading /etc/passwd: {e}")
    exit(1)

for name in usernames:
    if name not in users:
        print(f"\nFound unauthorized user: {name}")
        i = input(f"  -> Delete user '{name}' and their home directory? (y/N): ")
        if i.lower() == "y":
            try:
                subprocess.run(["sudo", "userdel", "-r", name], check=True)
                print(f"  SUCCESS: Deleted user {name}.")
            except subprocess.CalledProcessError as e:
                print(f"  ERROR: Failed to delete user {name}. {e}")
        else:
            print(f"  SKIPPED: User {name} not deleted.")

for name in users:
    if name not in usernames:
        print(f"\nFound missing authorized user: {name}")
        i = input(f"  -> Create user '{name}'? (y/N): ")
        if i.lower() == "y":
            try:
                # Create user with home directory and default shell
                subprocess.run(["sudo", "useradd", "-m", "-s", "/bin/bash", name], check=True)
                print(f"  SUCCESS: Created user {name}. Set password immediately.")
            except subprocess.CalledProcessError as e:
                print(f"  ERROR: Failed to create user {name}. {e}")
        else:
            print(f"  SKIPPED: User {name} not created.")

print("\n[+] Checking admin permissions...")
for name in users:
    if name not in usernames:
        print(f"\nSkipping admin check for '{name}' (user does not exist).")
        continue
    
    try:
        user_groups_output = subprocess.check_output(["groups", name], text=True)
        user_groups = user_groups_output.split()
        name_has_admin = "sudo" in user_groups or "admin" in user_groups
    except subprocess.CalledProcessError as e:
        print(f"  ERROR: Could not get groups for user {name}. Skipping. {e}")
        continue

    if name in admins and not name_has_admin:
        print(f"\nUser '{name}' IS an admin but LACKS admin permissions.")
        i = input(f"  -> Add user '{name}' to 'sudo' group? (y/N): ")
        if i.lower() == "y":
            try:
                subprocess.run(["sudo", "usermod", "-aG", "sudo", name], check=True)
                print(f"  SUCCESS: Added '{name}' to 'sudo' group.")
            except subprocess.CalledProcessError as e:
                print(f"  ERROR: Failed to add '{name}' to sudo group. {e}")
        else:
            print(f"  SKIPPED: User '{name}' does not have admin permissions.")
            
    if name not in admins and name_has_admin:
        print(f"\nUser '{name}' is NOT an admin but HAS admin permissions.")
        i = input(f"  -> Remove user '{name}' from 'sudo' group? (y/N): ")
        if i.lower() == "y":
            try:
                subprocess.run(["sudo", "deluser", name, "sudo"], check=True)
                print(f"  SUCCESS: Removed '{name}' from 'sudo' group.")
            except subprocess.CalledProcessError as e:
                print(f"  ERROR: Failed to remove '{name}' from sudo group. {e}")
        else:
            print(f"  SKIPPED: User '{name}' still has admin permissions.")

print("\n[+] Checking for weak passwords...")
for name, password in zip(admins, passwords):
    if name not in usernames:
        continue # Skip users that don't exist
        
    if password is None:
        print(f"\nWARN: Could not parse password for admin '{name}'. Check manually.")
        continue

    is_weak = False
    if len(password) < 10: is_weak = True
    if not re.search(r"[A-Z]", password): is_weak = True
    if not re.search(r"[a-z]", password): is_weak = True
    if not re.search(r"[0-9]", password): is_weak = True
    if not re.search(r"[!@#$%^&*()\[\]{},.?~_\-+=|\\:;']", password): is_weak = True
    
    if is_weak:
        print(f"\nAdmin '{name}' has a weak password ('{password}').")
        i = input(f"  -> Force password change for '{name}'? (y/N): ")
        if i.lower() == "y":
            try:
                # Force user to change password on next login
                subprocess.run(["sudo", "passwd", "-e", name], check=True)
                print(f"  SUCCESS: User '{name}' will be forced to change password on next login.")
            except subprocess.CalledProcessError as e:
                print(f"  ERROR: Failed to expire password for '{name}'. {e}")
        else:
            print(f"  SKIPPED: User '{name}' still has a weak password.")

print("\n--- Python user script finished. ---")
