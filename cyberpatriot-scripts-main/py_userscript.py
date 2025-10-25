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

admins_passwords = contents[admin_index + 1:user_index-1]
users = contents[user_index + 1:]

admins_passwords[0] = admins_passwords[0].removesuffix(" (you)")
for i in range(1, len(admins_passwords), 2):
    admins_passwords[i] = re.sub(r".*password: ", "", admins_passwords[i])
admins = admins_passwords[::2]

users.extend(admins)

print(users)

print("\nChecking users on/off system...")
usernames = []
with open('/etc/passwd', 'r') as f:
    for line in f:
        parts = line.split(':')
        if len(parts) > 3 and re.match(r'^\d{4}$', parts[2]):
            usernames.append(parts[0])

for name in usernames:
    if name not in users:
        print(f"Found unauthorized user {name}...", end=" ")
        i = input("Delete user? (Y/n): ")
        if i.lower() == "y":
            os.system(f"sudo userdel -r {name}")
            print(f"Deleted user {name}...")
        else:
            print(f"User {name} not deleted...")

for name in users:
    if name not in usernames:
        print(f"Found missing user {name}...", end=" ")
        i = input("Create user? (Y/n): ")
        if i.lower() == "y":
            os.system(f"sudo useradd {name}")
            print(f"Created user {name}... (make sure to add user to groups)")
        else:
            print(f"User {name} not created...")

print("\nChecking admin permissions...")
for name in users:
    name_has_admin = "sudo" in subprocess.check_output(["groups", name], text=True).split()
    if name in admins and not name_has_admin:
        print(f"User {name} is an admin but does not have sudo permissions...", end=" ")
        i = input("Add sudo permissions? (Y/n): ")
        if i.lower() == "y":
            os.system(f"sudo usermod -aG sudo {name}")
            print(f"Added sudo permissions to user {name}...")
        else:
            print(f"User {name} does not have sudo permissions...")
    if name not in admins and name_has_admin:
        print(f"User {name} is not an admin but has sudo permissions...", end=" ")
        i = input("Remove sudo permissions? (Y/n): ")
        if i.lower() == "y":
            os.system(f"sudo deluser {name} sudo")
            print(f"Removed sudo permissions from user {name}...")
        else:
            print(f"User {name} has sudo permissions...")

print("\nChecking for password quality...")
for name, password in zip(admins, admins_passwords[1::2]):
    if len(password) < 8 or not re.search(r"[A-Z]", password) or not re.search(r"[a-z]", password) or not re.search(r"[0-9]", password) or not re.search(r"[!@#$%^&*]", password):
        print(f"Admin {name} may have a weak password...", end=" ")
        i = input("Change password? (Y/n): ")
        if i.lower() == "y":
            os.system(f"sudo passwd {name}")
            print(f"Changed password for admin {name}...")
        else:
            print(f"Admin {name} has a weak password...")
