#Tanner Cole
# Security Log Classifier
#Module 1: Python Scripting Fundamentals

# 1. Accessing The Log File
with open("logins.txt") as f:
    lines = f.readlines()

print(f"Loaded {len(lines)} login records.\n")

# 2. Initializing Log Counters
total_attempts = 0
successful_logins = 0
failed_logins = 0
internal_ips = 0
external_ips = 0

# (Stretch Goal) Failure Tracking for User and IP
failures_by_user = {}
failures_by_ip = {}

# 3. Processing each log entry
for line in lines:
    line = line.strip()
    if not line:
        continue  # skip empty lines

    parts = line.split()
    if len(parts) != 3:
        # Basic defensive coding; students don't *have* to do this
        continue

    username, ip, result = parts
    total_attempts += 1

   # Setting up counters to track Success and Failures
    if result == "SUCCESS":
        successful_logins += 1
    else:
        failed_logins += 1

        # Stretch Goal: tracking failures by individual user
        if username not in failures_by_user:
            failures_by_user[username] = 0
        failures_by_user[username] += 1

        # Stretch Goal: tracking failures by user IP
        if ip not in failures_by_ip:
            failures_by_ip[ip] = 0
        failures_by_ip[ip] += 1

    # Classify each IP as internal or external
    if ip.startswith("10.") or ip.startswith("192.168."):
        internal_ips += 1
    else:
        external_ips += 1

# 4. Print summary results
print("=== Login Summary ===")
print(f"Total login attempts: {total_attempts}")
print(f"Successful logins:    {successful_logins}")
print(f"Failed logins:        {failed_logins}")
print()
print(f"Internal IPs seen: {internal_ips}")
print(f"External IPs seen: {external_ips}")
print()

# 5. Stretch Goal: Brute Force Detection
print("=== Possible Brute-Force Indicators ===")
for user, count in failures_by_user.items():
    if count >= 3:
        print(f"User '{user}' had {count} failed logins.")

for ip, count in failures_by_ip.items():
    if count >= 3:
        print(f"IP '{ip}' had {count} failed logins.")

