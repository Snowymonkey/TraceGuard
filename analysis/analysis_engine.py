import json

ip_events_counter = {}
sudo_events_counter = {}

ip_events = {}
sudo_events = {}

with open("analysis/config.json", "r") as json_file:
    config = json.load(json_file)

ssh_failed_threshold = config["ssh_failed_threshold"]
http_400_threshold = config["http_400_threshold"]
sudo_threshold = config["sudo_threshold"]

def process(parsed_log):

    if parsed_log["source"] == "Apache":
        ip = parsed_log["ip"]

        if ip not in ip_events:
            ip_events[ip] = []

        ip_events[ip].append(parsed_log)

        if ip not in ip_events_counter:
            ip_events_counter[ip] = {
                "400 ERRORS" : 0,
                "Failed SSH Logins" : 0,
            }

        if parsed_log["response_code"][0] == "4":
            ip_events_counter[ip]["400 ERRORS"] += 1

    
    elif parsed_log["source"] == "auth" and parsed_log["service"] == "sshd":
        ip = parsed_log["ip"]

        if ip not in ip_events:
            ip_events[ip] = []

        ip_events[ip].append(parsed_log)

        if ip not in ip_events_counter:
            ip_events_counter[ip] = {
                "400 ERRORS" : 0,
                "Failed SSH Logins" : 0,
            }
        
        event_type = parsed_log["event_type"]

        if event_type == "Failed password" or event_type == "Invalid user":
            ip_events_counter[ip]["Failed SSH Logins"] += 1


    elif parsed_log["source"] == "auth" and parsed_log["service"] == "sudo":
        user = parsed_log["user"]

        if user not in sudo_events:
            sudo_events[user] = []

        sudo_events[user].append(parsed_log)

        if user not in sudo_events_counter:
            sudo_events_counter[user] = {
                "sudo commands" : 0
            }
        
        sudo_events_counter[user]["sudo commands"] += 1

def write_logs():

    with open("reports/ip_log", "a") as file:
        for ip in ip_events_counter:
            file.write(f"{str(ip)} - - {str(ip_events_counter[ip])}\n")

    with open("reports/sudo_log", "a") as file:
        for user in sudo_events_counter:
            file.write(f"{str(user)} - - {str(sudo_events_counter[user])}\n")

def write_report():

    for ip in ip_events_counter:
        if ip_events_counter[ip]["400 ERRORS"] > http_400_threshold:
            with open("reports/ip_reports", "w") as file:
                file.write(f"ALERT - HTTP 400 Threshold Reached - {ip}\n\n")
                file.write(f"400 ERRORS : {ip_events_counter[ip]["400 ERRORS"]}\n")
                file.write("Possible web scan\n\n")
                file.write("————————————————————————————————————————————————————\n\n")
        
        if ip_events_counter[ip]["Failed SSH Logins"] > ssh_failed_threshold:
            with open("reports/ip_reports", "w") as file:
                file.write(f"ALERT - SSH Failed Login Threshold Reached - {ip}\n\n")
                file.write(f"Failed SSH Logins : {ip_events_counter[ip]["Failed SSH Logins"]}\n")
                file.write("Possible brute-force attack\n\n")
                file.write("————————————————————————————————————————————————————\n\n")

    for user in sudo_events_counter:
        if sudo_events_counter[user]["sudo commands"] > sudo_threshold:
            with open("reports/sudo_reports", "w") as file:
                file.write(f"ALERT - Sudo Command Threshold Reached - {user}\n\n")
                file.write(f"Sudo commands : {sudo_events_counter[user]["sudo commands"]}\n")
                file.write("Possible suspicious administrator activity\n\n")
                file.write("————————————————————————————————————————————————————\n\n")