import json


ip_events_counter = {}
sudo_events_counter = {}

ip_events = {}
sudo_events = {}

with open("analysis/config.json", "r") as json_file:
    config = json.load(json_file)

ssh_failed_threshold = config["ssh_failed_threshold"]
http_400_threshold = config["http_400_threshold"]
unique_404_threshold = config["unique_404_threshold"]
sudo_threshold = config["sudo_threshold"]

def create_ip_event_counter():
    return {
                "400 Errors" : 0,
                "Tracked 404s" : set(),
                "Unique 404 Count" : 0,
                "Failed SSH Logins" : 0,
                "Successful SSH Logins" : 0
            }

def create_sudo_event_counter():
    return {
                "sudo commands" : 0
            }

def process(parsed_log):

    if parsed_log["source"] == "Apache":
        ip = parsed_log["ip"]

        if ip not in ip_events:
            ip_events[ip] = []

        ip_events[ip].append(parsed_log)

        if ip not in ip_events_counter:
            ip_events_counter[ip] = create_ip_event_counter()

        response_code = parsed_log["response_code"]

        if response_code[0] == "4":
            ip_events_counter[ip]["400 Errors"] += 1

            if response_code == "404":
                if parsed_log["request"] not in ip_events_counter[ip]["Tracked 404s"]:
                    ip_events_counter[ip]["Tracked 404s"].add(parsed_log["request"])
                    ip_events_counter[ip]["Unique 404 Count"] += 1

    
    elif parsed_log["source"] == "auth" and parsed_log["service"] == "sshd":
        ip = parsed_log["ip"]

        if ip not in ip_events:
            ip_events[ip] = []

        ip_events[ip].append(parsed_log)

        if ip not in ip_events_counter:
            ip_events_counter[ip] = create_ip_event_counter()
        
        event_type = parsed_log["event_type"]

        if event_type == "Failed password" or event_type == "Invalid user":
            ip_events_counter[ip]["Failed SSH Logins"] += 1
        
        if event_type == "Accepted password":
            ip_events_counter[ip]["Successful SSH Logins"] += 1


    elif parsed_log["source"] == "auth" and parsed_log["service"] == "sudo":
        user = parsed_log["user"]

        if user not in sudo_events:
            sudo_events[user] = []

        sudo_events[user].append(parsed_log)

        if user not in sudo_events_counter:
            sudo_events_counter[user] = create_sudo_event_counter()
        
        sudo_events_counter[user]["sudo commands"] += 1

def write_logs():

    with open("reports/ip_log", "w") as file:
        for ip in ip_events_counter:
            file.write(f"{str(ip)} - - {str(ip_events_counter[ip])}\n")

    with open("reports/sudo_log", "w") as file:
        for user in sudo_events_counter:
            file.write(f"{str(user)} - - {str(sudo_events_counter[user])}\n")

def write_report():

    for ip in ip_events_counter:
        if ip_events_counter[ip]["400 Errors"] > http_400_threshold and ip_events_counter[ip]["Unique 404 Count"] > unique_404_threshold:
            with open("reports/ip_reports", "w") as file:
                file.write(f"ALERT - Unqiue 404 Threshold Reached - {ip}\n\n")
                file.write(f"400 Errors : {ip_events_counter[ip]["400 Errors"]}\n")
                file.write(f"Unique 404 Errors : {ip_events_counter[ip]["Unique 404 Count"]}\n")
                file.write("Possible web scan\n\n")
                for parsed_log in ip_events[ip]:
                    file.write(build_http_log(parsed_log))
                file.write("\n————————————————————————————————————————————————————\n\n")
        elif ip_events_counter[ip]["400 Errors"] > http_400_threshold:
            with open("reports/ip_reports", "a") as file:
                file.write(f"ALERT - HTTP 400 Threshold Reached - {ip}\n\n")
                file.write(f"400 Errors : {ip_events_counter[ip]["400 Errors"]}\n")
                file.write("Possible web scan\n\n")
                for parsed_log in ip_events[ip]:
                    file.write(build_http_log(parsed_log))
                file.write("\n————————————————————————————————————————————————————\n\n")
        
        if ip_events_counter[ip]["Failed SSH Logins"] > ssh_failed_threshold and ip_events_counter[ip]["Successful SSH Logins"] > 0:
            with open("reports/ip_reports", "a") as file:
                file.write(f"ALERT - Accepted SSH Login and SSH Failed Login Threshold Reached - {ip}\n\n")
                file.write(f"Failed SSH Logins : {ip_events_counter[ip]["Failed SSH Logins"]}\n")
                file.write(f"Accepted SSH Logins : {ip_events_counter[ip]["Successful SSH Logins"]}\n")
                file.write("Possible SSH breach\n\n")
                for parsed_log in ip_events[ip]:
                    file.write(build_ssh_log(parsed_log))
                file.write("\n————————————————————————————————————————————————————\n\n")

        elif ip_events_counter[ip]["Failed SSH Logins"] > ssh_failed_threshold:
            with open("reports/ip_reports", "a") as file:
                file.write(f"ALERT - SSH Failed Login Threshold Reached - {ip}\n\n")
                file.write(f"Failed SSH Logins : {ip_events_counter[ip]["Failed SSH Logins"]}\n")
                file.write("Possible brute-force attack\n\n")
                for parsed_log in ip_events[ip]:
                    file.write(build_ssh_log(parsed_log))
                file.write("\n————————————————————————————————————————————————————\n\n")

    for user in sudo_events_counter:
        if sudo_events_counter[user]["sudo commands"] > sudo_threshold:
            with open("reports/sudo_reports", "w") as file:
                file.write(f"ALERT - Sudo Command Threshold Reached - {user}\n\n")
                file.write(f"Sudo commands : {sudo_events_counter[user]["sudo commands"]}\n")
                file.write("Possible suspicious administrator activity\n\n")
                file.write("————————————————————————————————————————————————————\n\n")

def build_ssh_log(parsed_log):
    return parsed_log["date"] + " " + parsed_log["time"] + " " + parsed_log["event_type"] + " on user: " + parsed_log["target_username"] + '\n'

def build_http_log(parsed_log):
    return parsed_log["date"] + " " + parsed_log["time"] + " " + parsed_log["request"] + " - Response: " + parsed_log["response_code"] + '\n'
