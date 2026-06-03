import json
from datetime import datetime

time_format = '%H:%M:%S'

## Suspicious event counter
ip_events_counter = {}
sudo_events_counter = {}

## Timeframes for suspicious activities
ip_timeframe = {}
sudo_timeframe = {}

## Overall Log
ip_events = {} 
sudo_events = {}

with open("analysis/config.json", "r") as json_file:
    config = json.load(json_file)

ssh_failed_threshold = config["ssh_failed_threshold"]
http_400_threshold = config["http_400_threshold"]
unique_404_threshold = config["unique_404_threshold"]
sudo_threshold = config["sudo_threshold"]
http_404_timeframe = config["404_error_timeframe"]

def create_ip_event_counter():
    return {
                "400 Errors" : 0,
                "Tracked 404s" : set(),
                "Start 404 Error Time" : None,
                "Max 404s in Timeframe" : 0,
                "Current 404s in Timeframe" : 0,
                "Failed SSH Logins" : 0,
                "Successful SSH Logins" : 0
            }

def create_ip_timeframe(): 
    return {
        "Start 404 Error Time" : None,
        "Current 404s in Timeframe" : 0
    }

def create_sudo_timeframe():
    return {
        "Start SSH Login Timeframe" : None,
        "Current SSH Logins in Timeframe" : 0
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
                
                if ip not in ip_timeframe:
                    ip_timeframe[ip] = create_ip_timeframe()

                curr_log_time = datetime.strptime(parsed_log["time"], time_format)
                start_log_time = ip_timeframe[ip]["Start 404 Error Time"]

                if start_log_time is None:
                    ip_timeframe[ip]["Current 404s in Timeframe"] += 1
                    ip_timeframe[ip]["Start 404 Error Time"] = curr_log_time

                elif (curr_log_time - start_log_time).total_seconds() > http_404_timeframe:
                    ip_timeframe[ip]["Start 404 Error Time"] = curr_log_time
                    ip_events_counter[ip]["Max 404s in Timeframe"] = max(ip_events_counter[ip]["Max 404s in Timeframe"], ip_timeframe[ip]["Current 404s in Timeframe"])
                    ip_timeframe[ip]["Current 404s in Timeframe"] = 1
                else:
                    ip_timeframe[ip]["Current 404s in Timeframe"] += 1
            

    
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

# def write_logs():
#     clear_logs()

#     with open("reports/ip_log", "a") as file:
#         for ip in ip_events_counter:
#             file.write(f"{str(ip)} - - {str(ip_events_counter[ip])}\n")

#     with open("reports/sudo_log", "a") as file:
#         for user in sudo_events_counter:
#             file.write(f"{str(user)} - - {str(sudo_events_counter[user])}\n")

# def write_report():
#     clear_reports()

#     for ip in ip_events_counter:
#         if ip_events_counter[ip]["400 Errors"] > http_400_threshold and len(ip_events_counter[ip]["Tracked 404s"]) > unique_404_threshold:
#             with open("reports/ip_reports", "a") as file:
#                 file.write(f"ALERT - Unqiue 404 Threshold Reached - {ip}\n\n")
#                 file.write(f"400 Errors : {ip_events_counter[ip]["400 Errors"]}\n")
#                 file.write(f"Unique 404 Errors : {len(ip_events_counter[ip]["Tracked 404s"])}\n")
#                 file.write(f"{max(ip_events_counter[ip]["Max 404s in Timeframe"], ip_events_counter[ip]["Current 404s in Timeframe"])} 404s in {http_404_timeframe} seconds\n")
#                 file.write("Possible web scan\n\n")
#                 for parsed_log in ip_events[ip]:
#                     file.write(build_http_log(parsed_log))
#                 file.write("\n————————————————————————————————————————————————————\n\n")
#         elif ip_events_counter[ip]["400 Errors"] > http_400_threshold:
#             with open("reports/ip_reports", "a") as file:
#                 file.write(f"ALERT - HTTP 400 Threshold Reached - {ip}\n\n")
#                 file.write(f"400 Errors : {ip_events_counter[ip]["400 Errors"]}\n")
#                 file.write("Possible web scan\n\n")
#                 for parsed_log in ip_events[ip]:
#                     file.write(build_http_log(parsed_log))
#                 file.write("\n————————————————————————————————————————————————————\n\n")
        
#         if ip_events_counter[ip]["Failed SSH Logins"] > ssh_failed_threshold and ip_events_counter[ip]["Successful SSH Logins"] > 0:
#             count = max_count_till_login(ip)
#             with open("reports/ip_reports", "a") as file:
#                 file.write(f"ALERT - Accepted SSH Login and SSH Failed Login Threshold Reached - {ip}\n\n")
#                 file.write(f"Failed SSH Logins : {ip_events_counter[ip]["Failed SSH Logins"]}\n")
#                 file.write(f"Accepted SSH Logins : {ip_events_counter[ip]["Successful SSH Logins"]}\n")
#                 file.write(f"{count} Failures Untill Succesful Login\n")
#                 file.write("Possible SSH breach\n\n")
#                 for parsed_log in ip_events[ip]:
#                     file.write(build_ssh_log(parsed_log))
#                 file.write("\n————————————————————————————————————————————————————\n\n")

#         elif ip_events_counter[ip]["Failed SSH Logins"] > ssh_failed_threshold:
#             with open("reports/ip_reports", "a") as file:
#                 file.write(f"ALERT - SSH Failed Login Threshold Reached - {ip}\n\n")
#                 file.write(f"Failed SSH Logins : {ip_events_counter[ip]["Failed SSH Logins"]}\n")
#                 file.write("Possible brute-force attack\n\n")
#                 for parsed_log in ip_events[ip]:
#                     file.write(build_ssh_log(parsed_log))
#                 file.write("\n————————————————————————————————————————————————————\n\n")

#     for user in sudo_events_counter:
#         if sudo_events_counter[user]["sudo commands"] > sudo_threshold:
#             with open("reports/sudo_reports", "a") as file:
#                 file.write(f"ALERT - Sudo Command Threshold Reached - {user}\n\n")
#                 file.write(f"Sudo commands : {sudo_events_counter[user]["sudo commands"]}\n")
#                 file.write("Possible suspicious administrator activity\n\n")
#                 file.write("————————————————————————————————————————————————————\n\n")

# def build_ssh_log(parsed_log):
#     return parsed_log["date"] + " " + parsed_log["time"] + " " + parsed_log["event_type"] + " on user: " + parsed_log["target_username"] + '\n'

# def build_http_log(parsed_log):
#     return parsed_log["date"] + " " + parsed_log["time"] + " " + parsed_log["request"] + " - Response: " + parsed_log["response_code"] + '\n'

# def clear_reports():
#     open("reports/ip_reports", "w").close()
#     open("reports/sudo_reports", "w").close()

# def clear_logs():
#     open("reports/ip_log", "w").close()
#     open("reports/sudo_log", "w").close()

# def max_count_till_login(ip):
#     count = 0
#     max_failures = 0
#     for parsed_log in ip_events[ip]:
#         if parsed_log["source"] == "auth" and parsed_log["service"] == "sshd":
#             if parsed_log["event_type"] == "Failed password" or parsed_log["event_type"] == "Invalid user":
#                 count += 1
#             if parsed_log["event_type"] == "Accepted password":
#                 max_failures = max(count, max_failures)
#                 count = 0
#     return max_failures

def pass_analysis_data():
    return {
        "ip_events_counter" : ip_events_counter,
        "ip_events" : ip_events,
        "ip_timeframe" : ip_timeframe,

        "sudo_events_counter" : sudo_events_counter,
        "sudo_events" : sudo_events,
        "sudo_timeframe" : sudo_timeframe,
    }