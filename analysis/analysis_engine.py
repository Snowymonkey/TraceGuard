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

http_404_timeframe = config["404_error_timeframe"]
sudo_commands_timeframe = config["sudo_commands_timeframe"]

def create_ip_event_counter():
    return {
                "400 Errors" : 0,
                "Tracked 404s" : set(),
                "Start 404 Error Time" : None,
                "Max 404s in Timeframe" : 0,
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
        "Start Sudo Timeframe" : None,
        "Current Sudo Commands in Timeframe" : 0
    }

def create_sudo_event_counter():
    return {
                "sudo commands" : 0,
                "Max Sudo Commands in Timeframe" : 0,
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
                    ip_timeframe[ip]["Current 404s in Timeframe"] = 1
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

        if user not in sudo_timeframe:
            sudo_timeframe[user] = create_sudo_timeframe()

        curr_log_time = datetime.strptime(parsed_log["time"], time_format)
        start_log_time = sudo_timeframe[user]["Start Sudo Timeframe"]

        if start_log_time is None:
            sudo_timeframe[user]["Current Sudo Commands in Timeframe"] += 1
            sudo_timeframe[user]["Start Sudo Timeframe"] = curr_log_time

        elif (curr_log_time - start_log_time).total_seconds() > sudo_commands_timeframe:
            sudo_timeframe[user]["Start Sudo Timeframe"] = curr_log_time
            sudo_events_counter[user]["Max Sudo Commands in Timeframe"] = max(sudo_events_counter[user]["Max Sudo Commands in Timeframe"], sudo_timeframe[user]["Current Sudo Commands in Timeframe"])
            sudo_timeframe[user]["Current Sudo Commands in Timeframe"] = 1
        else:
            sudo_timeframe[user]["Current Sudo Commands in Timeframe"] += 1

def clear_analysis_data():
    ip_events = {}
    sudo_events = {}

    ip_events_counter = {}
    sudo_events_counter = {}

    ip_timeframe = {}
    sudo_timeframe = {}

def pass_analysis_data():
    return {
        "ip_events_counter" : ip_events_counter,
        "ip_events" : ip_events,
        "ip_timeframe" : ip_timeframe,

        "sudo_events_counter" : sudo_events_counter,
        "sudo_events" : sudo_events,
        "sudo_timeframe" : sudo_timeframe,
    }