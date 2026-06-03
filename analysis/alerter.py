import json

with open("analysis/config.json", "r") as json_file:
    config = json.load(json_file)

ssh_failed_threshold = config["ssh_failed_threshold"]
http_400_threshold = config["http_400_threshold"]
unique_404_threshold = config["unique_404_threshold"]
sudo_threshold = config["sudo_threshold"]
http_404_timeframe = config["404_error_timeframe"]
sudo_commands_timeframe = config["sudo_commands_timeframe"]

alerts = [
    # {"ip" : "1.1.1.1", 
    # "alert_type" : "SSH Login Threshold",
    # "attack_type" : "Possible brute-force attack",
    # "alert_data" : {"Failed SSH Logins" : 40, etc.},
    # "logs" : []}
]

def detect_threats(analysis_data):
    ip_events_counter = analysis_data["ip_events_counter"]
    ip_events = analysis_data["ip_events"]
    alert_data = {}

    for ip in ip_events_counter:

        if ip_events_counter[ip]["400 Errors"] > http_400_threshold and len(ip_events_counter[ip]["Tracked 404s"]) > unique_404_threshold:
            alert_type = "Unqiue 404 Threshold Reached"
            attack_type = "Possible Web Scan"
            alert_data["400 Errors"] = ip_events_counter[ip]["400 Errors"]
            alert_data["Unqiue 404 Errors"] = len(ip_events_counter[ip]["Tracked 404s"])
            alert_data["Max 404s in Timeframe"] = (ip_events_counter[ip]["Max 404s in Timeframe"], http_404_timeframe)

            alerts.append({"ip": ip, "alert_type" : alert_type, "attack_type" : attack_type, "alert_data" : alert_data, "logs" : ip_events[ip]})
            alert_data = {}

        
        elif ip_events_counter[ip]["400 Errors"] > http_400_threshold:
            alert_type = "HTTP 400 Threshold Reached"
            attack_type = "Possible Web Scan"
            alert_data["400 Errors"] = ip_events_counter[ip]["400 Errors"]

            alerts.append({"ip": ip, "alert_type" : alert_type, "attack_type" : attack_type, "alert_data" : alert_data, "logs" : ip_events[ip]})
            alert_data = {}
        
        
        if ip_events_counter[ip]["Failed SSH Logins"] > ssh_failed_threshold and ip_events_counter[ip]["Successful SSH Logins"] > 0:
            count = max_count_till_login(ip, ip_events)
            alert_type = "Accepted SSH Login and SSH Failed Login Threshold Reached"
            attack_type = "Possible SSH Breach"
            alert_data["Failed SSH Logins"] = ip_events_counter[ip]["Failed SSH Logins"]
            alert_data["Successful SSH Logins"] = ip_events_counter[ip]["Successful SSH Logins"]
            alert_data["Failures Untill Login"] = count

            alerts.append({"ip": ip, "alert_type" : alert_type, "attack_type" : attack_type, "alert_data" : alert_data, "logs" : ip_events[ip]})
            alert_data = {}

        
        elif ip_events_counter[ip]["Failed SSH Logins"] > ssh_failed_threshold:
            alert_type = "SSH Failed Login Threshold Reached"
            attack_type = "Possible Brute-Force Attack"
            alert_data["Failed SSH Logins"] = ip_events_counter[ip]["Failed SSH Logins"]

            alerts.append({"ip": ip, "user": None, "alert_type" : alert_type, "attack_type" : attack_type, "alert_data" : alert_data, "logs" : ip_events[ip]})
            alert_data = {}
    
    
    sudo_events_counter = analysis_data["sudo_events_counter"]
    sudo_events = analysis_data["sudo_events"]


    for user in sudo_events_counter:
        if sudo_events_counter[user]["sudo commands"] > sudo_threshold:
            alert_type = "Sudo Command Threshold Reached"
            alert_data["Max Sudo Commands in Timeframe"] = (sudo_events_counter[user]["Max Sudo Commands in Timeframe"], sudo_commands_timeframe)
            attack_type = "Possible Suspicious Administrator Activity"
            alert_data["Sudo commands"] = sudo_events_counter[user]["sudo commands"]

            alerts.append({"ip" : None, "user" : user, "alert_type" : alert_type, "attack_type" : attack_type, "alert_data" : alert_data, "logs" : sudo_events[user]})
            alert_data = {}
    
    return alerts


def max_count_till_login(ip, ip_events):
    count = 0
    max_failures = 0
    for parsed_log in ip_events[ip]:
        if parsed_log["source"] == "auth" and parsed_log["service"] == "sshd":
            if parsed_log["event_type"] == "Failed password" or parsed_log["event_type"] == "Invalid user":
                count += 1
            if parsed_log["event_type"] == "Accepted password":
                max_failures = max(count, max_failures)
                count = 0
    return max_failures