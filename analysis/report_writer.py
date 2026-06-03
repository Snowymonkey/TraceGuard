def write_logs(analysis_data):
    clear_logs()

    ip_events_counter = analysis_data["ip_events_counter"]
    sudo_events_counter = analysis_data["sudo_events_counter"]

    with open("reports/ip_logs", "a") as file:
        for ip in ip_events_counter:
            file.write(f"{str(ip)} - - {str(ip_events_counter[ip])}\n")

    with open("reports/sudo_logs", "a") as file:
        for user in sudo_events_counter:
            file.write(f"{str(user)} - - {str(sudo_events_counter[user])}\n")

def write_reports(alerts):
    clear_reports()
    write_http_reports(alerts)
    write_sudo_reports(alerts)


def write_http_reports(alerts):

    with open("reports/ip_reports", "a") as file:
        for alert in alerts:
           if alert["user"] is None:
                ## Write Log Title
                file.write(f"ALERT - {alert["alert_type"]} - {alert["ip"]}\n\n")

                ## Write Log Data (Statistics)
                for type, data in alert["alert_data"].items():
                    if type == "400 Errors":
                        file.write(f"400 Errors : {data}\n")
                    elif type == "Unqiue 404 Errors":
                        file.write(f"Unique 404 Errors : {data}\n")
                    elif type == "Max 404s in Timeframe":
                        file.write(f"{data[0]} 404s in {data[1]} Seconds\n")
                    elif type == "Failed SSH Logins":
                        file.write(f"Failed SSH Logins : {data}\n")
                    elif type == "Successful SSH Logins":
                        file.write(f"Accepted SSH Logins : {data}\n")
                    elif type == "Failures Untill Login":
                        file.write(f"{data} Failures Until Succesful Login\n")
                file.write(alert["attack_type"] + "\n\n")

                ## Write log history
                for parsed_log in alert["logs"]:
                    if parsed_log["source"] == "Apache":
                        file.write(build_http_log(parsed_log))
                    elif parsed_log["source"] == "auth" and parsed_log["service"] == "sshd":
                        file.write(build_ssh_log(parsed_log))
                file.write("\n————————————————————————————————————————————————————\n\n")

def write_sudo_reports(alerts):

    with open("reports/sudo_reports", "a") as file:
        for alert in alerts:
           if alert["ip"] is None:
                ## Write Log Title
                file.write(f"ALERT - {alert["alert_type"]} - {alert["user"]}\n\n")

                ## Write Log Data (Statistics)
                for type, data in alert["alert_data"].items():
                    if type == "Sudo commands":
                        file.write(f"Made {data} Total Sudo Commands\n")
                    elif type == "Max Sudo Commands in Timeframe":
                        file.write(f"{data[0]} Sudo Commands in {data[1]} Seconds\n")
                file.write(alert["attack_type"] + "\n\n")

                ## Write log history
                for parsed_log in alert["logs"]:
                    if parsed_log["source"] == "auth" and parsed_log["service"] == "sudo":
                        file.write(build_sudo_log(parsed_log))
                file.write("\n————————————————————————————————————————————————————\n\n")


def build_ssh_log(parsed_log):
    return parsed_log["date"] + " " + parsed_log["time"] + " " + parsed_log["event_type"] + " on user: " + parsed_log["target_username"] + '\n'

def build_http_log(parsed_log):
    return parsed_log["date"] + " " + parsed_log["time"] + " " + parsed_log["request"] + " - Response: " + parsed_log["response_code"] + '\n'

def build_sudo_log(parsed_log):
    return parsed_log["date"] + " " + parsed_log["time"] + " " + parsed_log["command"] + "\n"

def clear_reports():
    open("reports/ip_reports", "w").close()
    open("reports/sudo_reports", "w").close()

def clear_logs():
    open("reports/ip_logs", "w").close()
    open("reports/sudo_logs", "w").close()
