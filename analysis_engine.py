

ip_events_counter = {

    # "1.1.1.1" : {
    #             "400 ERRORS" : 0,
    #             "Failed SSH Logins" : 0,
    #         }

    # "1.1.1.1" : {
    #             "sudo commands" : 0
    #         }
    
}

sudo_events_counter = {

    # "user" : {"sudo commands" : 0 }

}

ip_events = {
    
}

sudo_events = {

}

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

    
    if parsed_log["source"] == "auth" and parsed_log["service"] == "sshd":
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


    if parsed_log["source"] == "auth" and parsed_log["service"] == "sudo":
        user = parsed_log["user"]

        if user not in sudo_events:
            sudo_events[user] = []

        sudo_events[user].append(parsed_log)

        if user not in sudo_events_counter:
            sudo_events_counter[user] = {
                "sudo commands" : 0
            }
        
        sudo_events_counter[user]["sudo commands"] += 1


## Separate ip reports and user reports
def write_report():

    with open("reports/ip_reports", "a") as file:
        for ip in ip_events_counter:
            file.write(f"{str(ip)} - - {str(ip_events_counter[ip])}\n")

    with open("reports/sudo_reports", "a") as file:
        for user in sudo_events_counter:
            file.write(f"{str(user)} - - {str(sudo_events_counter[user])}\n")