

ip_alerts = {
    # "1.1.1.1" : set()
}

alerts = [
    # {"ip" : "1.1.1.1", 
    # "alert_type" : "SSH Login Threshold",
    # "attack_type" : "Possible brute-force attack",
    # "alert_data" : {"Failed SSH Logins" : 40, etc.},
    # "logs" : []}
]

correlated_alerts = []


def create_ip_alerts():
    return set()

def correlate_alerts(alerts):
    
    for alert in alerts:

        if alert["ip"] not in ip_alerts:
            ip_alerts[alert["ip"]] = create_ip_alerts()

        ip_alerts[alert["ip"]].add(alert["alert_type"])
    
    for ip in ip_alerts:
        if len(ip_alerts[ip]) > 0:
            all_attacks = ip_alerts[ip]
            if "Unique 404 Threshold Reached" in all_attacks:
                recon = "Unique 404 Threshold Reached" 
            elif "HTTP 400 Threshold Reached" in all_attacks:
                recon = "HTTP 400 Threshold Reached"
            else:
                recon = "No Recon"

            if "Accepted SSH Login and SSH Failed Login Threshold Reached" in all_attacks:
                attack = "SSH Failed Login Threshold Reached"
                breach = "Accepted SSH Login"
            elif "SSH Failed Login Threshold Reached" in all_attacks:
                attack = "SSH Failed Login Threshold Reached"
                breach = "No SSH Breach"
            else:
                attack = "No Attack"
                breach = "No SSH Breach"
            
            correlated_alerts.append({"ip" : ip, "recon" : recon, "attack": attack, "breach" : breach}) 

    return correlated_alerts 
            