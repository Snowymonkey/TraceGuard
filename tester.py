# INTENDED TO BE USED WITH config.json CONFIGRUED AS:

# {
#     "ssh_failed_threshold" : 0,

#     "http_400_threshold" : 0,
#     "unique_404_threshold" : 0,
#     "404_error_timeframe" : 10,

#     "sudo_commands_timeframe" : 10,
#     "sudo_threshold" : 0,

#     "show_full_logs_on_alert" : true
# }

import datetime

from parsers.apache_analyzer import parse_apache
from parsers.linux_analyzer import parse_linux_auth
from parsers.sudo_analyzer import parse_sudo
from analysis.analysis_engine import process, pass_analysis_data
from analysis.alerter import detect_threats
from analysis.correlation_engine import correlate_alerts

parsed_logs = []

parsed_log = None

with open("tests/Bad-data-test", 'r', errors='ignore') as file:
    for line in file:

        if " - - " in line:         ## Apache log
            parsed_log = parse_apache(line)
            if parsed_log is not None and parsed_log["ip"] is None:
                parsed_log = None

        elif "sshd[" in line:       ## SSH log
            parsed_log = parse_linux_auth(line)
            if parsed_log is not None and parsed_log["ip"] is None:
                parsed_log = None                                                  

        elif "sudo" in line:       ## sudo log
            parsed_log = parse_sudo(line)
            if parsed_log is not None and parsed_log["user"] is None or parsed_log["command"] is None:
                parsed_log = None
        
        assert(parsed_log) == None

        parsed_log = None

print("\n -- PASSED BAD-DATA-TEST -- \n")

with open("tests/Apache-test", "r", errors="ignore") as file:
    for line in file:
        parsed_logs.append(parse_apache(line))

assert(parsed_logs) == [{'source': 'Apache', 'ip': '144.76.194.187', 'date': '17/May/2015', 'time': '13:05:28', 'request': 'GET /wp-login.php HTTP/1.0', 'response_code': '404'}, {'source': 'Apache', 'ip': '144.76.194.187', 'date': '17/May/2015', 'time': '13:05:37', 'request': 'GET /administrator/index.php HTTP/1.0', 'response_code': '404'}]
print("PASSED APACHE PARSER TEST")
parsed_logs = []

with open("tests/Command-test", "r", errors="ignore") as file:
   for line in file:
        parsed_logs.append(parse_sudo(line))

assert(parsed_logs) == [{'source': 'auth', 'date': 'Feb 10', 'time': '12:01:19', 'user': 'root', 'service': 'sudo', 'command': '/bin/ls', 'working_directory': '/home/ubuntu '}, {'source': 'auth', 'date': 'Feb 10', 'time': '12:01:20', 'user': 'root', 'service': 'sudo', 'command': '/bin/apt update', 'working_directory': '/home/ubuntu '}, {'source': 'auth', 'date': 'Feb 10', 'time': '12:01:21', 'user': 'root', 'service': 'sudo', 'command': '/bin/ls', 'working_directory': '/home/ubuntu '}, {'source': 'auth', 'date': 'Feb 10', 'time': '12:01:22', 'user': 'root', 'service': 'sudo', 'command': '/bin/apt update', 'working_directory': '/home/ubuntu '}, {'source': 'auth', 'date': 'Feb 10', 'time': '12:01:23', 'user': 'root', 'service': 'sudo', 'command': '/bin/ls', 'working_directory': '/home/ubuntu '}, {'source': 'auth', 'date': 'Feb 10', 'time': '12:01:24', 'user': 'root', 'service': 'sudo', 'command': '/bin/apt update', 'working_directory': '/home/ubuntu '}, {'source': 'auth', 'date': 'Feb 10', 'time': '12:01:25', 'user': 'root', 'service': 'sudo', 'command': '/bin/ls', 'working_directory': '/home/ubuntu '}, {'source': 'auth', 'date': 'Feb 10', 'time': '12:01:27', 'user': 'root', 'service': 'sudo', 'command': '/bin/apt update', 'working_directory': '/home/ubuntu '}, {'source': 'auth', 'date': 'Feb 10', 'time': '12:01:28', 'user': 'root', 'service': 'sudo', 'command': '/bin/ls', 'working_directory': '/home/ubuntu '}, {'source': 'auth', 'date': 'Feb 10', 'time': '12:01:30', 'user': 'root', 'service': 'sudo', 'command': '/bin/apt update', 'working_directory': '/home/ubuntu '}]
print("PASSED COMMAND PARSER TEST")
parsed_logs = []

with open("tests/Linux-test", "r", errors="ignore") as file:
    for line in file:
        parsed_logs.append(parse_linux_auth(line))

assert(parsed_logs) == [{'source': 'auth', 'date': 'Feb 10', 'time': '15:45:09', 'ip': '103.106.189.143', 'port': '60824', 'service': 'sshd', 'event_type': 'Failed password', 'target_username': 'root'}, {'source': 'auth', 'date': 'Feb 10', 'time': '15:45:11', 'ip': '103.106.189.143', 'port': '60824', 'service': 'sshd', 'event_type': 'Connection closed', 'target_username': 'root'}, {'source': 'auth', 'date': 'Feb 10', 'time': '15:45:11', 'ip': '180.101.88.228', 'port': '11349', 'service': 'sshd', 'event_type': 'Failed password', 'target_username': 'root'}, {'source': 'auth', 'date': 'Feb 10', 'time': '15:45:12', 'ip': '103.106.189.143', 'port': None, 'service': 'sshd', 'event_type': 'authentication failure', 'target_username': 'root'}, {'source': 'auth', 'date': 'Feb 10', 'time': '15:45:14', 'ip': '180.101.88.228', 'port': '11349', 'service': 'sshd', 'event_type': 'Failed password', 'target_username': 'root'}, {'source': 'auth', 'date': 'Feb 10', 'time': '15:45:14', 'ip': '103.106.189.143', 'port': '33990', 'service': 'sshd', 'event_type': 'Failed password', 'target_username': 'root'}, {'source': 'auth', 'date': 'Feb 10', 'time': '15:45:16', 'ip': '103.106.189.143', 'port': '33990', 'service': 'sshd', 'event_type': 'Connection closed', 'target_username': 'root'}, {'source': 'auth', 'date': 'Feb 10', 'time': '15:45:16', 'ip': '180.101.88.228', 'port': '11349', 'service': 'sshd', 'event_type': 'Received disconnect', 'target_username': None}, {'source': 'auth', 'date': 'Feb 10', 'time': '15:45:16', 'ip': '180.101.88.228', 'port': '11349', 'service': 'sshd', 'event_type': 'Disconnected from authenticating', 'target_username': 'root'}, {'source': 'auth', 'date': 'Feb 10', 'time': '15:45:16', 'ip': '180.101.88.228', 'port': None, 'service': 'sshd', 'event_type': 'authentication failure', 'target_username': 'root'}, {'source': 'auth', 'date': 'Feb 10', 'time': '15:45:18', 'ip': '103.106.189.143', 'port': None, 'service': 'sshd', 'event_type': 'authentication failure', 'target_username': 'root'}, {'source': 'auth', 'date': 'Feb 10', 'time': '15:45:21', 'ip': '103.106.189.143', 'port': '35180', 'service': 'sshd', 'event_type': 'Failed password', 'target_username': 'root'}]
print("PASSED LINUX PARSER TEST")
parsed_logs = []

print("\n -- PARSER TESTS PASSED -- \n")

with open("tests/Correlation-test", "r", errors='ignore') as file:
    for line in file:
        if " - - " in line:         ## Apache log
            parsed_log = parse_apache(line)
            if parsed_log is not None and parsed_log["ip"] is None:
                parsed_log = None

        elif "sshd[" in line:       ## SSH log
            parsed_log = parse_linux_auth(line)
        
        process(parsed_log)

assert(pass_analysis_data()) == {'ip_events_counter': {'192.168.1.50': {'400 Errors': 5, 'Tracked 404s': {'GET /pooop HTTP/1.1', 'GET /wp-login.php HTTP/1.1', 'GET /.env HTTP/1.1', 'GET /yaaah HTTP/1.1', 'GET /admin HTTP/1.1'}, 'Start 404 Error Time': None, 'Max 404s in Timeframe': 0, 'Failed SSH Logins': 5, 'Successful SSH Logins': 0}}, 'ip_events': {'192.168.1.50': [{'source': 'Apache', 'ip': '192.168.1.50', 'date': '02/Jun/2026', 'time': '12:00:01', 'request': 'GET /admin HTTP/1.1', 'response_code': '404'}, {'source': 'Apache', 'ip': '192.168.1.50', 'date': '02/Jun/2026', 'time': '12:00:02', 'request': 'GET /wp-login.php HTTP/1.1', 'response_code': '404'}, {'source': 'Apache', 'ip': '192.168.1.50', 'date': '02/Jun/2026', 'time': '12:00:03', 'request': 'GET /.env HTTP/1.1', 'response_code': '404'}, {'source': 'Apache', 'ip': '192.168.1.50', 'date': '02/Jun/2026', 'time': '12:00:03', 'request': 'GET /yaaah HTTP/1.1', 'response_code': '404'}, {'source': 'Apache', 'ip': '192.168.1.50', 'date': '02/Jun/2026', 'time': '12:00:05', 'request': 'GET /pooop HTTP/1.1', 'response_code': '404'}, {'source': 'auth', 'date': 'Jun  2', 'time': '12:00:10', 'ip': '192.168.1.50', 'port': '50000', 'service': 'sshd', 'event_type': 'Failed password', 'target_username': 'admin'}, {'source': 'auth', 'date': 'Jun  2', 'time': '12:00:11', 'ip': '192.168.1.50', 'port': '50001', 'service': 'sshd', 'event_type': 'Failed password', 'target_username': 'root'}, {'source': 'auth', 'date': 'Jun  2', 'time': '12:00:12', 'ip': '192.168.1.50', 'port': '50002', 'service': 'sshd', 'event_type': 'Failed password', 'target_username': 'test'}, {'source': 'auth', 'date': 'Jun  2', 'time': '12:00:13', 'ip': '192.168.1.50', 'port': '50003', 'service': 'sshd', 'event_type': 'Failed password', 'target_username': 'guest'}, {'source': 'auth', 'date': 'Jun  2', 'time': '12:00:14', 'ip': '192.168.1.50', 'port': '50004', 'service': 'sshd', 'event_type': 'Failed password', 'target_username': 'ubuntu'}]}, 'ip_timeframe': {'192.168.1.50': {'Start 404 Error Time': datetime.datetime(1900, 1, 1, 12, 0, 1), 'Current 404s in Timeframe': 5}}, 'sudo_events_counter': {}, 'sudo_events': {}, 'sudo_timeframe': {}} 

print("\n -- ANALYSIS ENGINE TEST PASSED -- \n")

alerts = detect_threats(pass_analysis_data())
assert(alerts) == [{'ip': '192.168.1.50', 'user': None, 'alert_type': 'Unique 404 Threshold Reached', 'attack_type': 'Possible Web Scan', 'alert_data': {'400 Errors': 5, 'Unique 404 Errors': 5, 'Max 404s in Timeframe': (0, 10)}, 'logs': [{'source': 'Apache', 'ip': '192.168.1.50', 'date': '02/Jun/2026', 'time': '12:00:01', 'request': 'GET /admin HTTP/1.1', 'response_code': '404'}, {'source': 'Apache', 'ip': '192.168.1.50', 'date': '02/Jun/2026', 'time': '12:00:02', 'request': 'GET /wp-login.php HTTP/1.1', 'response_code': '404'}, {'source': 'Apache', 'ip': '192.168.1.50', 'date': '02/Jun/2026', 'time': '12:00:03', 'request': 'GET /.env HTTP/1.1', 'response_code': '404'}, {'source': 'Apache', 'ip': '192.168.1.50', 'date': '02/Jun/2026', 'time': '12:00:03', 'request': 'GET /yaaah HTTP/1.1', 'response_code': '404'}, {'source': 'Apache', 'ip': '192.168.1.50', 'date': '02/Jun/2026', 'time': '12:00:05', 'request': 'GET /pooop HTTP/1.1', 'response_code': '404'}, {'source': 'auth', 'date': 'Jun  2', 'time': '12:00:10', 'ip': '192.168.1.50', 'port': '50000', 'service': 'sshd', 'event_type': 'Failed password', 'target_username': 'admin'}, {'source': 'auth', 'date': 'Jun  2', 'time': '12:00:11', 'ip': '192.168.1.50', 'port': '50001', 'service': 'sshd', 'event_type': 'Failed password', 'target_username': 'root'}, {'source': 'auth', 'date': 'Jun  2', 'time': '12:00:12', 'ip': '192.168.1.50', 'port': '50002', 'service': 'sshd', 'event_type': 'Failed password', 'target_username': 'test'}, {'source': 'auth', 'date': 'Jun  2', 'time': '12:00:13', 'ip': '192.168.1.50', 'port': '50003', 'service': 'sshd', 'event_type': 'Failed password', 'target_username': 'guest'}, {'source': 'auth', 'date': 'Jun  2', 'time': '12:00:14', 'ip': '192.168.1.50', 'port': '50004', 'service': 'sshd', 'event_type': 'Failed password', 'target_username': 'ubuntu'}]}, {'ip': '192.168.1.50', 'user': None, 'alert_type': 'SSH Failed Login Threshold Reached', 'attack_type': 'Possible Brute-Force Attack', 'alert_data': {'Failed SSH Logins': 5}, 'logs': [{'source': 'Apache', 'ip': '192.168.1.50', 'date': '02/Jun/2026', 'time': '12:00:01', 'request': 'GET /admin HTTP/1.1', 'response_code': '404'}, {'source': 'Apache', 'ip': '192.168.1.50', 'date': '02/Jun/2026', 'time': '12:00:02', 'request': 'GET /wp-login.php HTTP/1.1', 'response_code': '404'}, {'source': 'Apache', 'ip': '192.168.1.50', 'date': '02/Jun/2026', 'time': '12:00:03', 'request': 'GET /.env HTTP/1.1', 'response_code': '404'}, {'source': 'Apache', 'ip': '192.168.1.50', 'date': '02/Jun/2026', 'time': '12:00:03', 'request': 'GET /yaaah HTTP/1.1', 'response_code': '404'}, {'source': 'Apache', 'ip': '192.168.1.50', 'date': '02/Jun/2026', 'time': '12:00:05', 'request': 'GET /pooop HTTP/1.1', 'response_code': '404'}, {'source': 'auth', 'date': 'Jun  2', 'time': '12:00:10', 'ip': '192.168.1.50', 'port': '50000', 'service': 'sshd', 'event_type': 'Failed password', 'target_username': 'admin'}, {'source': 'auth', 'date': 'Jun  2', 'time': '12:00:11', 'ip': '192.168.1.50', 'port': '50001', 'service': 'sshd', 'event_type': 'Failed password', 'target_username': 'root'}, {'source': 'auth', 'date': 'Jun  2', 'time': '12:00:12', 'ip': '192.168.1.50', 'port': '50002', 'service': 'sshd', 'event_type': 'Failed password', 'target_username': 'test'}, {'source': 'auth', 'date': 'Jun  2', 'time': '12:00:13', 'ip': '192.168.1.50', 'port': '50003', 'service': 'sshd', 'event_type': 'Failed password', 'target_username': 'guest'}, {'source': 'auth', 'date': 'Jun  2', 'time': '12:00:14', 'ip': '192.168.1.50', 'port': '50004', 'service': 'sshd', 'event_type': 'Failed password', 'target_username': 'ubuntu'}]}]

print("\n -- ALERTER TEST PASSED -- \n")

correlated_alerts = correlate_alerts(alerts)
assert(correlated_alerts) == [{'ip': '192.168.1.50', 'recon': 'Unique 404 Threshold Reached', 'attack': 'SSH Failed Login Threshold Reached', 'breach': 'No SSH Breach'}]

print("\n -- CORRELATION ENGINE PASSED -- \n")