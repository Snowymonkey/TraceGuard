from parsers.apache_analyzer import parse_apache
from parsers.linux_analyzer import parse_linux_auth
from parsers.sudo_analyzer import parse_sudo
from analysis.analysis_engine import process, pass_analysis_data
from analysis.report_writer import write_logs, write_reports
from analysis.alerter import detect_threats

# input = input("\nFile location: ")

with open("sample-logs/suspicious-logs/sus-times", 'r', errors='ignore') as file:
    for line in file:

        if " - - " in line:         ## Apache log
            parsed_log = parse_apache(line)

        elif "sshd[" in line:       ## SSH log
            parsed_log = parse_linux_auth(line)
        
        elif "sudo" in line:       ## sudo log
            parsed_log = parse_sudo(line)
        
        if parsed_log:
            process(parsed_log)
        else:
            print("ERROR PARSING LINE")

analysis_data = pass_analysis_data()
alerts = detect_threats(analysis_data)
write_logs(analysis_data)
write_reports(alerts)
