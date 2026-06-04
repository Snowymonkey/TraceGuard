from parsers.apache_analyzer import parse_apache
from parsers.linux_analyzer import parse_linux_auth
from parsers.sudo_analyzer import parse_sudo
from analysis.analysis_engine import process, pass_analysis_data
from analysis.report_writer import write_logs, write_reports, write_multi_chain_report
from analysis.alerter import detect_threats
from analysis.correlation_engine import correlate_alerts

# input = input("\nFile location: ")

parsed_log = None

with open("sample-logs/multi-chain-logs/multi-chain", 'r', errors='ignore') as file:
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
        
        if parsed_log:
            process(parsed_log)
        else:
            print("ERROR PARSING LINE -> " + line)

        parsed_log = None

analysis_data = pass_analysis_data()
alerts = detect_threats(analysis_data)
correlated_alerts = correlate_alerts(alerts)
write_logs(analysis_data)
write_reports(alerts)
write_multi_chain_report(correlated_alerts)