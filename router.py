from parsers.apache_analyzer import parse_apache
from parsers.linux_analyzer import parse_linux_auth
from parsers.sudo_analyzer import parse_sudo
from analysis.analysis_engine import process, write_logs, write_report

# input = input("\nFile location: ")

with open("sample-logs/suspicious-logs/sus", 'r', errors='ignore') as file:
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

write_logs()
write_report()