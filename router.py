from parsers.apache_analyzer import parse_apache
from parsers.linux_analyzer import parse_linux_auth
from parsers.sudo_analyzer import parse_sudo
from analysis.analysis_engine import process, pass_analysis_data
from analysis.report_writer import write_logs, write_reports, write_multi_chain_report
from analysis.alerter import detect_threats
from analysis.correlation_engine import correlate_alerts


def route(file_path, export_location, verbose):
    if export_location is None:
        export_location = "reports"

    parsed_log = None

    if verbose:
        print("\nStarting Log Parsing...")

    try:
        with open(file_path, 'r', errors='ignore') as file:
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
                    if (parsed_log is not None) and parsed_log["user"] is None or parsed_log["command"] is None:
                        parsed_log = None
                
                if parsed_log:
                    process(parsed_log)
                else:
                    print("ERROR PARSING LINE -> " + line)

                parsed_log = None
    except FileNotFoundError:
        print(f"File Not Found : {file_path}")
    except PermissionError:
        print(f"Permission Denied : {file_path}")
    except IsADirectoryError:
        print(f"Expected File Got a Directory : {file_path}")
    
    if verbose:
        print("Finished Log Parsing")
        
    analysis_data = pass_analysis_data()

    if verbose:
        print("Detecting Threats...")

    alerts = detect_threats(analysis_data)

    if verbose:
        print("Finished Detecting Threats")
        print("Correlating Threats...")

    correlated_alerts = correlate_alerts(alerts)

    if verbose:
        print("Finished Correlating Threats")
        print(f"Writing Logs and Reports to {export_location}...")

    write_logs(analysis_data, export_location)
    write_reports(alerts, export_location)
    write_multi_chain_report(correlated_alerts, export_location)

    if verbose:
        print("Finished Writing Logs and Reports\n")
        print("<- TraceGuard Complete ->\n")