from apache_analyzer import parse_apache
from linux_analyzer import parse_linux_auth
from sudo_analyzer import parse_sudo

input = input("File location: ")

with open(input, 'r', errors='ignore') as file:
    for line in file:

        if " - - " in line:         ## If Apache log
            items = parse_apache(line)
            print(items)

        elif "sshd[" in line:       ## If linux auth ssh log
            items = parse_linux_auth(line)
            print(items)
        
        elif "sudo" in line:       ## If linux auth sudo log
            items = parse_sudo(line)
            print(items)