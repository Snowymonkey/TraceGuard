from apache_analyzer import parse_apache
from linux_analyzer import parse_linux_auth

input = input("File location: ")

with open(input, 'r', errors='ignore') as file:
    for line in file:
        
        if " - - " in line:
            items = parse_apache(line)
            print(items["date"])

        elif "sshd[" in line:
            items = parse_linux_auth(line)
            print(items["date"])