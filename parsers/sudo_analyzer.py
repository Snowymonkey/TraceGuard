import re


def parse_date(line):
    pattern = r'(\w+\s+\d+)'
    match = re.match(pattern, line)

    if match:
        return match.group(1)
    
    return None

def parse_time(line):
    pattern = r'(\d{2}:\d{2}:\d{2})'
    match = re.search(pattern, line)

    if match:
        return match.group(1)
    
    return None

def parse_command(line):
    pattern = r'COMMAND=(.+)'

    match = re.search(pattern, line)

    if match:
        return match.group(1).strip()
    
    return None

def parse_working_directory(line):
    pattern = r'PWD=([^;]+)'

    match = re.search(pattern, line)

    if match:
        return match.group(1)
    
    return None

def parse_user(line):
    pattern = r'USER=([^;]+)'

    match = re.search(pattern, line)

    if match:
        return match.group(1).strip()
    
    return None

def parse_sudo(line):
    return {
        "source" : "auth",
        "date" : parse_date(line),
        "time" : parse_time(line),
        "user" : parse_user(line),
        "service" : "sudo",
        "command" : parse_command(line),
        "working_directory" : parse_working_directory(line)
    }




## TEST -- TEST -- TEST -- TEST -- TEST -- TEST -- TEST -- TEST -- TEST -- TEST -- TEST -- TEST -- TEST -- TEST

# with open('sample-logs/Linux/chatgpt-linux-logs', 'r', errors='ignore') as file:
#     for line in file:
#         if "sudo" in line:
#             items = parse_sudo(line)
#             print(items)