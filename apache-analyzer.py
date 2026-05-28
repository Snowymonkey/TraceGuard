import re

HTTPMeaning = {'200' : 'OK, request succeeded', '304' : 'Not Modified', '400' : 'Bad Request', '401' : 'Unauthorized', '403' : 'Forbidden', '404' : 'Not Found', '410' : 'Gone'}
pattern = re.compile(r'(\S+) - - \[(.*?)\] "(.*?)" (\d{3})')
lineNumber = 1

with open('sample-logs/medium_NASA_access_log_Jul95', 'r', errors='ignore') as file:
    for line in file:

        match = pattern.match(line)
    

        if match:
            client = match.group(1)
            date = match.group(2)
            request = match.group(3)
            response_code = match.group(4)
        else:
            print("=============ERROR=============")
            print(lineNumber, line)
        
        lineNumber += 1
        
            
            

        
        