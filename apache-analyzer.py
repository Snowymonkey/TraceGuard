import re


## Determine client IP / website
with open('sample-logs/small_NASA_access_log_Jul95', 'r') as file:
    for line in file:
        
        splicedLine = line.split(" - - ", 1)
        client = splicedLine[0]
        date = splicedLine[1].split(" \"")[0]
        HTTPCodes = splicedLine[1].split(" \"")[1].rsplit(" " ,2)[1]

        print(client)
        print(date)
        print(HTTPCodes)
        


## Determine date and time of request


## Status code of request