from pathlib import Path
from router import route
import argparse
# options = ["1", "2", "3", "4"]

# def menu():
#     print("\n <--- TRACEGUARD ---> ")
#     print("1. Select file")
#     print("2. Select directory")
#     print("3. Run tester")
#     print("4. Exit")
#     selection = input("\n : ")
#     return selection

parser = argparse.ArgumentParser(
                    prog='TraceGuard',
                    description='Analysizes and identifies threats within Apache web logs and Linux Auth logs',
                    epilog='Use --help to view all available arguments'
)
group = parser.add_mutually_exclusive_group(required=True)

group.add_argument(
    "-f",
    "--file",
    metavar="FILE",
    help="Analyze a single log file."
)

group.add_argument(
    "-d",
    "--directory",
    metavar="DIRECTORY",
    help="Analyze all supported log files within a directory."
)

parser.add_argument(
    "-c",
    "--config",
    default="config.json",
    metavar="CONFIG",
    help="Specify an alternate configuration file (default: config.json)."
)

args = parser.parse_args()

if args.file:
    route(args.file)

elif args.directory:
    for file in Path(args.directory).glob("*"):
        if file.is_file():
            route(file)



print(args.file)
