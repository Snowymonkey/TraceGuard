from pathlib import Path
from router import route
import argparse

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
    "-e",
    "--export",
    default="reports",
    metavar="DIRECTORY",
    help="Specify an alternate export location."
)

parser.add_argument(
    "-v",
    "--verbose",
    action="store_true",
    help="States when operations such as log parsing start and finish."
)

parser.add_argument(
    "--version",
    action="version",
    version="TraceGuard Version 1.0.0"

)

args = parser.parse_args()

if args.file:
    route(args.file, args.export, args.verbose)

elif args.directory:
    for file in Path(args.directory).glob("*"):
        if file.is_file():
            route(file, args.export, args.verbose)
