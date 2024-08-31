#
# sslscan-informer.py
#   By Lepus Hare
#       This program takes a non-formatted text output from sslscan (run sslscan with the --no-colour , --iana-names arguments) and creates a html output which can be copied into richtextbox fields.
#       sslscan-informer.py comes with a generic template to format the output for each host. 
#

from sys import argv
from getopt import getopt

globals = {"input": "", "output": "./out.html", "template": "./templates/template.html", "hosts": "./templates/host.html"}

# Usage
def usage():
    print("python3 ./sslscan-informer.py [options] -i <path-to-input>")
    print("Options:")
    print("-i           Input file")
    print("-t           Template file.")
    print("-h           Per-host template file")


# Process Options
def processOptions():
    global globals
    shortOptions = "t:o:i:"
    
    args, values = getopt(argv[1:], shortOptions, [])
    for opt in args:
        if opt[0] == '-i':
            globals["input"] = opt[1]

    if globals["input"] == "":
        print("An input is required.")
        usage()
        exit(1)


# Entry point
def main():
    processOptions()
    pass

if __name__ == "__main__":
    main()