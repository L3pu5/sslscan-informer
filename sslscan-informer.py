#
# sslscan-informer.py
#   By Lepus Hare
#       This program takes a non-formatted text output from sslscan (run sslscan with the --no-colour , --iana-names arguments) and creates a html output which can be copied into richtextbox fields.
#       sslscan-informer.py comes with a generic template to format the output for each host. 
#

from sys import argv
from getopt import getopt
from modules import parser as Parser
from modules import poller as Poller

globals = {"input": "", 
           "output": "./out.html",
             "template": "./templates/template.html", 
             "hosts": "./templates/host.html",
             "update": False
             }

# Banner
def banner():
    print("sslscan-informer.py")
    print("     by Lepus Hare")
    print(" B U N N Y B U N N Y B U N N Y ")

# Usage
def usage():
    print("python3 ./sslscan-informer.py [options] -i <path-to-input>")
    print("Options:")
    print("-i           Input file")
    print("-t           Template file.")
    print("-h           Per-host template file")
    print("-u           force an update")


# Process Options
def processOptions():
    global globals
    shortOptions = "t:o:i:u"
    
    args, values = getopt(argv[1:], shortOptions, [])
    for opt in args:
        if opt[0] == '-i':
            globals["input"] = opt[1]
        if opt[0] == '-u':
            globals["uptdate"] = True

    if globals["input"] == "":
        print("An input is required.")
        usage()
        exit(1)


# Entry point
def main():
    banner()
    global globals
    # Process the options
    processOptions()
    # Create the Poller
    poller = Poller.Poller()
    if globals['update'] == True:
        poller.ForceUpdate()
    else:
        lastUpdated = poller.CheckForceUpdate()
        print(f"Your cipher suites were last updated {lastUpdated}.")

    # Mount the Cipher Suites
    poller.Mount()

    # Create the Parser
    parser = Parser.Parser(poller)
    parser.ParseHostFile(globals["hosts"])
    outputLines = parser.ParseInputFile(globals["input"])

    # Read the template file
    f = open(globals['template'])
    template = f.readlines()
    for i in range(len(template)):
        template[i] = template[i].replace('<!-- OUTPUT_TAG -->', '\n'.join(outputLines))
    f.close()

    # Write to file
    f = open(globals['output'], "w")
    f.writelines(template)
    f.close()


if __name__ == "__main__":
    main()