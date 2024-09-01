# Poller.py
#   By Lepus Hare
# The poller class exists to track and request the CS specs from ciphersuite.

import requests
import json
import pathlib
from datetime import datetime
from _collections_abc import MutableMapping, MutableSequence
from enum import Enum

routes =[
    "https://ciphersuite.info/api/cs/security/"
]

class Suite():
    ianaName: str
    security: str
    hashAlgorithm: str
    protocolVersion: str
    exchangeAlgorithm: str
    encryptAlgorithm: str
    authAlgorithm: str
    
    def FromJson(json, name):
        output = Suite()
        output.ianaName = name
        output.security = json['security']
        output.hashAlgorithm = json['hash_algorithm']
        output.protocolVersion = json['protocol_version']
        output.hashAlgorithm = json['hash_algorithm']
        output.encryptAlgorithm = json['enc_algorithm']
        return output

class Poller():
    Suites: MutableMapping[str,  MutableMapping[str, Suite]] = {}

    # Request the cache.
    def __downloadCache(this, label:str):
        global routes
        data = requests.get(routes[0] + label)
        print(f"Requesting {label} ciphers from ciphersuite.")
        f = open(f".{label}", "w")
        f.write(data.text)
        f.close()

    # Update all caches
    def ForceUpdate(this):
        # Download the caches.
        this.__downloadCache('insecure')
        this.__downloadCache('weak')
        this.__downloadCache('secure')
        this.__downloadCache('recommended')

        # Create a file for the timestamp
        f = open(".updated", "w")
        f.write( datetime.now().strftime("%d/%m/%Y %H:%M:%S") )
        f.close()

    # Check for existing Cache
    def CheckUpdate(this):
        if pathlib.Path("./.updated").is_file():
            f = open("./.updated", "r")
            line = f.readline()
            f.close()
            return line
        return "never"
    
    # Check and if not, Update, else return it
    def CheckForceUpdate(this):
        lastUpdated = this.CheckUpdate()
        if (lastUpdated == "never"):
            this.ForceUpdate()
            return "just now"
        else:
            return lastUpdated

    # Load a Json BLob into memory
    def __mount(this, label):
        this.Suites[label] = {}
        f = open(f"./.{label}", "r")
        blob = json.loads(f.readline())
        f.close()
        for cipherSuite in blob['ciphersuites']:
            for (name, data) in cipherSuite.items():
                this.Suites[label][name] = Suite.FromJson(data, name)

    def Mount(this):
        this.__mount('insecure')
        this.__mount('weak')
        this.__mount('recommended')
        this.__mount('secure')

    def QueryStrength(this, cipherName):
        if this.Query(cipherName, 'insecure'):
            return 'insecure'
        
        if this.Query(cipherName, 'weak'):
            return 'weak'
            pass

        if this.Query(cipherName, 'secure'):
            return 'secure'
        
        if this.Query(cipherName, 'recommended'):
            return 'recommended'
        
        return 'unknown'

    def Query(this, cipherName, cipherLevel):
        if cipherName in this.Suites[cipherLevel].keys():
            return True
        return False