# parser.py
#   By Lepus Hare
# The parser class exists to take a host html template file as initial input, then take a sslscan output as input to generate the final output. It does all the heavy lifting.

from enum import Enum
from datetime import datetime
from _collections_abc import MutableSequence

# Enumerators
class BLOCK_TYPE(Enum):
    PROTOCOLS       = 0
    CIPHERS         = 1
    METADATA        = 2

class ELEMENT_TYPE(Enum):
    LINE            = 0
    LINE_INDEX      = 1
    SELF            = 2

class STATEMENT_TYPE(Enum):
    CONTAINS        = 0
    IS              = 1

class COMPONENT_TYPE(Enum):
    LINE            = 0
    LINE_INDEX      = 1
    CIPHER_STRENGTH = 2
    CIPHER_BITS     = 3
    META_EXPIRE     = 4
    META_RENEW      = 5 # UNIMPLEMNETED YET
    META_BEFORE     = 6
    META_BITS       = 7

class CONDITION_TYPE(Enum):
    CONTAINS        = 0
    IS              = 1
    IS_GREATER      = 2
    IS_LESSER       = 3
    IS_GREATER_EQ   = 4
    IS_LESSER_EQ    = 5
    IS_NOT          = 6

class RESULT_TYPE(Enum):
    STRING_LITERAL  = 0
    # CIPHER_STRENGTH = 1
    # CIPHER_BITS     = 2
    # META_EXPIRE     = 3
    # META_RENEW      = 4
    # META_BEFORE     = 5
    # META_BITS       = 6

## ++ Shared
class Element():
    type: ELEMENT_TYPE = ELEMENT_TYPE.LINE
    index: int = 0

    def __init__(this, type: ELEMENT_TYPE, index = 0):
        this.type = type
        this.index = index
    
    def FromString(text:str):
        output = Element()
        text = text.strip()
        if text.count('SELF') == 1:
            output.type = ELEMENT_TYPE.SELF
            return output
        
        if text.count('LINE[') == 1:
            output.type = ELEMENT_TYPE.LINE_INDEX
            endIndex = text.find(']')
            output.index = int(text[5:endIndex])
        else:
            output.type = ELEMENT_TYPE.LINE
        return output

    def Get(this, text: str):
        if this.type == ELEMENT_TYPE.LINE:
            return text
        elif this.type == ELEMENT_TYPE.LINE_INDEX:
            return text.split(' ')[this.index]

## -- Shared

## ++ Outcomes 
class Outcome():
    cssClass: str
    element: Element

    # Returns html text to render if the outcome is applied.
    # This returns a Tuple. In the event of 'Self', the program must re-batch the request as it requires elements from the component to complete
    def Apply(this, text:str):
        if this.element.type == ELEMENT_TYPE.LINE:
            return (False, f"<span class='{this.cssClass}'>{text}</span>")
        elif this.element.type == ELEMENT_TYPE.LINE_INDEX:
            fields = text.split()
            tempString = f"<span class='{this.cssClass}'>{fields[this.element.index]}</span>"
            fields[this.element.index] = tempString
            return (False, ' '.join(fields))
        elif this.element.type == ELEMENT_TYPE.SELF:
            return (True, f"<span class='{this.cssClass}'>SELF</span>")
        print(f"ERROR: Unable to apply an Outcome on '{text}'.")
        exit(1)

    def FromString(text:str):
        output = Outcome()
        if text.count("ON") == 1:
            fields = text.split()
            output.cssClass = fields[0]
            output.element = Element.FromText(fields[2])
        else:
            output.element = Element()
        return output

    def __init__(this, cssClass: str, element=None):
        if element == None:
            this.element = Element()
        this.cssClass = cssClass

## -- Outcomes


## ++ Conditions 

# Defines a Result
class Result():
    type: RESULT_TYPE
    value: str = ""

    def Get(this):
        return this.value

# Component Mapping for string token 
Components = {"CIPHER_STRENGTH": COMPONENT_TYPE.CIPHER_STRENGTH,
               "CIPHER_BITS": COMPONENT_TYPE.CIPHER_BITS,
                "META_EXPIRE": COMPONENT_TYPE.META_EXPIRE,
                "META_RENEW": COMPONENT_TYPE.META_RENEW,
                "META_BEFORE": COMPONENT_TYPE.META_BEFORE,
                "META_BITS": COMPONENT_TYPE.META_BITS}
# Defines a Component
class Component():
    type: COMPONENT_TYPE
    index: int = 0

    # Returns a string equal to the result of the component from an input line
    def Get(this, text: str):
        if this.type == COMPONENT_TYPE.LINE:
            return text
        
        if this.type == COMPONENT_TYPE.LINE_INDEX:
            return text.split()[this.index]
        
        if this.type == COMPONENT_TYPE.CIPHER_BITS:
            fields = text.split()
            bitsIndex = 0
            for i in range(len(fields)):
                if fields[i] == "bits":
                    bitsIndex = i-1
                    break
            return fields[bitsIndex]

        if this.type == COMPONENT_TYPE.CIPHER_STRENGTH:
            # Lookup against the cache from CS
            pass

        # Return 'before-active-date' or 'ok' if ok.
        if this.type == COMPONENT_TYPE.META_BEFORE:
            if text.count('before') != 1:
                pass
            now = datetime.now()
            # Get the date section
            startIndex = text.find(':')
            endIndex = 'GMT'
            dateString = text[startIndex:endIndex].strip()
            timeBefore = datetime.strptime("%b %d %H:%M:%S %Y")
            if now - timeBefore > 0:
                return 'before-active-date'
            else:
                return 'ok'
        
        # Returns 'expired' or 'ok'.
        if this.type == COMPONENT_TYPE.META_EXPIRE:
            if text.count('after') != 1:
                pass
            now = datetime.now()
            # Get the date section
            startIndex = text.find(':')
            endIndex = 'GMT'
            dateString = text[startIndex:endIndex].strip()
            timeExpire = datetime.strptime("%b %d %H:%M:%S %Y")
            if now - timeExpire < 0:
                return 'expired'
            else:
                return 'ok'
        
        # Returns the bits of the RSA key.
        if this.type == COMPONENT_TYPE.META_BITS:
            if text.count('Key Strength') != 1:
                pass
        
            fields = text.split()
            return fields[-1].strip()

        print(f"Error: Component unable to resolve field in '{text}'")
        exit(1)

    def FromString(text: str):
        global Components
        output = Component()
        text = text.strip()
        if text in Components.keys():
            output.type = Components[text]
            return output

        if text.count('LINE[') == 1:
            output.type = COMPONENT_TYPE.LINE_INDEX
            endIndex = text.find(']')
            output.index = int(text[5:endIndex])
        else:
            output.type = COMPONENT_TYPE.LINE
        return output


# Defines a Statement
class Statement():
    type: STATEMENT_TYPE
    component: Component
    result: Result

    def Test(this, text: str):
        if this.type == STATEMENT_TYPE.IS:
            return this.component.Get(text) == this.result.Get()

        if this.type == STATEMENT_TYPE.CONTAINS:
            return (this.component.Get(text).count(this.result.Get) != 0)

        print(f"Error: Unable to Test statement.")
        exit (1)

    def FromString(text: str):
        output = Statement()
        text = text.strip()
        if text.contains('IS'):
            output.type = STATEMENT_TYPE.IS
            fields = text.split('IS')
            output.component = Component.FromString(fields[0])
            output.result = Result.FromString(fields[1])
            return output
        
        if text.contains('CONTAINS'):
            output.type = STATEMENT_TYPE.CONTAINS
            fields = text.split('CONTAINS')
            output.component = Component.FromString(fields[0])
            output.result = Result.FromString(fields[1])
            return output

        print(f"Error: Unable to process statement in statement '{text}'.")
        exit(1)

# Defines a Condition
class Condition():
    baseStatement:  Statement # for base statements
    optStatement:   Statement # for AND statements
    def __init__(this, baseStatement, optStatement=None):
        this.baseStatement = baseStatement
        this.optStatement = optStatement

    def Test(this, text: str):
        flag1 = this.baseStatement.Test(text)
        if this.optStatement == None:
            return flag1
        
        flag2 = this.optStatement.Test(text)

        return flag1 and flag2

    def FromString(text: str):
        output = Condition()
        text = text.strip()
        if (text.count('AND') == 1):
            fields = text.split('AND')
            output.baseStatement = Statement.FromString(fields[0])
            output.optStatement = Statement.FromString(fields[1])
            return output
    
        output.baseStatement = Statement.FromString(fields[0])
        output.optStatement = None
        return output

## -- Conditions
# Defines a Rule for processing text.
class Rule():
    rawTex: str
    condition: Condition
    outcome: Outcome

    # Returns true if the condition matches the text
    def Test(this, text: str):
        flag1 = False
        flag2 = True
        return flag2 & flag1
    
    # Returns the HTML render text when applying the 'outcome' to the rule.
    def Apply(this, text:str):
        (result, string) = this.outcome.Apply(text)
        if result == True:
            string.replace(Condition.baseStatement.component.Get(text))
        return string


    def FromString(rawText: str):
        output = Rule()
        output.rawText = rawText.strip()
        if (output.rawText.count('->') != 1):
            print(f"Error: Illegal Rule format. Rule '{rawText}' does not contain one '->'.")
            exit(1)
        fields = output.rawTex.split('->')
        output.condition = Condition.FromString(fields[0])
        output.outcome = Outcome.FromString(fields[1])


# Manages a 'block' of instructions.
class BlockManager():
    type: BLOCK_TYPE
    Rules: MutableSequence[Rule] = []

    def __init__(this, type):
        this.type = type
        this.Rules = []

    def AddRuleFromString(this, text):
        this.Rules.append(Rule.FromString(text))

    # Returns true if any the rules match
    def Test(this, text):
        for rule in this.Rules:
            if rule.Test(text) == True:
                return True
        return False
    
    # Returns the string for any of the rules matching, else returns the string as is
    def TestAndApply(this, text):
        for rule in this.Rules:
            if rule.Test(text) == True:
                return rule.Apply(text)
        return text



# A dictionary of all block managers and their links
BlockManagers = {
    "PROTOCOLS": "SSL/TLS Protocols:",
    "FALLBACK": "TLS Fallback SCSV:",
    "RENEGOTIATION": "TLS renegotiation:",
    "COMPRESSION": "TLS Compression:",
    "HEARTBLEED": "Heartbleed",
    "CIPHERS": "Supported Server Cipher(s):",
    "EXCHANGE_GROUPS": "Server Key Exchange Group(s):",
    "METADATA": "SSL Certificate"
}
# Performs parsing and evaluation.
class Parser():

    managers = {
    "PROTOCOLS": None,
    "FALLBACK": None,
    "RENEGOTIATION": None,
    "COMPRESSION": None,
    "HEARTBLEED": None,
    "CIPHERS": None,
    "EXCHANGE_GROUPS": None,
    "METADATA": None,
}
    template: MutableSequence[str] = []
    hostTemplate: MutableSequence[str] = []

    # Read the template files
    def ReadTemplate(this, templateFile):
        f = open(templateFile)
        this.template = f.readlines()
        f.close()

    # Parse the host file
    def ParseHostFile(this, hostFile):
        global BlockManagers

        f = open(hostFile)
        lines = f.readlines()
        f.close()

        this.hostTemplate = []
        # Parse the lines, ignore non-directives
        for i in range(len(lines)):
            line = lines[i].strip()
            #Is this a control block?
            if line.count('WHERE') == 1:
                #If so, create the appropriate blockManager and consume all inner lines
                fields = line.split()
                for key in BlockManagers.keys():
                    if fields[0] == key:

            else:
                #  





    # Parse the input 
    def ParseInputFile(this, inputFile):
        f = open(inputFile)
        for line in f.readlines():
            #If this line contains a colon, it is a new field and should apply the appropriate rule manager 

        f.close()