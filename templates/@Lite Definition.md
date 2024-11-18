# Lite Definition Guidance
The host.html file and template.html files define how to format the output from the tool. 

The program will us the template to dress the document. For each host within the input from sslscan, the program will create an entry for the 'host.html' template using a lite interpreter. The definitions for this interpreter are as follows.

No. I will not create a ASN or BNF for this.

## Lite Definition
Reserved Keywords:
IP_ADDRESS, PORT, HOST_NAME, PROTOCOLS, CIPHERS, METADATA, WHERE, ==, !=, >=, <= AND, ->, :.

#### IP_ADDRESS
The IP address of the host.

#### PORT
The port of the host.

#### HOST_NAME
The hostname of the host as presented within the scan.

<hr>

### PROTOCOLS, CIPHERS, METADATA
Each of these 'top level' headings must be enclosed within their own div. You may apply any other css/html elements around or within the div opening tag. 
``` 
        DATA_TYPE WHERE:
            CONDITION => OUTCOME
```

The statement 'PROTOCOLS WHERE:' will consume the following lines until the closing div tag. For each line consumed by the program from the source file, the program will perform a match against the input text for the source against each condition, stopping at the first met condition. The outcome will then be performed on the line.

```
<outcome> ::= <css-class> | <css-class> ON <element>
<element> ::= LINE | LINE[<index>] | SELF
```

```
<condition> ::= <statement> | <statament> AND <statement>
<statement> ::= <component> CONTAINS <resultl> | <component> IS <result>
<component> ::= LINE | LINE[<index>] | <function>
<function>  ::= CIPHER_STRENGTH | CIPHER_BITS | META_EXPIRE | META_RENEW | META_BEFORE | META_BITS
<result>    ::= <string-literal> | 'weak' | 'expired' | 'inactive' | 'before-active-date'
``` 