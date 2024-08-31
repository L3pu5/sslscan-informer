# sslscan-informer
Local python script that ingests output from ssl scan, then reproduces with html formatting, highlighting that are weak according to the CipherSuite API. Thi sprogram  Locally caches the repsonse from CipherSuite to avoid spamming the service.

## Metadata

| Field | Value|
| --- | --- |
|Version |0.0.1 |
|Author | Lepus Hare |

## Usage

```
python3 sslscan-informer [options] <no-colour-sslscan-output>
```

| Option | Description |
| --- |---|
| -t | **Template File** <br> A file that defines the expected html output for the final render.<br>Default: -t `template.html`|
| -o | **Output File** <br>A file to write the resultant html to.<br> Default: `-o out.html`
| -i | **Input File** <br>A file to read.|
## Referencs

https://testssl.sh/openssl-iana.mapping.html