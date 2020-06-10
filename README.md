# checkTLS
Java programs for checking certificates used in web browsers.
## Description

There are two programs:client and server.

Both will validate a given key store and trust store, and certificates are valid.  For example 
1 server certificates need to have the Altername Name (IP address) specified, and serverAuth attribute.
2 client certificates need a clientAuth attribute
3 validity dates are checked
4 CA certificates are checked
5 use of weak certificates which may not be accepted by Firefox or Chrome have a warning.

## table of contents

## Installation
## Usage
