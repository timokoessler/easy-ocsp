#!/bin/sh
openssl ocsp -index /data/index.txt -port 8888 -rsigner /data/ocsp-server.crt -rkey /data/ocsp-server.key -CA /data/cacert.pem -ignore_err
