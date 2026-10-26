#!/bin/bash

env=$1
iec examples/${env}.ingress.txt --authorized --output-html ./output/${env}.report.html --output-md ./output/${env}.report.md --insecure-tls
