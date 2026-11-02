#!/bin/bash

env=$1
args=()
[[ -n "${SLACK_WEBHOOK:-}" ]] && args+=(--slack-webhook "$SLACK_WEBHOOK")
iec examples/${env}.ingress.txt --authorized --output-html ./output/${env}.report.html --output-md ./output/${env}.report.md --insecure-tls "${args[@]}"
