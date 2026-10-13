#!/bin/bash

kubectl get ing -A -o go-template='
{{printf "%-25s %-40s %-30s %-60s %-10s\n" "NAMESPACE" "NAME" "HOSTS" "PATHS" "PORTS"}}
{{- range .items}}
{{- $ns := .metadata.namespace}}
{{- $name := .metadata.name}}
{{- $ports := "80"}}
{{- if .spec.tls}}{{$ports = "80, 443"}}{{end}}
{{- range .spec.rules}}
{{- $host := .host}}
{{- range .http.paths}}
{{- printf "%-25s %-40s %-30s %-60s %-10s\n" $ns $name $host .path $ports}}
{{- end}}
{{- end}}
{{- end}}'
