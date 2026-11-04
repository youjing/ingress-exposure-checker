#!/bin/bash

# 使用完全限定资源名 ingresses.networking.k8s.io:
# K8s < 1.21 存在 extensions 与 networking.k8s.io 双 API 组,
# 短名 "ing" 可能被 kubectl 解析到 extensions 组导致 RBAC Forbidden
kubectl get ingresses.networking.k8s.io -A -o go-template='
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
