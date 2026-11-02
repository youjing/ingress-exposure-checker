#!/usr/bin/env sh
# 在集群内执行: 导出 Ingress 清单 -> iec 扫描 -> Slack 告警/报告上传
# 所需环境变量 (Slack 三项可选, 经 k8s Secret 注入):
#   IEC_ENV_NAME    环境名, 显示在 Slack 卡片标题 (默认 "cluster")
#   IEC_CONCURRENCY 扫描并发 (默认 10)
#   SLACK_WEBHOOK / SLACK_TOKEN / SLACK_CHANNEL
set -eu

ENV_NAME="${IEC_ENV_NAME:-cluster}"
OUT_DIR="${IEC_OUT_DIR:-/tmp}"
TARGETS="${OUT_DIR}/${ENV_NAME}.ingress.txt"
REPORT="${OUT_DIR}/report.html"

echo "[iec] 导出 Ingress 清单 -> ${TARGETS}"
/opt/iec/list-ingress.sh > "${TARGETS}"
count=$(grep -vc '^NAMESPACE' "${TARGETS}" || true)
echo "[iec] 目标数: ${count}"
if [ "${count}" -eq 0 ]; then
    echo "[iec] 集群无 Ingress, 退出"
    exit 0
fi

set -- "$TARGETS" --authorized --insecure-tls \
     --output-html "${REPORT}" --output-md "${OUT_DIR}/report.md" \
     --concurrency "${IEC_CONCURRENCY:-10}"
[ -n "${SLACK_WEBHOOK:-}" ] && set -- "$@" --slack-webhook "${SLACK_WEBHOOK}"
[ -n "${SLACK_TOKEN:-}" ]   && set -- "$@" --slack-token "${SLACK_TOKEN}"
[ -n "${SLACK_CHANNEL:-}" ] && set -- "$@" --slack-channel "${SLACK_CHANNEL}"

echo "[iec] 开始扫描..."
exec iec "$@"
