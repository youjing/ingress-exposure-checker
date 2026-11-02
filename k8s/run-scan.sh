#!/usr/bin/env sh
# 在集群内执行: 导出 Ingress 清单 -> iec 扫描 -> Slack 告警/报告上传 -> Alertmanager 推送
# 所需环境变量 (Slack/Alertmanager 凭据可选, 经 k8s Secret 注入):
#   IEC_ENV_NAME            环境名, 显示在 Slack 卡片标题 (默认 "cluster")
#   IEC_CONCURRENCY         扫描并发 (默认 10)
#   IEC_EXTRA_ARGS          追加 iec 参数 (空格分隔, 不支持带引号参数)
#   IEC_EXIT_ZERO           设置任意值: 扫描完成即退出码 0 (发现漏洞不再标记 Job 失败)
#   SLACK_WEBHOOK / SLACK_TOKEN / SLACK_CHANNEL
#   ALERTMANAGER_URL / ALERTMANAGER_USER / ALERTMANAGER_PASSWORD / ALERTMANAGER_ENDSAT_HOURS
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
[ -n "${ALERTMANAGER_URL:-}" ] && set -- "$@" --alertmanager-url "${ALERTMANAGER_URL}"
[ -n "${ALERTMANAGER_USER:-}" ] && set -- "$@" --alertmanager-user "${ALERTMANAGER_USER}"
[ -n "${ALERTMANAGER_PASSWORD:-}" ] && set -- "$@" --alertmanager-password "${ALERTMANAGER_PASSWORD}"
[ -n "${ALERTMANAGER_ENDSAT_HOURS:-}" ] && set -- "$@" --alertmanager-endsat-hours "${ALERTMANAGER_ENDSAT_HOURS}"
[ -n "${IEC_EXIT_ZERO:-}" ] && set -- "$@" --exit-zero
[ -n "${IEC_EXTRA_ARGS:-}" ] && set -- "$@" ${IEC_EXTRA_ARGS}

echo "[iec] 开始扫描..."
exec iec "$@"
