# iec 集群扫描镜像: iec + kubectl + ingress 导出脚本
# 用法: docker build -f k8s/Dockerfile -t ghcr.io/youjing/iec:latest .
FROM python:3.12-slim

ARG TARGETARCH
ARG KUBECTL_VERSION=v1.31.4

WORKDIR /opt/iec

COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/
RUN pip install --no-cache-dir .

# kubectl (Job 内通过 in-cluster ServiceAccount 访问本集群 API)
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && curl -fsSL -o /usr/local/bin/kubectl \
       "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${TARGETARCH:-amd64}/kubectl" \
    && chmod +x /usr/local/bin/kubectl \
    && rm -rf /var/lib/apt/lists/*

COPY list-ingress.sh /opt/iec/list-ingress.sh
COPY k8s/run-scan.sh /usr/local/bin/run-scan.sh
RUN chmod +x /opt/iec/list-ingress.sh /usr/local/bin/run-scan.sh

ENTRYPOINT ["/usr/local/bin/run-scan.sh"]
