FROM python:3.12-slim

WORKDIR /scan

COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/

RUN pip install --no-cache-dir .

# 报告输出到挂载目录: docker run -v "$PWD/output:/scan/output" ...
ENTRYPOINT ["iec"]
CMD ["--help"]
