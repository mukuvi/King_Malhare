# King Malhare scanner worker.
# Includes the core tool set. Prowler, ScoutSuite, Checkov and Trivy are optional;
# install them in a derived image and the Integrations page will detect them.
FROM python:3.12-slim-bookworm

ARG NUCLEI_VERSION=3.11.1
ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       ca-certificates curl unzip git openssl nmap sqlmap gobuster whatweb \
       perl libnet-ssleay-perl libjson-perl libxml-writer-perl \
    && rm -rf /var/lib/apt/lists/*

# Nikto is not packaged in Debian bookworm; install the maintained upstream release.
RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto \
    && ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto \
    && chmod 0755 /opt/nikto/program/nikto.pl \
    && apt-get update \
    && apt-get install -y --no-install-recommends libio-socket-ssl-perl \
    && rm -rf /var/lib/apt/lists/*

# Nuclei (pinned release)
RUN curl -fsSL -o /tmp/nuclei.zip "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" \
    && unzip -q /tmp/nuclei.zip -d /usr/local/bin nuclei \
    && chmod 0755 /usr/local/bin/nuclei \
    && rm -f /tmp/nuclei.zip

# testssl.sh (pinned release from the maintained testssl/testssl.sh repository)
RUN curl -fsSL https://codeload.github.com/testssl/testssl.sh/tar.gz/refs/tags/v3.2.5 \
      | tar -xz -C /opt \
    && mv /opt/testssl.sh-3.2.5 /opt/testssl \
    && ln -s /opt/testssl/testssl.sh /usr/local/bin/testssl.sh \
    && chmod 0755 /opt/testssl/testssl.sh

# Additional web, network, container and IaC scanners.
ARG FFUF_VERSION=2.3.0
ARG HTTPX_VERSION=1.12.0
ARG SUBFINDER_VERSION=2.17.0
ARG GRYPE_VERSION=0.121.2
ARG GITLEAKS_VERSION=8.30.1
ARG TFSEC_VERSION=1.28.14
ARG SYFT_VERSION=1.57.0

RUN curl -fsSL "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VERSION}/ffuf_${FFUF_VERSION}_linux_amd64.tar.gz" \
      | tar -xz -C /usr/local/bin ffuf \
    && curl -fsSL -o /tmp/httpx.zip "https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VERSION}/httpx_${HTTPX_VERSION}_linux_amd64.zip" \
    && unzip -q /tmp/httpx.zip -d /usr/local/bin httpx \
    && curl -fsSL -o /tmp/subfinder.zip "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_amd64.zip" \
    && unzip -q /tmp/subfinder.zip -d /usr/local/bin subfinder \
    && curl -fsSL "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_amd64.tar.gz" \
      | tar -xz -C /usr/local/bin grype \
    && curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
      | tar -xz -C /usr/local/bin gitleaks \
    && curl -fsSL -o /usr/local/bin/tfsec "https://github.com/aquasecurity/tfsec/releases/download/v${TFSEC_VERSION}/tfsec-linux-amd64" \
    && chmod 0755 /usr/local/bin/tfsec \
    && curl -fsSL "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_amd64.tar.gz" \
      | tar -xz -C /usr/local/bin syft \
    && rm -f /tmp/httpx.zip /tmp/subfinder.zip

# Nuclei templates that ship with the product (safe, deterministic checks).
COPY km_worker/nuclei_templates /opt/nuclei-templates/king-malhare
ENV NUCLEI_TEMPLATES=/opt/nuclei-templates/king-malhare
COPY km_worker/wordlists/common.txt /opt/wordlists/common.txt
ENV DIR_WORDLIST=/opt/wordlists/common.txt

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt wafw00f sslyze semgrep schemathesis

COPY km_worker ./km_worker

RUN useradd --system --uid 10001 --create-home --shell /usr/sbin/nologin scanner \
    && mkdir -p /tmp/king-malhare-work \
    && chown -R scanner:scanner /app /tmp/king-malhare-work

USER scanner
ENV PYTHONUNBUFFERED=1 \
    SCANNER_WORK_DIR=/tmp/king-malhare-work \
    WORKER_HTTP_PORT=8090 \
    HOME=/home/scanner

EXPOSE 8090
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8090/health', timeout=3).status==200 else 1)"

CMD ["python", "-m", "km_worker.main"]
