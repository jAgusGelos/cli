# Infisical Web App runner (F1). Base and Chromium pinned as in spikes/rbi-runner (SPIKE-RESULT.md).
FROM debian@sha256:04634311a8d5fc442b6eb06d792293c4f3e2268652ca7634e00ce8ef5cc0a28a
# 155.0.8059.39-1~deb13u1 (spike) was superseded in debian-security; same milestone, newer security build.
ARG CHROMIUM_VERSION=155.0.8059.79-1~deb13u1
RUN apt-get update && apt-get install -y --no-install-recommends \
      chromium=${CHROMIUM_VERSION} chromium-common=${CHROMIUM_VERSION} \
      xvfb ffmpeg python3 python3-xlib python3-av libnss3-tools iptables procps \
      fonts-dejavu-core x11-utils \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -u 1000 -m -d /home/rbi rbi \
    && mkdir -p /etc/chromium/policies /opt/iwa/policies /quarantine \
    && rm -rf /etc/chromium/policies/managed /etc/chromium/policies/recommended \
    && ln -s /tmp/iwa/policies /etc/chromium/policies/managed
COPY policies/rbi.json /opt/iwa/policies/rbi.json
COPY entrypoint.sh netns-rules.sh netprobe.py /opt/iwa/
COPY agent/iwa_agent /opt/iwa/agent/iwa_agent
RUN chmod 0755 /opt/iwa/entrypoint.sh /opt/iwa/netns-rules.sh /opt/iwa/netprobe.py \
    && chmod -R a-w,a+rX /opt/iwa /etc/chromium
ENV PYTHONPATH=/opt/iwa/agent PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 1000:1000
WORKDIR /home/rbi
ENTRYPOINT ["/opt/iwa/entrypoint.sh"]
