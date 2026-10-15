# Infisical Web App runner (F1). Base and Chromium pinned as in spikes/rbi-runner (SPIKE-RESULT.md).
FROM debian@sha256:04634311a8d5fc442b6eb06d792293c4f3e2268652ca7634e00ce8ef5cc0a28a
# 155.0.8059.39-1~deb13u1 (spike) was superseded in debian-security; same milestone, newer security build.
ARG CHROMIUM_VERSION=155.0.8059.79-1~deb13u1
RUN apt-get update && apt-get install -y --no-install-recommends \
      chromium=${CHROMIUM_VERSION} chromium-common=${CHROMIUM_VERSION} \
      xvfb ffmpeg python3 python3-xlib python3-av libnss3-tools iptables procps \
      fonts-dejavu-core x11-utils openssl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -u 1000 -m -d /home/rbi rbi \
    && mkdir -p /etc/chromium/policies /etc/chromium/native-messaging-hosts /opt/iwa/policies /quarantine \
    && rm -rf /etc/chromium/policies/managed /etc/chromium/policies/recommended \
    && ln -s /tmp/iwa/policies /etc/chromium/policies/managed
COPY policies/rbi.json /opt/iwa/policies/rbi.json
COPY entrypoint.sh netns-rules.sh netprobe.py /opt/iwa/
COPY agent/iwa_agent /opt/iwa/agent/iwa_agent
COPY ext /opt/iwa/ext
COPY nativehost.py /opt/iwa/nativehost.py
COPY native-messaging-host.json /etc/chromium/native-messaging-hosts/com.infisical.rbi.json
RUN mkdir -p /opt/iwa/keys /etc/chromium/native-messaging-hosts \
    && openssl genrsa -out /opt/iwa/keys/ext.pem 2048 2>/dev/null \
    && openssl rsa -in /opt/iwa/keys/ext.pem -pubout -outform DER -out /tmp/ext.pub.der 2>/dev/null \
    && PUB_B64=$(base64 -w0 /tmp/ext.pub.der) \
    && sed -i "s#__EXTENSION_KEY__#$PUB_B64#" /opt/iwa/ext/manifest.json \
    && chromium --no-sandbox --pack-extension=/opt/iwa/ext --pack-extension-key=/opt/iwa/keys/ext.pem >/dev/null 2>&1 \
    && EXT_ID=$(python3 -c 'import hashlib; b=hashlib.sha256(open("/tmp/ext.pub.der","rb").read()).digest()[:16]; print("".join(chr(97+(x>>4)) + chr(97+(x&15)) for x in b))') \
    && sed -i "s/__EXTENSION_ID__/$EXT_ID/g" /opt/iwa/ext/updates.xml \
    && printf '%s\n' "$EXT_ID" >/opt/iwa/ext-id \
    && sed -i "s#chrome-extension://\*/#chrome-extension://$EXT_ID/#" /etc/chromium/native-messaging-hosts/com.infisical.rbi.json \
    && rm -rf /opt/iwa/keys /tmp/ext.pub.der \
    && chmod 0755 /opt/iwa/entrypoint.sh /opt/iwa/netns-rules.sh /opt/iwa/netprobe.py /opt/iwa/nativehost.py \
    && chmod -R a-w,a+rX /opt/iwa /etc/chromium
ENV PYTHONPATH=/opt/iwa/agent PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 1000:1000
WORKDIR /home/rbi
ENTRYPOINT ["/opt/iwa/entrypoint.sh"]
