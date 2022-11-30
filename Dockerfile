FROM alpine:3.15

ARG VERSION TITLE DESCRIPTION LICENSES URL CREATED REVISION

LABEL org.opencontainers.image.version="$VERSION" \
      org.opencontainers.image.authors="armedpot <armedpot@norad.de>" \
      org.opencontainers.image.title="$TITLE" \
      org.opencontainers.image.description="$DESCRIPTION" \
      org.opencontainers.image.licenses="$LICENSES" \
      org.opencontainers.image.url="$URL" \
      org.opencontainers.image.created="$CREATED" \
      org.opencontainers.image.revision="$REVISION"

RUN apk -U --no-cache add \
    python3 \
    py3-pip \
    py3-requests \
    py3-lxml \
    git && \
    git clone https://github.com/telekom-security/ewsposter /opt/ewsposter && \
    cd /opt/ewsposter && \
    mkdir -p spool log json && \
    #git checkout dev_v1.24.0 && \
    pip install --no-cache-dir hpfeeds3 xmljson influxdb-client influxdb && \
    adduser --disabled-password --shell /bin/ash --uid 2000 ews && \
    cp /opt/ewsposter/ews.cfg.docker /opt/ewsposter/ews.cfg && \
    chown -R ews:ews /opt/ewsposter && \
    apk del git


STOPSIGNAL SIGKILL

USER ews:ews
WORKDIR /opt/ewsposter

CMD [ "python3", "ews.py",  "-l 0" ]
