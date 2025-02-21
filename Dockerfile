FROM alpine:3.20

ARG VERSION AUTHOR TITLE DESCRIPTION LICENSES URL CREATED REVISION

LABEL org.opencontainers.image.version="$VERSION" \
      org.opencontainers.image.authors="$AUTHOR" \
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
    git checkout master && \
    pip install --no-cache-dir -r requirements.txt && \
    adduser --disabled-password --shell /bin/ash --uid 2000 ews && \
    cp /opt/ewsposter/ews.cfg.docker /opt/ewsposter/ews.cfg && \
    chown -R ews:ews /opt/ewsposter && \
    apk del git


STOPSIGNAL SIGKILL

USER ews:ews
WORKDIR /opt/ewsposter

CMD [ "python3", "ews.py",  "-l 1" ]
