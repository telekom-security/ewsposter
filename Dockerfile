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

ENV PATH="/opt/ewsposter/bin:$PATH"

RUN apk -U --no-cache add \
    python3 \
    py3-virtualenv \
    py3-pip \
    git && \
    git clone https://github.com/telekom-security/ewsposter /opt/ewsposter && \
    adduser --disabled-password --shell /bin/ash --uid 2000 ews && \
    cd /opt/ewsposter && \
    mkdir -p spool log json && \
    git checkout master && \
    cp /opt/ewsposter/ews.cfg.docker /opt/ewsposter/ews.cfg && \
    python3 -m venv /opt/ewsposter && \
    source /opt/ewsposter/bin/activate && \
    pip3 install --upgrade setuptools wheel && \
    pip3 install -r requirements.txt && \
    chown -R ews:ews /opt/ewsposter && \
    apk del git

STOPSIGNAL SIGKILL

USER ews:ews
WORKDIR /opt/ewsposter

CMD [ "python3", "ews.py",  "-l 1" ]
