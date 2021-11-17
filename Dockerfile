FROM alpine:latest

RUN apk -U --no-cache add \
    python3 \
    py3-pip \
    py3-requests \
    py3-lxml \
    git && \
    git clone https://github.com/telekom-security/ewsposter /opt/ewsposter && \
    cd /opt/ewsposter && \
    mkdir -p spool log json && \
    #git checkout develop && \
    pip install --no-cache-dir hpfeeds3 xmljson influxdb-client influxdb influxdb-client[ciso] && \
    adduser --disabled-password --shell /bin/ash --uid 2000 ews && \
    chown -R ews:ews /opt/ewsposter && \
    apk del git

ADD --chown=ews:ews ews.cfg.docker /opt/ewsposter/ews.cfg

STOPSIGNAL SIGKILL

USER ews:ews
WORKDIR /opt/ewsposter

CMD python3 ews.py -l 30
