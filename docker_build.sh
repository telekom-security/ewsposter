#!/bin/bash

export TITEL="ewsposter"
export VERSION="1.24"


docker build \
    --build-arg VERSION=${VERSION}\
    --build-arg TITEL=${TITLE} \
    --build-arg DESCRIPTION="collect logs and alerts from 27 honeypots and send it to backed (eg peba, geba), hpfeeds, influxdb or jSON file." \
    --build-arg LICENSES="GPL-3.0" \
    --build-arg URL="https://github.com/telekom-security/ewsposter" \
    --build-arg CREATED=$(date +"%Y-%m-%dT%H:%M:%N%z") \
    --build-arg REVISION=$(pwgen -A -r ghijklmnopqrstuvwxyz 40 1) \
    --tag mtr.devops.telekom.de/markus_schroer/${TITEL}:${VERSION} \
    . \
    --load
