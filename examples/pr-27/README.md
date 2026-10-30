# Runtime examples for PR #27

These are explicitly prepared address-discovery inputs and offline
reproduction steps, validated in an isolated Ubuntu 26.04 ARM64 Lima VM on
2026-10-30. No honeypot capture or real ipify response is claimed for this
configuration-only change.

## What this example covers

This change concerns address discovery, not a honeypot log schema. Supplied addresses and ews.ip are explicit test inputs. The reproduction calls the real getIP/getExternalIP code, substituting only the external HTTP response/failure. No ipify response or production-network log is fabricated.

## Run from the ewsposter checkout

Use this PR's branch and a Python environment containing the checkout's
`requirements.txt`. Dependencies belong in a virtual environment:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python examples/pr-27/reproduce.py
```

For an already prepared environment use its Python executable instead.
Expected: exit status 0 and a final `PASS:` line. Run the existing PR tests too;
the example replay complements them, it does not replace them.


The reproduction uses the actual implementation on this PR branch, with explicit
assertions for the changed behavior and temporary independent state. It does not
send EWS/HPFeeds/Influx messages. Network lookups, where relevant, are controlled
test responses, not a call to an external service. No parser code is patched.
Prepared file states are clearly separated from original `logs/` captures.


## Network isolation used for validation

Validation ran on Python 3.14.4 inside a new network namespace with only loopback
enabled. To repeat that additional isolation on Linux (using an absolute path
to your prepared Python), run:

```sh
sudo unshare -n sh -c 'ip link set lo up; exec "$@"' sh \
  "$PWD/.venv/bin/python" "$PWD/examples/pr-27/reproduce.py"
```

The IP-discovery example can log that the intentionally isolated namespace has
no route for internal-address detection. That diagnostic is expected; its
external-lookup assertions must still pass.

## Provenance and regeneration

`provenance.json` records the exact ewsposter head, T-Pot source commit,
native architecture, local image content ID and hashes of the original captured
files where applicable. `producer/Dockerfile.txt`, when present, records the
producer image recipe and upstream version/pin used for this capture.
The package's `.gitattributes` disables newline conversion to preserve captured
file hashes and prepared byte-boundary fixtures across checkouts.
The local image tag/content ID identifies the capture; it is not a promise that
this image has been uploaded to a registry.

`inputs/sources.json` and `inputs/ews.ip` contain only documentation
addresses and explicit configuration cases. `reproduce.py` invokes the real
address-discovery code, with controlled HTTP response/error objects and
assertions. No producer image or runtime honeypot log is needed for this case.

## Boundaries

The capture documents the cases above, not every possible historic schema or
malformed input. File rotation, interrupted writes and omitted files in the
shared-helper examples are explicit replay manipulations, not claims about
what a running producer naturally wrote. No production parser changes are
part of this example commit.
