# Runtime examples for PR #33

These are real honeypot outputs from **controlled harmless test traffic** in a
new isolated Ubuntu 26.04 ARM64 Lima VM, captured on 2026-10-30. They are **not
wild-caught attacks**. Test credentials/payloads were deliberately generated.
No production data, private keys or actual service credentials are included.

## What this example covers

Actual structured Glutton TCP/UDP sessions from the native TPROXY integration test, with binary/TLS/handler metadata. diagnostic.log is separately supplied and is not mixed into the session input: some INFO packet diagnostics have legacy-compatible endpoints and would duplicate session traffic if configured as a second input. Configure only glutton.log. Historical slog/hex examples are not falsely presented as newly produced logs.

## Run from the ewsposter checkout

Use this PR's branch and a Python environment containing the checkout's
`requirements.txt`. Dependencies belong in a virtual environment:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python examples/pr-33/verify.py
```

For an already prepared environment use its Python executable instead.
Expected: exit status 0 and a final `PASS:` line. Run the existing PR tests too;
the example replay complements them, it does not replace them.


The verifier starts a local HTTP sink, then imports the **real PR parser and EAlert**.
It uses the actual XML/JSON serialization and POST path, not a fake EAlert.
Both backend URLs point to that local sink. HPFeeds and InfluxDB are disabled.
Proxy environment settings are disabled for the replay child. Its timezone is
fixed to UTC so parsers using the local timezone produce stable expected output.
Outputs and indexes live in a temporary directory, not in this checkout.
It checks every supplied expected alert field and repeats the pass with preserved
indexes, requiring **zero additional POSTs**. `expected.json` records the verified
XML alert content for these fixed captured inputs; it is not a fabricated log.
Producer `src_ip` values are isolated VM/container-network addresses.
The replay's external target is the documentation address `192.0.2.10`.


## Network isolation used for validation

Validation ran on Python 3.14.4 inside a new network namespace with only loopback
enabled. To repeat that additional isolation on Linux (using an absolute path
to your prepared Python), run:

```sh
sudo unshare -n sh -c 'ip link set lo up; exec "$@"' sh \
  "$PWD/.venv/bin/python" "$PWD/examples/pr-33/verify.py"
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

Producer images were built from T-Pot source commit
`69accabc24d58cbe75d8c382f06a84018251b679`. This local source snapshot need not
already be available as a public remote commit. The supplied log/payload files
are sufficient for offline ewsposter testing without rebuilding a honeypot.
The capture started with T-Pot's `docker/_tests/tests/glutton.sh`
and its unchanged producer configuration, using loopback ports and retained
artifacts; protocol/configuration details are in that source snapshot.
Additional controlled requests, where used, are included in `capture-requests.py`.
That capture companion assumes the original VM's retained smoke-test artifacts;
it records how the traffic was generated, not the portable replay entry point.
Use `verify.py` above to test the supplied files on another machine.

Runtime addresses, timestamps, IDs and original container file references in
the logs were not rewritten. Stored files are placed under `payloads/` with
the relative path structure needed by the parser; private keys and unrelated
runtime state were never included. No live EWS backend was contacted.

## Boundaries

The capture documents the cases above, not every possible historic schema or
malformed input. File rotation, interrupted writes and omitted files in the
shared-helper examples are explicit replay manipulations, not claims about
what a running producer naturally wrote. No production parser changes are
part of this example commit.

## EOF regression exposed by the real capture

The original PR head `a36c0d3ab20cc62d9c0a6f1fdfe1e14a9ec4bd0e` loops forever at the
actual `EAlert.lineREAD` EOF value `()`. Its unit-test stand-in supplied an empty
string instead. The full captured-file replay reproduced the hang under a
bounded timeout. The separately authorized preceding fix commit `bba86131faccd25a3599b9ae6bcf4a8748d826fa` adds
that EOF case, with a RED-to-GREEN regression test and a guard that `[]`, false
and zero JSON values still get skipped rather than prematurely ending the scan.
All 11 parser tests pass on Python 3.12 and 3.14. These supplied files were
validated against the fixed implementation, without modifying EAlert.
