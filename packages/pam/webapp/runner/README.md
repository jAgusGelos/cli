# Web App runner (F1)

One disposable Chromium per Web App PAM session, next to the gateway. Three pieces, all specified by
`.workspace/features/INF-WEBAPP/contracts/CONTRACTS.md` (sections 2, 3 and 4):

| Piece | Path | What it does |
|---|---|---|
| Runner image | `runner/image/` | Pinned Debian + Chromium kiosk on Xvfb, managed policies, Python agent `iwa_agent` |
| Supervisor | `supervisor/` (`cmd/iwa-supervisor`) | Host process, HTTP/1.1 on a unix socket: launch, status, destroy runners on `iwa-runners` with netns egress rules |
| Harness | `runner/harness/` | Standalone fake gateway (agent link + CONNECT proxy) that drives one runner end to end and checks the output |

## Build

```bash
docker build -t infisical-webapp-runner:dev packages/pam/webapp/runner/image
docker image inspect --format '{{.Id}}' infisical-webapp-runner:dev   # the digest to pin
go build -o /tmp/iwa/iwa-supervisor ./packages/pam/webapp/supervisor/cmd/iwa-supervisor
go build -o /tmp/iwa/iwa-harness ./packages/pam/webapp/runner/harness
```

Current image (M3, 2026-10-15 15:45):
`infisical-webapp-runner@sha256:044a632374ed2c831d5bf7b26250ef64962c9e7991e659a5ca91e8678b146a4a`
(Chromium `155.0.8059.79-1~deb13u1`, base `debian@sha256:04634311...0a28a`). Every rebuild changes the digest: refresh
both env lines below.

## Pinning the image in the gateway config

The supervisor only runs images in its allowlist, resolves the ref to the local image ID and always runs
`docker run ... sha256:<id>`, so a retag cannot swap the image. The running container's `{{.Image}}` equals the pinned
digest (checked by the harness).

```bash
# supervisor (demo only: a release build ships the allowlist of Infisical-published digests instead)
INFISICAL_WEBAPP_RUNNER_IMAGES=infisical-webapp-runner@sha256:044a632374ed2c831d5bf7b26250ef64962c9e7991e659a5ca91e8678b146a4a
# gateway: the image ref it sends as `image` in POST /v1/runners
INFISICAL_WEBAPP_RUNNER_IMAGE=infisical-webapp-runner@sha256:044a632374ed2c831d5bf7b26250ef64962c9e7991e659a5ca91e8678b146a4a
# both sides, optional override of /tmp/infisical-webapp/supervisor.sock
INFISICAL_WEBAPP_SUPERVISOR_SOCKET=/tmp/infisical-webapp/supervisor.sock
```

See `supervisor.env.example`. A bare tag (`infisical-webapp-runner:dev`) or any ref outside the allowlist gets
`403 image_not_allowed`.

## Run the supervisor

```bash
INFISICAL_WEBAPP_RUNNER_IMAGES=<ref above> /tmp/iwa/iwa-supervisor
curl --unix-socket /tmp/infisical-webapp/supervisor.sock http://x/v1/health
```

At startup it creates `iwa-runners` (`--internal`, `172.28.0.0/24`, bridge `iwa-runners0`, default gateway mode) so
the host owns `172.28.0.1`; the gateway binds its runner listeners after `/v1/health` returns `ok`. Stopping the
supervisor leaves running sessions alone; `DELETE /v1/runners/{sessionId}` removes runner, netns pause container and
helper (idempotent). Max concurrent runners: `INFISICAL_WEBAPP_MAX_RUNNERS` (default 4).

Fixed launch spec (CONTRACTS 3): `--read-only`, tmpfs `/tmp` `/home/rbi` `/quarantine` owned by uid 1000,
`--shm-size 1g`, custom seccomp (Docker default plus `clone`, `clone3`, `unshare`, `setns`), `no-new-privileges`,
`--cap-drop ALL --cap-add SYS_CHROOT` (enough for the Chromium sandbox as uid 1000, verified), `--user 1000:1000`,
`--network container:iwa-netns-<12hex>`. The netns egress rules (`OUTPUT DROP` except loopback and the gateway agent
and proxy ports on `172.28.0.1`) are applied by a one-shot `NET_ADMIN` helper before the runner starts; the runner
never holds `NET_ADMIN`. `IWA_*` values reach docker through the client environment, never argv.

## Run the harness (no live stack)

The harness uses ports 17701/13128 on `172.28.0.1` so it never collides with the live gateway (7701/3128). It needs
the demo app `iwa-demo-app` (F6, `demo/webapp/up.sh`) or `-start-demo-app`.

```bash
mkdir -p /tmp/iwa-f1
INFISICAL_WEBAPP_SUPERVISOR_SOCKET=/tmp/iwa-f1/supervisor.sock INFISICAL_WEBAPP_RUNNER_IMAGES=<ref> /tmp/iwa/iwa-supervisor &
/tmp/iwa/iwa-harness -socket /tmp/iwa-f1/supervisor.sock -image <ref> -agent-port 17701 -proxy-port 13128 -out /tmp/iwa-f1/run1
```

Exit 0 means: agent handshake, live H.264 decoded, forced keyframe, recording init + 10 s segments with matching
sha256 (H.264 High, IDR first), input seen by the demo app, netns check (`172.28.0.1:80/8080` and DNS fail, agent and
proxy ports reachable), image pin, clean destroy, no runner token in any log. Outputs land in `-out`.

Extra scenarios (each still runs the default checks):

| Flag | What it adds |
|---|---|
| `-codec vp9` | `live_start vp9`: `VIDEO_CONFIG vp09.00.10.08`, VP9 frames written to `live.ivf` and decoded; recording stays H.264 |
| `-lockdown` | Injects F12, Ctrl+Shift+I, Ctrl+N + typed `chrome://settings`, Shift+Esc, Ctrl+P and the rogue CRX link; frames and window lists per step, `watchdog_closed` events |
| `-measure 60` | Wheel motion on the input page while sampling `docker stats` every 2 s; writes `measure.json` |
| `-stall-test` | SIGSTOP Xvfb for 2 s; expects exactly one `REC_LOSS capture_stall` |
| `-reconnect-test` | Drops the agent link mid-run; expects a re-dial, continued segment indexes and a new live epoch on `live_start` |

## Extension and download controls (M3)

The image packs `ext/` into `ext.crx` with a build-local RSA key and serves an update manifest at
`file:///opt/iwa/ext/updates.xml`. The managed policy force-installs it and the Chromium command also loads the same
immutable extension directory as a delivery fallback. The extension registers `com.infisical.rbi`; the native host
uses `/tmp/iwa/native.sock` and never writes credentials to logs. The agent forwards `ext_hello`,
`credential_injected`, `login_result`, `guard_closed`, `nav_blocked`, `pong`, and `download` as `AGENT_EVENT` frames.
Downloads are forced to `/quarantine`; the agent-side completion path hashes the file before emitting `download`.

The native host accepts only the Chrome little-endian length-prefixed JSON protocol and caps messages at 4 MiB. A
release image must replace the build-local extension key and record the resulting CRX id in its image provenance.

## Tests

```bash
go test ./packages/pam/webapp/...
IWA_DOCKER_TESTS=1 go test ./packages/pam/webapp/supervisor/ -run Docker -v
python3 -m unittest discover -s packages/pam/webapp/runner/image/agent/tests -v
# in-image selftests (inside a runner started with the launch spec)
python3 -m iwa_agent.selftest live
python3 -m iwa_agent.selftest recorder
```

## Wire notes for F2

- `AGENT_HELLO.liveCodecs` is `["vp9","h264"]`. VP9 live: `VIDEO_CONFIG {"codec":"vp09.00.10.08",...}` with no
  `format`, one VP9 frame per `VIDEO_CHUNK`. Every `live_start` restarts the live encoder and bumps `epoch`;
  `live_quality` does the same with the new bitrate; `live_pause`/`live_resume` stop and restart sending (resume starts
  with a keyframe).
- The X11 watchdog closes any extra top-level window (Task Manager, Ctrl+N windows) and sends
  `AGENT_EVENT {"kind":"watchdog_closed","wmClass","wmName"}`.
- `REC_LOSS capture_stall` after >= 1 s without captured frames. On link loss the agent keeps capturing and recording,
  re-dials with the same token for 30 s (new `AGENT_HELLO`, `seq` from 0), re-sends up to 60 s of buffered segments,
  and waits for a new `live_start`; after 30 s it exits 2.
- `ime` and `paste` text is typed per character (Unicode through a temporary keysym remap).
- `VIDEO_CONFIG.codec` for H.264 is derived from the live encoder's SPS: today `avc1.42C01F` (Constrained Baseline, level 3.1),
  Annex B, SPS/PPS before every IDR. The viewer must pass it through (CONTRACTS 1.6), not hardcode `avc1.42E01F`.
- `REC_INIT.codec` comes from the init's `avcC` (`avc1.64001f`, High); `timescale` 90000; `ptsZeroUnixMs` set.
- The agent sends `REC_*` only after `AGENT_WELCOME ok`; on `shutdown` it flushes the partial segment and exits 0.
- Chromium still tries Google background hosts through the proxy; the egress proxy must refuse non-allowlisted
  CONNECTs immediately (a hanging CONNECT delays page loads).
