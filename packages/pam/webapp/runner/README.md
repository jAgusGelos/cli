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

Current image (M1, 2026-10-15 14:56):
`infisical-webapp-runner@sha256:2f17c9aebe3787d0a34d5239acb7c06766518e64f1a4121db698cbc208986513`
(Chromium `155.0.8059.79-1~deb13u1`, base `debian@sha256:04634311...0a28a`). Every rebuild changes the digest: refresh
both env lines below.

## Pinning the image in the gateway config

The supervisor only runs images in its allowlist, resolves the ref to the local image ID and always runs
`docker run ... sha256:<id>`, so a retag cannot swap the image. The running container's `{{.Image}}` equals the pinned
digest (checked by the harness).

```bash
# supervisor (demo only: a release build ships the allowlist of Infisical-published digests instead)
INFISICAL_WEBAPP_RUNNER_IMAGES=infisical-webapp-runner@sha256:2f17c9aebe3787d0a34d5239acb7c06766518e64f1a4121db698cbc208986513
# gateway: the image ref it sends as `image` in POST /v1/runners
INFISICAL_WEBAPP_RUNNER_IMAGE=infisical-webapp-runner@sha256:2f17c9aebe3787d0a34d5239acb7c06766518e64f1a4121db698cbc208986513
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

- `VIDEO_CONFIG.codec` is derived from the live encoder's SPS: today `avc1.42C01F` (Constrained Baseline, level 3.1),
  Annex B, SPS/PPS before every IDR. The viewer must pass it through (CONTRACTS 1.6), not hardcode `avc1.42E01F`.
- `REC_INIT.codec` comes from the init's `avcC` (`avc1.64001f`, High); `timescale` 90000; `ptsZeroUnixMs` set.
- The agent sends `REC_*` only after `AGENT_WELCOME ok`; on `shutdown` it flushes the partial segment and exits 0.
- Chromium still tries Google background hosts through the proxy; the egress proxy must refuse non-allowlisted
  CONNECTs immediately (a hanging CONNECT delays page loads).
