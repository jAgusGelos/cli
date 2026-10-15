// Package webapp is the gateway side of a Web App PAM session (INF-WEBAPP): it launches a disposable remote browser
// through the runner supervisor, accepts the runner agent link, relays live video to the viewer tunnel, filters and
// injects viewer input, records every fact as signed evidence (package recorder) and enforces egress through its own
// proxy (package egress). The wire and data formats come from package contract; nothing here re-implements them.
//
// The gateway reads this environment once, at start:
//
//	INFISICAL_WEBAPP_SUPERVISOR_SOCKET  unix socket of the runner supervisor
//	                                    default /tmp/infisical-webapp/supervisor.sock
//	INFISICAL_WEBAPP_RUNNER_IMAGE       runner image reference sent with every launch (must be in the supervisor
//	                                    allowlist), e.g. infisical-webapp-runner@sha256:<64 hex>; no default
//	INFISICAL_WEBAPP_HOSTS_OVERRIDE     comma-separated host=ip pairs the egress proxy consults before DNS,
//	                                    e.g. app.corp.internal=172.27.0.10; default empty (system resolver only)
//	INFISICAL_WEBAPP_AGENT_ADDR         listen address of the runner-agent endpoint, default 172.28.0.1:7701
//	INFISICAL_WEBAPP_PROXY_ADDR         listen address of the egress proxy, default 172.28.0.1:3128
//	INFISICAL_GATEWAY_DIR               directory of webapp-recording-key.pem (Ed25519, PKCS#8, mode 0600, created on
//	                                    first start); default the gateway session recording dir
//	                                    (/var/lib/infisical/session_recordings unless overridden)
//
// Both listeners bind only after the supervisor answers GET /v1/health with ok (the runner bridge, and so
// 172.28.0.1, exists only then). The gateway retries every 2 s for 60 s and then logs
// "Web App sessions disabled: supervisor unavailable"; every web-app session then fails with CONTROL error
// runner_unavailable. At start the gateway logs "Web App recording key fingerprint: SHA256:..."; record it out of
// band, it is the trust anchor of every replay.
//
// Example (demo host):
//
//	INFISICAL_WEBAPP_RUNNER_IMAGE=infisical-webapp-runner@sha256:... \
//	INFISICAL_WEBAPP_HOSTS_OVERRIDE=app.corp.internal=172.27.0.10 \
//	INFISICAL_GATEWAY_DIR=$HOME/.infisical-gateway \
//	infisical gateway start ...
package webapp
