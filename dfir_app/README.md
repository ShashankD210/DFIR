# DFIR Cloud + Local Application

This folder contains both halves of the same application:

- `server.py` is the cloud control plane and can also run locally.
- `local_connector.py` runs on an investigator's machine and connects outbound
  to the server.
- `Dockerfile` packages the cloud service for any container host.
- `docker-compose.yml` runs the cloud service locally using the same image
  definition used for deployment.
- `start-local.sh` starts the local connector with the structured environment.

The connector polls over HTTPS, so the local machine does not need an exposed
inbound port.

## Start the cloud service locally

From this folder:

```bash
export DFIR_ADMIN_TOKEN="replace-with-a-long-random-secret"
docker compose up --build
```

The API is then available at `http://127.0.0.1:8080`. For a cloud host, build
and deploy this folder as a container, set `DFIR_ADMIN_TOKEN` as a secret, and
mount persistent storage at `/app/data` for the SQLite database. Put the
service behind HTTPS before connecting an agent outside the local network.

## Run locally

The recommended local layout is:

```text
dfir_app/
├── server.py              # cloud control plane
├── local_connector.py     # local outbound connector
├── ../dfir_toolkit.py     # shared DFIR execution toolkit
├── data/                  # local runtime data and SQLite files
├── output/                # hashes and collected evidence
└── logs/                  # local connector logs
```

The connector integrates directly with the repository's
`../dfir_toolkit.py`. Set `DFIR_TOOLKIT_PATH` when the toolkit is stored
elsewhere.

```bash
export DFIR_ADMIN_TOKEN="replace-with-a-long-random-secret"
python3 server.py
```

Register a local connector and save the returned token securely:

```bash
curl -sS -X POST http://127.0.0.1:8080/api/agents \
  -H "Authorization: Bearer $DFIR_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"my-workstation"}'
```

Run the connector with the returned `id` and `token`:

```bash
export DFIR_CLOUD_URL="http://127.0.0.1:8080"
export DFIR_AGENT_ID="..."
export DFIR_AGENT_TOKEN="..."
./start-local.sh
```

Queue a safe, allowlisted action:

```bash
curl -sS -X POST "$DFIR_CLOUD_URL/api/agents/$DFIR_AGENT_ID/commands" \
  -H "Authorization: Bearer $DFIR_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"action":"check-tools"}'
```

For a cloud deployment, set `DFIR_ADMIN_TOKEN` as a platform secret, mount a
persistent volume for `DFIR_DATABASE`, and put the service behind HTTPS. Do
not commit admin or agent tokens. The current version intentionally supports
only `check-tools`, `hash`, and `logs`; expand the allowlist carefully.
