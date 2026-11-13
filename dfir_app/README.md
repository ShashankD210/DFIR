# DFIR Cloud + Local Application

This folder contains both halves of the same application:

- `server.py` is the cloud control plane and can also run locally.
- `local_connector.py` runs on an investigator's machine and connects outbound
  to the server.
- `toolkit_runner.py` is the shared execution wrapper for `dfir_toolkit.py`.
- `Dockerfile` packages the cloud service for any container host.
- `docker-compose.yml` runs the cloud service locally using the same image
  definition used for deployment.
- `start-local.sh` starts the local connector with the structured environment.

The connector polls over HTTPS, so the local machine does not need an exposed
inbound port.

Both environments run the same toolkit actions. The local connector executes
the repository toolkit on the local machine; the authenticated cloud endpoint
`POST /api/cloud/execute` executes the same toolkit inside the cloud container.
Supported actions are `check-tools`, `triage`, `hash`, `memory`, `yara`,
`capture`, `logs`, `rootkit`, and `report`. `install-all` is intentionally not
remote-enabled because it changes the host package environment.

## Start the cloud service locally

From the repository root:

```bash
export DFIR_ADMIN_TOKEN="replace-with-a-long-random-secret"
docker compose -f dfir_app/docker-compose.yml up --build
```

The API is then available at `http://127.0.0.1:8080`. For a cloud host, build
and deploy from the repository root with
`docker build -f dfir_app/Dockerfile .`, set `DFIR_ADMIN_TOKEN` as a secret,
and mount persistent storage at `/app/data` for the SQLite database and toolkit
output. Put the
service behind HTTPS before connecting an agent outside the local network.

## Run locally

The recommended local layout is:

```text
dfir_app/
├── server.py              # cloud control plane
├── local_connector.py     # local outbound connector
├── dfir_toolkit.py        # shared DFIR execution toolkit
├── data/                  # local runtime data and SQLite files
├── output/                # hashes and collected evidence
└── logs/                  # local connector logs
```

The connector integrates directly with the repository's
`dfir_toolkit.py`. It is linked to the repository's canonical toolkit so the
cloud and local applications run the same file. Set `DFIR_TOOLKIT_PATH` only
when the toolkit is stored elsewhere.

```bash
cd dfir_app
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

Run the same toolkit directly in the cloud container:

```bash
curl -sS -X POST "$DFIR_CLOUD_URL/api/cloud/execute" \
  -H "Authorization: Bearer $DFIR_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"action":"check-tools"}'
```

For a cloud deployment, set `DFIR_ADMIN_TOKEN` as a platform secret, mount a
persistent volume for `DFIR_DATABASE`, and put the service behind HTTPS. Do
not commit admin or agent tokens. Privileged actions such as triage, capture,
and rootkit checks require the same operating-system permissions as the
underlying toolkit command.
