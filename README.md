# Hugging Face Agent Intrusion Emulation Kit for Elastic

A safe, synthetic Elastic Security emulation kit for the public Hugging Face agent intrusion timeline.

This repository contains:

- A GitHub Pages-ready explainer site in `index.html`
- A portable Python runner in `scripts/run_hf_emulation.py`
- Synthetic telemetry shaped around the public Hugging Face incident
- Out-of-box Elastic Security and Elastic Defend coverage mapping
- Optional generated SIEM rules for test clusters that need extra alert signal

> This project is an independent synthetic Elastic emulation. It is not affiliated with Hugging Face.

## Live Site

This repo is prepared for GitHub Pages with the custom domain:

```text
hf-incident.threatsearch.io
```

GitHub Pages files:

- `CNAME` points to `hf-incident.threatsearch.io`
- `.nojekyll` disables Jekyll processing for static assets/files

Repository URL:

```text
https://github.com/jamesspi/hf-incident-emulation
```

## Credit

The campaign narrative, phase structure, and representative techniques are inspired by Hugging Face's public incident materials:

- [Anatomy of a Frontier Lab Agent Intrusion: A Technical Timeline](https://huggingface.co/blog/agent-intrusion-technical-timeline)
- [Anatomy of a Frontier Lab Agent Intrusion - Replay](https://huggingface-anatomy-of-frontier-lab-model-intrusion.static.hf.space/index.html)

Those original Hugging Face materials are the primary source for the intrusion story. This repo only translates the publicly described behaviors into safe synthetic telemetry and Elastic-oriented coverage mapping.

## Safety Scope

The runner creates synthetic telemetry only.

It does not:

- Run exploit payloads
- Create Kubernetes pods
- Contact cloud metadata endpoints
- Enroll VPN or mesh devices
- Access source control systems
- Touch real Hugging Face, OpenAI, cloud, Kubernetes, GitHub, or Tailscale infrastructure

All hostnames, users, cloud identities, IPs, auth keys, dataset names, and URLs are fake or reserved for documentation/testing.

## How It Works

The runner writes ECS-aligned synthetic documents to dedicated data streams:

```text
logs-frontier_lab_agent_emulation.endpoint-default
logs-frontier_lab_agent_emulation.kubernetes-default
logs-frontier_lab_agent_emulation.cloud-default
logs-frontier_lab_agent_emulation.github-default
logs-frontier_lab_agent_emulation.app-default
```

Each run gets:

- `run_id`
- `run_tag`
- `labels.campaign_id`
- `labels.attack_phase`

The generated events model phases such as:

- Dataset-worker local file disclosure
- Encoded Python payload execution
- Linux service-account token discovery
- Kubernetes TokenRequest and RBAC review
- Privileged pod / hostPath / chroot-style node pivot
- Cloud metadata and IAM enumeration
- Tailscale userspace SOCKS proxy pivot
- GitHub App token and repository activity
- Chunked public dead-drop exfiltration

## OOTB-First Coverage

The runner is OOTB-first by default. It creates synthetic telemetry designed to exercise out-of-box Elastic coverage when the relevant integrations, endpoint protections, and prebuilt rules are installed and enabled.

Optional generated rules are not created unless you pass:

```sh
--include-custom-rules
```

This keeps the default story focused on Elastic's out-of-box SIEM and endpoint coverage.

## Elastic Security / SIEM Rules

The relevant SIEM rule coverage includes:

- Suspicious Child Execution via Web Server
- Curl or Wget Spawned via Node.js
- GenAI Process Accessing Sensitive Files
- GenAI Process Connection to Unusual Domain
- GenAI Process Connection to Suspicious Top Level Domain
- GenAI Process Performing Encoding/Chunking Prior to Network Activity
- Connection to Common Large Language Model Endpoints
- Unusual Process Modifying GenAI Configuration File
- GenAI CLI Started with Unsafe Permission Bypass
- Elastic Defend Alert from GenAI Utility or Descendant
- LLM-Based Attack Chain Triage by Host
- Kubernetes Denied Service Account Request via Unusual User Agent
- Kubernetes Suspicious Self-Subject Review via Unusual User Agent
- Kubernetes Multi-Resource Discovery
- Kubernetes Secret get or list with Suspicious User Agent
- Kubernetes Secret get or list from Node or Pod Service Account
- Kubernetes Service Account Token Created via TokenRequest API
- Kubernetes Direct API Request via Curl or Wget
- [Kubernetes Privileged Pod Created](https://github.com/elastic/detection-rules/blob/main/rules/integrations/kubernetes/privilege_escalation_privileged_pod_created.toml)
- [Kubernetes Pod Created with a Sensitive hostPath Volume](https://github.com/elastic/detection-rules/blob/main/rules/integrations/kubernetes/privilege_escalation_pod_created_with_sensitive_hostpath_volume.toml)
- AWS Discovery API Calls via CLI from a Single Resource
- AWS STS GetCallerIdentity API Called for the First Time
- AWS EC2 Role GetCallerIdentity from New Source AS Organization

## Elastic Defend Endpoint Protections

The relevant endpoint-side protection coverage includes:

- Suspicious Web Server Child Process
- Payload Downloaded via Curl or Wget by Web Server
- Payload Execution by Web Server
- Payload Execution by Node.js Web Server
- [Decoded Payload Piped to Interpreter](https://github.com/elastic/protections-artifacts/blob/main/behavior/rules/linux/defense_evasion_decoded_payload_piped_to_interpreter.toml)
- [Suspicious Python Encoded Payload Execution](https://github.com/elastic/protections-artifacts/blob/main/behavior/rules/linux/execution_suspicious_python_encoded_payload_execution.toml)
- DNS Request by Recently Created Executable
- Environment Variable Secret Collection
- Multi-Value Secret Searching via Grep
- Cloud Credential Files Accessed by Process in Suspicious Directory
- Persistence via GenAI Tool
- Suspicious Binary Execution via Path Alias

## Optional Generated Rules

For labs that do not have the relevant OOTB content installed or enabled, the runner can create temporary generated SIEM rules as gap-fill content:

```sh
python3 scripts/run_hf_emulation.py --include-custom-rules
```

Generated rules are disabled after the run by default. Use:

```sh
--keep-rules-enabled
```

to leave them enabled, or:

```sh
--delete-rules-after
```

to delete them after the run.

## Quick Start

Use environment variables for credentials:

```sh
export ELASTIC_USERNAME="elastic-user"
export ELASTIC_PASSWORD="elastic-password"

python3 scripts/run_hf_emulation.py \
  --es-url http://localhost:9200 \
  --kibana-url http://localhost:5601 \
  --space default
```

API key auth is also supported:

```sh
export ELASTIC_API_KEY="base64-or-encoded-api-key"

python3 scripts/run_hf_emulation.py \
  --es-url https://your-es.example.com \
  --kibana-url https://your-kibana.example.com \
  --space default
```

## Connector Selection

The runner does not choose an AI/inference connector automatically.

List available AI/inference connectors:

```sh
python3 scripts/run_hf_emulation.py --list-connectors
```

Then specify one explicitly if you want the run to request an attack narrative:

```sh
python3 scripts/run_hf_emulation.py \
  --connector-name "OpenAI GPT-5.5"
```

or:

```sh
python3 scripts/run_hf_emulation.py \
  --connector-id ".openai-gpt-5.5-chat_completion" \
  --connector-type ".inference" \
  --connector-name "OpenAI GPT-5.5"
```

## Alert-Only Mode

Create data and alerts only:

```sh
python3 scripts/run_hf_emulation.py --skip-attack-discovery
```

## Cleanup

The runner leaves source data, generated alerts, and narrative results in place for review.

Delete synthetic data streams when you no longer need source documents:

```http
DELETE _data_stream/logs-frontier_lab_agent_emulation.endpoint-default
DELETE _data_stream/logs-frontier_lab_agent_emulation.kubernetes-default
DELETE _data_stream/logs-frontier_lab_agent_emulation.cloud-default
DELETE _data_stream/logs-frontier_lab_agent_emulation.github-default
DELETE _data_stream/logs-frontier_lab_agent_emulation.app-default
```

If generated rules were used, they are disabled by default. Use `--delete-rules-after` if you want them deleted automatically.

## Repository Structure

```text
.
├── CNAME
├── README.md
├── index.html
├── .nojekyll
└── scripts/
    └── run_hf_emulation.py
```

## Publishing Notes

Suggested GitHub Pages settings once the repo is pushed:

- Source: deploy from branch
- Branch: `main`
- Folder: `/`
- Custom domain: `hf-incident.threatsearch.io`

DNS should point the domain to GitHub Pages according to GitHub's current custom domain instructions.

## Disclaimer

This project is for defensive validation, education, and lab testing. It is a synthetic emulation of publicly described behavior. It does not contain working exploit payloads and should not be used to target real systems.

Hugging Face owns the original public incident writeups and replay linked above. This repository is an independent Elastic-focused emulation kit built from those public materials.
