# Hugging Face Agent Intrusion Replay for Elastic

A safe, synthetic replay of the public Hugging Face agent intrusion using Elastic Security detections.

This repository contains:

- A portable Python runner in `scripts/run_hf_emulation.py`
- Synthetic telemetry shaped around the public Hugging Face incident
- Out-of-box Elastic Security and Elastic Defend coverage mapping
- Optional generated SIEM rules for test clusters that need extra alert signal

> This project is an independent synthetic Elastic emulation. It is not affiliated with Hugging Face.

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

- [Suspicious Child Execution via Web Server](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22Suspicious%20Child%20Execution%20via%20Web%20Server%22&type=code)
- [Curl or Wget Spawned via Node.js](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22Curl%20or%20Wget%20Spawned%20via%20Node.js%22&type=code)
- [GenAI Process Accessing Sensitive Files](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22GenAI%20Process%20Accessing%20Sensitive%20Files%22&type=code)
- [GenAI Process Connection to Unusual Domain](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22GenAI%20Process%20Connection%20to%20Unusual%20Domain%22&type=code)
- [GenAI Process Connection to Suspicious Top Level Domain](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22GenAI%20Process%20Connection%20to%20Suspicious%20Top%20Level%20Domain%22&type=code)
- [GenAI Process Performing Encoding/Chunking Prior to Network Activity](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22GenAI%20Process%20Performing%20Encoding%2FChunking%20Prior%20to%20Network%20Activity%22&type=code)
- [Connection to Common Large Language Model Endpoints](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22Connection%20to%20Common%20Large%20Language%20Model%20Endpoints%22&type=code)
- [Unusual Process Modifying GenAI Configuration File](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22Unusual%20Process%20Modifying%20GenAI%20Configuration%20File%22&type=code)
- [GenAI CLI Started with Unsafe Permission Bypass](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22GenAI%20CLI%20Started%20with%20Unsafe%20Permission%20Bypass%22&type=code)
- [Elastic Defend Alert from GenAI Utility or Descendant](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22Elastic%20Defend%20Alert%20from%20GenAI%20Utility%20or%20Descendant%22&type=code)
- [LLM-Based Attack Chain Triage by Host](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22LLM-Based%20Attack%20Chain%20Triage%20by%20Host%22&type=code)
- [Kubernetes Denied Service Account Request via Unusual User Agent](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22Kubernetes%20Denied%20Service%20Account%20Request%20via%20Unusual%20User%20Agent%22&type=code)
- [Kubernetes Suspicious Self-Subject Review via Unusual User Agent](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22Kubernetes%20Suspicious%20Self-Subject%20Review%20via%20Unusual%20User%20Agent%22&type=code)
- [Kubernetes Multi-Resource Discovery](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22Kubernetes%20Multi-Resource%20Discovery%22&type=code)
- [Kubernetes Secret get or list with Suspicious User Agent](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22Kubernetes%20Secret%20get%20or%20list%20with%20Suspicious%20User%20Agent%22&type=code)
- [Kubernetes Secret get or list from Node or Pod Service Account](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22Kubernetes%20Secret%20get%20or%20list%20from%20Node%20or%20Pod%20Service%20Account%22&type=code)
- [Kubernetes Service Account Token Created via TokenRequest API](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22Kubernetes%20Service%20Account%20Token%20Created%20via%20TokenRequest%20API%22&type=code)
- [Kubernetes Direct API Request via Curl or Wget](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22Kubernetes%20Direct%20API%20Request%20via%20Curl%20or%20Wget%22&type=code)
- [Kubernetes Privileged Pod Created](https://github.com/elastic/detection-rules/blob/main/rules/integrations/kubernetes/privilege_escalation_privileged_pod_created.toml)
- [Kubernetes Pod Created with a Sensitive hostPath Volume](https://github.com/elastic/detection-rules/blob/main/rules/integrations/kubernetes/privilege_escalation_pod_created_with_sensitive_hostpath_volume.toml)
- [AWS Discovery API Calls via CLI from a Single Resource](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22AWS%20Discovery%20API%20Calls%20via%20CLI%20from%20a%20Single%20Resource%22&type=code)
- [AWS STS GetCallerIdentity API Called for the First Time](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22AWS%20STS%20GetCallerIdentity%20API%20Called%20for%20the%20First%20Time%22&type=code)
- [AWS EC2 Role GetCallerIdentity from New Source AS Organization](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22AWS%20EC2%20Role%20GetCallerIdentity%20from%20New%20Source%20AS%20Organization%22&type=code)

## Elastic Defend Endpoint Protections

The relevant endpoint-side protection coverage includes:

- [Suspicious Web Server Child Process](https://github.com/search?q=repo%3Aelastic%2Fprotections-artifacts+%22Suspicious%20Web%20Server%20Child%20Process%22&type=code)
- [Payload Downloaded via Curl or Wget by Web Server](https://github.com/search?q=repo%3Aelastic%2Fprotections-artifacts+%22Payload%20Downloaded%20via%20Curl%20or%20Wget%20by%20Web%20Server%22&type=code)
- [Payload Execution by Web Server](https://github.com/search?q=repo%3Aelastic%2Fprotections-artifacts+%22Payload%20Execution%20by%20Web%20Server%22&type=code)
- [Payload Execution by Node.js Web Server](https://github.com/search?q=repo%3Aelastic%2Fprotections-artifacts+%22Payload%20Execution%20by%20Node.js%20Web%20Server%22&type=code)
- [Decoded Payload Piped to Interpreter](https://github.com/elastic/protections-artifacts/blob/main/behavior/rules/linux/defense_evasion_decoded_payload_piped_to_interpreter.toml)
- [Suspicious Python Encoded Payload Execution](https://github.com/elastic/protections-artifacts/blob/main/behavior/rules/linux/execution_suspicious_python_encoded_payload_execution.toml)
- [DNS Request by Recently Created Executable](https://github.com/search?q=repo%3Aelastic%2Fprotections-artifacts+%22DNS%20Request%20by%20Recently%20Created%20Executable%22&type=code)
- [Environment Variable Secret Collection](https://github.com/search?q=repo%3Aelastic%2Fprotections-artifacts+%22Environment%20Variable%20Secret%20Collection%22&type=code)
- [Multi-Value Secret Searching via Grep](https://github.com/search?q=repo%3Aelastic%2Fprotections-artifacts+%22Multi-Value%20Secret%20Searching%20via%20Grep%22&type=code)
- [Cloud Credential Files Accessed by Process in Suspicious Directory](https://github.com/search?q=repo%3Aelastic%2Fprotections-artifacts+%22Cloud%20Credential%20Files%20Accessed%20by%20Process%20in%20Suspicious%20Directory%22&type=code)
- [Persistence via GenAI Tool](https://github.com/search?q=repo%3Aelastic%2Fprotections-artifacts+%22Persistence%20via%20GenAI%20Tool%22&type=code)
- [Suspicious Binary Execution via Path Alias](https://github.com/search?q=repo%3Aelastic%2Fprotections-artifacts+%22Suspicious%20Binary%20Execution%20via%20Path%20Alias%22&type=code)

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
