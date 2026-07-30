# Hugging Face Agent Intrusion Replay for Elastic

A safe, synthetic replay of the public Hugging Face agent intrusion using Elastic Security detections.

This repository contains:

- A portable Python runner in `scripts/run_hf_emulation.py`
- Synthetic telemetry shaped around the public Hugging Face incident
- Reliable generated SIEM rules that always produce alerts and a coherent narrative (the default detection path)
- **OOTB prebuilt-rule targeting** — synthetic telemetry written to the real Elastic integration data streams so a curated set of genuine Elastic prebuilt SIEM rules *actually fire* (not just get enabled)
- Best-effort matching and mapping against out-of-box Elastic Security / Elastic Defend coverage

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

The runner writes ECS-aligned synthetic documents to dedicated data streams for the custom-rule narrative:

```text
logs-frontier_lab_agent_emulation.endpoint-default
logs-frontier_lab_agent_emulation.kubernetes-default
logs-frontier_lab_agent_emulation.cloud-default
logs-frontier_lab_agent_emulation.github-default
logs-frontier_lab_agent_emulation.app-default
```

It also writes a smaller, precisely-shaped set of documents to the **real Elastic integration data streams** so genuine prebuilt rules fire (see [Targeted OOTB Prebuilt Rules](#targeted-ootb-prebuilt-rules)):

```text
logs-kubernetes.audit_logs-default
logs-endpoint.events.process-default
logs-aws.cloudtrail-default
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

## Detection Paths

The runner uses three complementary detection paths:

- **Guaranteed custom rules (default).** The runner creates a small set of temporary generated SIEM rules that match this run's synthetic telemetry directly (on `labels.run_id` + `labels.attack_phase`). These reliably fire, so a normal run **always** ends with alerts and enough signal for a coherent Attack Discovery narrative.
- **Targeted OOTB prebuilt rules (default).** The runner also emits a small set of precisely-shaped documents into the **real Elastic integration data streams** (`logs-kubernetes.audit_logs`, `logs-endpoint.events.process`, `logs-aws.cloudtrail`) that satisfy the *actual queries* of a curated set of genuine Elastic prebuilt rules. It then enables those rules and triggers manual runs, so real OOTB rules **actually fire** on the synthetic data. Doc generation is keyed to the rules actually installed at runtime, and each firing is confirmed by polling `.alerts-security.alerts-default`. See [Targeted OOTB Prebuilt Rules](#targeted-ootb-prebuilt-rules).
- **Best-effort OOTB intent overlay.** Separately, the runner matches required coverage *intents* against whatever prebuilt/Defend content is installed (by name / tag / MITRE technique) and can enable + run those too. This is a looser mapping and firing is not guaranteed.

Why not rely on OOTB alone? OOTB rules key off specific index patterns and `event.*` / `process.*` / `kubernetes.audit.*` / `aws.cloudtrail.*` fields. The targeted path handles this for a curated set; the custom path guarantees a narrative regardless of what content is installed.

To run OOTB-only (skip the guaranteed custom rules; the targeted OOTB path still fires real prebuilt alerts):

```sh
python3 scripts/run_hf_emulation.py --ootb-only     # alias: --no-custom-rules
```

To disable the targeted OOTB path (custom rules only):

```sh
python3 scripts/run_hf_emulation.py --no-target-ootb-rules
```

The runner never silently ends at 0 alerts: the custom path (unless `--ootb-only`) and the targeted OOTB path (unless `--no-target-ootb-rules`) both produce alerts on their own.

## Targeted OOTB Prebuilt Rules

This is the path that makes **real Elastic prebuilt rules actually fire**. For a curated set of installed prebuilt rules, the runner emits synthetic documents shaped to satisfy each rule's *exact query*, writes them to the **real integration data stream** the rule searches, then enables the rules and triggers manual runs. Every firing is confirmed by polling `.alerts-security.alerts-default` and reported per rule (fired / not fired, with a reason).

Doc generation is **keyed to the rules actually installed at runtime** (stable `rule_id` → synthetic-telemetry emitter). If a targeted rule is not installed, it is skipped gracefully. A single document can trip several rules (for example one privileged pod creation with a `hostPath` volume and `hostPID`/`hostNetwork`/`hostIPC` trips every pod-security rule), so the runner de-duplicates shared emitters.

The curated target set — all 25 verified firing live against the Elastic 9.x prebuilt package:

| Rule | `rule_id` | Type | Phase |
| --- | --- | --- | --- |
| Suspicious Child Execution via Web Server | `f16fca20-4d6c-43f9-aec1-20b6de3b0aeb` | eql | dataset_worker_foothold |
| Suspicious Command Execution via Web Server | `6148b9f5-5b12-4704-9ef7-f4b4c5dd9bb5` | eql | dataset_worker_foothold |
| Base64 Decoded Payload Piped to Interpreter | `5bdad1d5-5001-4a13-ae99-fa8619500f1a` | eql (sequence) | encoded_c2 |
| Kubernetes and Cloud Credential Path Access via Process Arguments | `5f0fff18-f340-444b-9a98-c49ade766ff4` | query | linux_recon_secrets |
| Kubernetes Service Account Token Created via TokenRequest API | `4df91789-7859-4bc4-9c5a-6b56bfa81a8b` | query | k8s_token_rbac |
| Kubernetes Secret get or list with Suspicious User Agent | `a4c8e901-2b7f-4d6e-9a3c-8e1f0d5b6c2a` | query | k8s_token_rbac |
| Kubernetes Secret get or list from Node or Pod Service Account | `f8a31c62-0d4e-4b9a-b7e1-6c2a9d4e8f10` | query | k8s_token_rbac |
| Kubernetes Secrets List Across Cluster or Sensitive Namespaces | `7e3f9a2b-1c4d-5e6f-8a0b-9c8d7e6f5a4b` | query | k8s_token_rbac |
| Kubernetes Privileged Pod Created | `c7908cac-337a-4f38-b50d-5eeb78bdb531` | query | k8s_privileged_hostpath |
| Kubernetes Pod Created with a Sensitive hostPath Volume | `2abda169-416b-4bb3-9a6b-f8d239fd78ba` | query | k8s_privileged_hostpath |
| Kubernetes Pod Created With HostPID | `df7fda76-c92b-4943-bc68-04460a5ea5ba` | query | k8s_privileged_hostpath |
| Kubernetes Pod Created With HostNetwork | `12cbf709-69e8-4055-94f9-24314385c27e` | query | k8s_privileged_hostpath |
| Kubernetes Pod Created With HostIPC | `764c8437-a581-4537-8060-1fdb0e92c92d` | query | k8s_privileged_hostpath |
| AWS AssumeRoleWithWebIdentity from Kubernetes SA and External ASN | `ae32268b-bfd0-4c35-b002-13461b5830ca` | query | cloud_iam_enumeration |
| Curl SOCKS Proxy Activity from Unusual Parent | `734239fe-eda8-48c0-bca8-9e3dafd81a88` | eql | mesh_vpn_pivot |
| Potential Linux Tunneling and/or Port Forwarding via Command Line | `8c8df61f-ed2a-4832-87b8-ee30812606e0` | eql | mesh_vpn_pivot |
| Curl or Wget Spawned via Node.js | `d9af2479-ad13-4471-a312-f586517f1243` | eql | dataset_worker_foothold |
| GenAI CLI Started with Unsafe Permission Bypass | `c1326e45-6d3c-4a2d-9882-606a0c310299` | eql | dataset_worker_foothold |
| Kubernetes Direct API Request via Curl or Wget | `b53f1d73-150d-484d-8f02-222abeb5d5fa` | eql | k8s_recon_discovery |
| Kubernetes Denied Service Account Request via Unusual User Agent | `63c056a0-339a-11ed-a261-0242ac120002` | new_terms | k8s_recon_discovery |
| Kubernetes Suspicious Self-Subject Review via Unusual User Agent | `12a2f15d-597e-4334-88ff-38a02cb1330b` | new_terms | k8s_recon_discovery |
| Kubernetes Multi-Resource Discovery | `c2a91e88-4f4b-4e1d-9c7b-8fde112a9403` | esql | k8s_recon_discovery |
| AWS STS GetCallerIdentity API Called for the First Time | `30fbf4db-c502-4e68-a239-2e99af0f70da` | new_terms | cloud_iam_enumeration |
| AWS EC2 Role GetCallerIdentity from New Source AS Organization | `b2f8c4e1-6a73-4f1e-9c2d-8e5b0a1d3f7c` | new_terms | cloud_iam_enumeration |
| AWS Discovery API Calls via CLI from a Single Resource | `74f45152-9aee-11ef-b0a5-f661ea17fbcd` | esql | cloud_iam_enumeration |

Integration data streams and the key ECS/integration fields each group satisfies:

- `logs-endpoint.events.process-default` — `host.os.type:linux`, `event.category:process`, `event.type:start`, `event.action:exec`, plus `process.name` / `process.args` / `process.command_line` / `process.parent.name` / `process.parent.command_line` / `process.entity_id` / `process.parent.entity_id` / `host.id`. Examples: a web-server (`python … app.py`) spawning `curl`; a shell run as `bash -c id`; a `python -c … base64.b64decode(…)` decode piped to a shell (ordered sequence within `maxspan`); `cat /var/run/secrets/kubernetes.io/serviceaccount/token`; a Node.js server (`node … agent-server.js`) spawning `curl http…`; a GenAI CLI launched with `claude --dangerously-skip-permissions`; `curl … https://10.96.0.1/api/v1/namespaces/*/secrets`; `curl --socks5-hostname 127.0.0.1:1055 …`; `ssh -N -L 127.0.0.1:1055:10.99.4.12:443 …`.
- `logs-kubernetes.audit_logs-default` — `data_stream.dataset:kubernetes.audit_logs`, `kubernetes.audit.verb`, `kubernetes.audit.objectRef.resource` / `.subresource`, `kubernetes.audit.annotations.authorization_k8s_io/decision` (`allow` for most rules, `forbid` for the denied-request rule), `kubernetes.audit.requestObject.spec.*` (privileged / hostPath / hostPID / hostNetwork / hostIPC), `user.name` (a `system:serviceaccount:*` identity), `event.action`, `source.ip`, and `user_agent.original` — which is also the `new_terms` field for the denied-request and self-subject-review rules (seeded with a per-run-unique value), and `get`/`list` across several distinct resources in one minute drives the ES|QL Multi-Resource Discovery rule.
- `logs-aws.cloudtrail-default` — `data_stream.dataset:aws.cloudtrail`, `event.provider:sts.amazonaws.com`, `event.outcome:success`, `user.name`, `source.as.organization.name` (a non-Amazon ASN). Beyond `AssumeRoleWithWebIdentity`, the emitters also cover `GetCallerIdentity` for the `new_terms` first-seen-`aws.cloudtrail.user_identity.arn` rule and the AssumedRole-from-new-source-AS-org rule (`user.id` like `*:i-*`), plus a burst of distinct `aws-cli` `Describe`/`Get`/`List` calls (with `user_agent.name:aws-cli` and `aws.cloudtrail.user_identity.access_key_id`) for the ES|QL discovery rule. A single console-origin primer doc maps `aws.cloudtrail.session_credential_from_console` so that ES|QL query compiles even without the AWS integration index template.

Flags:

```sh
--target-ootb-rules        # on by default: emit OOTB-satisfying telemetry and enable+run the targets
--no-target-ootb-rules     # disable this path (custom rules only)
--ootb-target-run-lookback-minutes N   # manual-run window for the targets (default 20)
--ootb-target-alert-timeout N          # seconds to wait for the targets to fire (default 180)
```

All identifiers remain synthetic/safe: reserved/RFC5737 IPs, `.invalid` domains, fake ARNs/tokens, and a synthetic container image name deliberately outside every rule's allow-list. No exploit payloads are emitted; no real pods, cloud calls, or API requests are made.

The targeted set now includes `new_terms` and `esql` rules where they can be satisfied deterministically with synthetic docs (per-run-unique `new_terms` values; multi-event volume/time-window seeding for `esql`). Rules that remain **reference coverage** (installed, incident-relevant, but not fired by this kit) are those that need data this kit does not synthesize on this stack: the GenAI file/network/DNS rules (they require `logs-endpoint.events.file*` / `logs-endpoint.events.network*` or Windows/macOS host telemetry), the `esql` *Elastic Defend Alert from GenAI Utility or Descendant* (needs real Elastic Defend `logs-endpoint.alerts-*` with `process.Ext.ancestry`), and the `esql` *LLM-Based Attack Chain Triage by Host* (needs a configured LLM inference connector). `machine_learning`, `threshold`, `threat_match`, and `data_view`-only rule types are still out of scope for synthetic firing.

## OOTB Coverage Matching

Instead of relying on brittle exact rule names, the runner enumerates **all** installed Detection Engine rules and matches required coverage *intents* against what is actually installed, using, in order:

1. Exact display name
2. Normalized name (casefold, collapse whitespace, strip punctuation)
3. A small alias map for known naming differences
4. Tag / MITRE technique discovery (for example `Data Source: Kubernetes`, `Data Source: AWS`, plus technique IDs) as a fallback to find equivalent installed rules

Each required intent is mapped to an attack phase and carries candidate names, aliases, data-source tags, and technique IDs. GenAI/LLM and Elastic Defend items (for example *Elastic Defend Alert from GenAI Utility or Descendant*) are marked as non-installable content: they are endpoint/GenAI features rather than installable SIEM Detection Engine rules, so "not found" for those is expected rather than a coverage failure.

The coverage report shows matched intents (with the actual installed rule name + id and how it matched), unmatched installable intents, and expected-absent non-installable items. To also print the closest installed rule names for every intent (useful for debugging naming drift):

```sh
python3 scripts/run_hf_emulation.py --debug-rule-matches --check-ootb-rules
```

Install or update Elastic prebuilt SIEM rules before matching:

```sh
--install-prebuilt-rules
```

Enable matched-but-disabled OOTB rules (interactively, or non-interactively with the flag):

```sh
--enable-ootb-rules
```

Manually schedule matched + enabled OOTB rules after telemetry is written (best-effort overlay; per-rule failures are tolerated and the run continues):

```sh
--run-ootb-rules
```

Kibana / Elasticsearch endpoints used:

- `GET /api/detection_engine/rules/_find` — enumerate installed rules (paginated, `per_page` up to 100)
- `POST /api/detection_engine/rules/_bulk_action` — `enable` matched+disabled rules, and `run` them
- `POST /internal/alerting/rule/{id}/_run_soon` — per-rule fallback for manual runs
- `PUT /api/detection_engine/rules/prepackaged` (fallback `POST /api/detection_engine/prebuilt_rules/installation/_perform`) — install prebuilt rules

Use `--skip-ootb-rule-check` to skip the matching step entirely. Elastic Defend endpoint protections are documented below for context, but they are not matched or enabled by this script because they are not SIEM Detection Engine rules.

## Elastic Security / SIEM Rules

Every rule below is installed in the target stack. The kit **actively fires** the rules in the
first group by writing precisely-shaped ECS telemetry to the real integration data streams and
confirming each one produces alerts — 25 verified firing against the Elastic 9.x prebuilt package
(see [Targeted OOTB Prebuilt Rules](#targeted-ootb-prebuilt-rules)). The **reference coverage**
group is installed and relevant to this incident but is not triggered by synthetic ingestion on
this stack; each item notes why.

### Fired live by this kit (verified)

Worker and host execution (`logs-endpoint.events.process`):

- [Suspicious Child Execution via Web Server](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22Suspicious%20Child%20Execution%20via%20Web%20Server%22&type=code)
- [Suspicious Command Execution via Web Server](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22Suspicious%20Command%20Execution%20via%20Web%20Server%22&type=code)
- [Curl or Wget Spawned via Node.js](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22Curl%20or%20Wget%20Spawned%20via%20Node.js%22&type=code)
- [Base64 Decoded Payload Piped to Interpreter](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22Base64%20Decoded%20Payload%20Piped%20to%20Interpreter%22&type=code)
- [GenAI CLI Started with Unsafe Permission Bypass](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22GenAI%20CLI%20Started%20with%20Unsafe%20Permission%20Bypass%22&type=code)
- [Kubernetes and Cloud Credential Path Access via Process Arguments](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22Kubernetes%20and%20Cloud%20Credential%20Path%20Access%20via%20Process%20Arguments%22&type=code)
- [Curl SOCKS Proxy Activity from Unusual Parent](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22Curl%20SOCKS%20Proxy%20Activity%20from%20Unusual%20Parent%22&type=code)
- [Potential Linux Tunneling and/or Port Forwarding via Command Line](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22Potential%20Linux%20Tunneling%20and/or%20Port%20Forwarding%20via%20Command%20Line%22&type=code)

Kubernetes audit and API (`logs-kubernetes.audit_logs`, plus one endpoint-process rule):

- [Kubernetes Direct API Request via Curl or Wget](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22Kubernetes%20Direct%20API%20Request%20via%20Curl%20or%20Wget%22&type=code)
- [Kubernetes Service Account Token Created via TokenRequest API](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22Kubernetes%20Service%20Account%20Token%20Created%20via%20TokenRequest%20API%22&type=code)
- [Kubernetes Secret get or list with Suspicious User Agent](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22Kubernetes%20Secret%20get%20or%20list%20with%20Suspicious%20User%20Agent%22&type=code)
- [Kubernetes Secret get or list from Node or Pod Service Account](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22Kubernetes%20Secret%20get%20or%20list%20from%20Node%20or%20Pod%20Service%20Account%22&type=code)
- [Kubernetes Secrets List Across Cluster or Sensitive Namespaces](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22Kubernetes%20Secrets%20List%20Across%20Cluster%20or%20Sensitive%20Namespaces%22&type=code)
- [Kubernetes Privileged Pod Created](https://github.com/elastic/detection-rules/blob/main/rules/integrations/kubernetes/privilege_escalation_privileged_pod_created.toml)
- [Kubernetes Pod Created with a Sensitive hostPath Volume](https://github.com/elastic/detection-rules/blob/main/rules/integrations/kubernetes/privilege_escalation_pod_created_with_sensitive_hostpath_volume.toml)
- [Kubernetes Pod Created With HostPID](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22Kubernetes%20Pod%20Created%20With%20HostPID%22&type=code)
- [Kubernetes Pod Created With HostNetwork](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22Kubernetes%20Pod%20Created%20With%20HostNetwork%22&type=code)
- [Kubernetes Pod Created With HostIPC](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22Kubernetes%20Pod%20Created%20With%20HostIPC%22&type=code)
- [Kubernetes Denied Service Account Request via Unusual User Agent](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22Kubernetes%20Denied%20Service%20Account%20Request%20via%20Unusual%20User%20Agent%22&type=code)
- [Kubernetes Suspicious Self-Subject Review via Unusual User Agent](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22Kubernetes%20Suspicious%20Self-Subject%20Review%20via%20Unusual%20User%20Agent%22&type=code)
- [Kubernetes Multi-Resource Discovery](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22Kubernetes%20Multi-Resource%20Discovery%22&type=code)

Cloud / AWS identity (`logs-aws.cloudtrail`):

- [AWS AssumeRoleWithWebIdentity from Kubernetes SA and External ASN](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22AWS%20AssumeRoleWithWebIdentity%20from%20Kubernetes%20SA%20and%20External%20ASN%22&type=code)
- [AWS STS GetCallerIdentity API Called for the First Time](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22AWS%20STS%20GetCallerIdentity%20API%20Called%20for%20the%20First%20Time%22&type=code)
- [AWS EC2 Role GetCallerIdentity from New Source AS Organization](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22AWS%20EC2%20Role%20GetCallerIdentity%20from%20New%20Source%20AS%20Organization%22&type=code)
- [AWS Discovery API Calls via CLI from a Single Resource](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22AWS%20Discovery%20API%20Calls%20via%20CLI%20from%20a%20Single%20Resource%22&type=code)

### Reference coverage (not triggered by this kit)

Installed and incident-relevant, but not fired via synthetic ingestion on this stack. Left listed
and linked for context, with the reason each one is not exercised:

- [GenAI Process Accessing Sensitive Files](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22GenAI%20Process%20Accessing%20Sensitive%20Files%22&type=code) — eql over `logs-endpoint.events.file*`; the kit does not emit endpoint file events.
- [GenAI Process Connection to Unusual Domain](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22GenAI%20Process%20Connection%20to%20Unusual%20Domain%22&type=code) — new_terms over macOS `logs-endpoint.events.network*`.
- [GenAI Process Connection to Suspicious Top Level Domain](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22GenAI%20Process%20Connection%20to%20Suspicious%20Top%20Level%20Domain%22&type=code) — eql, Windows/macOS network only.
- [GenAI Process Performing Encoding/Chunking Prior to Network Activity](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22GenAI%20Process%20Performing%20Encoding%2FChunking%20Prior%20to%20Network%20Activity%22&type=code) — eql process→network sequence; needs endpoint network events.
- [Connection to Common Large Language Model Endpoints](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22Connection%20to%20Common%20Large%20Language%20Model%20Endpoints%22&type=code) — eql, Windows/macOS DNS only.
- [Unusual Process Modifying GenAI Configuration File](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22Unusual%20Process%20Modifying%20GenAI%20Configuration%20File%22&type=code) — new_terms over `logs-endpoint.events.file*`.
- [Elastic Defend Alert from GenAI Utility or Descendant](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22Elastic%20Defend%20Alert%20from%20GenAI%20Utility%20or%20Descendant%22&type=code) — esql over `logs-endpoint.alerts-*`; needs real Elastic Defend endpoint alerts and `process.Ext.ancestry`.
- [LLM-Based Attack Chain Triage by Host](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22LLM-Based%20Attack%20Chain%20Triage%20by%20Host%22&type=code) — esql with a `COMPLETION` step; needs a configured LLM inference connector.

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

## Generated Rules (Default Guaranteed Path)

The runner creates a small set of temporary generated SIEM rules that reliably match this run's synthetic telemetry. This is the default detection path and is what guarantees alerts and a narrative. No flag is needed to enable it; use `--ootb-only` (alias `--no-custom-rules`) to skip it.

Generated rules are disabled after the run by default. Use:

```sh
--keep-rules-enabled
```

to leave them enabled, or:

```sh
--delete-rules-after
```

to delete them after the run.

`--include-custom-rules` is still accepted for backward compatibility but is now a no-op, since custom rules run by default.

## Quick Start

Use environment variables for credentials:

```sh
export ELASTIC_USERNAME="elastic-user"
export ELASTIC_PASSWORD="elastic-password"
```

A plain run uses the guaranteed custom path (always produces alerts) **and** the targeted OOTB path (real prebuilt rules fire on synthetic telemetry), plus the best-effort intent overlay against whatever else is installed:

```sh
python3 scripts/run_hf_emulation.py \
  --es-url http://localhost:9200 \
  --kibana-url http://localhost:5601 \
  --space default
```

If the prebuilt rule package is not yet installed, add `--install-prebuilt-rules` so the targeted rules exist:

```sh
python3 scripts/run_hf_emulation.py \
  --es-url http://localhost:9200 \
  --kibana-url http://localhost:5601 \
  --space default \
  --install-prebuilt-rules
```

To also enable and manually run the looser intent-matched OOTB rules as an overlay:

```sh
python3 scripts/run_hf_emulation.py \
  --es-url http://localhost:9200 \
  --kibana-url http://localhost:5601 \
  --space default \
  --install-prebuilt-rules \
  --enable-ootb-rules \
  --run-ootb-rules
```

Check the OOTB SIEM rule status without ingesting any telemetry:

```sh
python3 scripts/run_hf_emulation.py \
  --es-url http://localhost:9200 \
  --kibana-url http://localhost:5601 \
  --space default \
  --check-ootb-rules
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

Delete the dedicated synthetic data streams when you no longer need source documents:

```http
DELETE _data_stream/logs-frontier_lab_agent_emulation.endpoint-default
DELETE _data_stream/logs-frontier_lab_agent_emulation.kubernetes-default
DELETE _data_stream/logs-frontier_lab_agent_emulation.cloud-default
DELETE _data_stream/logs-frontier_lab_agent_emulation.github-default
DELETE _data_stream/logs-frontier_lab_agent_emulation.app-default
```

The targeted OOTB path writes into the **shared** integration data streams (`logs-kubernetes.audit_logs-default`, `logs-endpoint.events.process-default`, `logs-aws.cloudtrail-default`), which may also hold real integration data. Do **not** delete those data streams. Instead, remove only the synthetic documents, which carry the `ootb-target-telemetry` tag and this run's `labels.run_id`:

```http
POST logs-kubernetes.audit_logs-default,logs-endpoint.events.process-default,logs-aws.cloudtrail-default/_delete_by_query
{
  "query": { "term": { "tags": "ootb-target-telemetry" } }
}
```

Generated rules run by default and are disabled after the run (unless `--ootb-only` was used). Use `--delete-rules-after` if you want them deleted automatically, or `--keep-rules-enabled` to leave them enabled.

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
