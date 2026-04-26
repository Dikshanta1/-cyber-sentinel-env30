# Cyber-Sentinel: Training LLM Agents for Real Security Operation Centre(SOC) Incident Response

Most security benchmarks ask a model to *talk* about cybersecurity. Cyber-Sentinel asks the model to actually do the work.

In a real SOC, an analyst rarely receives a clean question with a clean answer. They receive scattered evidence: a suspicious email, DNS logs, endpoint activity, identity events, proxy traffic, a policy document, and sometimes a SIEM database. The job is to inspect the environment, connect the evidence, avoid false positives, and produce a containment decision that another system or human can trust.

That is the gap Cyber-Sentinel targets.

Cyber-Sentinel is an OpenEnv-style reinforcement learning environment where an LLM acts inside a sandboxed terminal. The agent runs bash commands, reads realistic enterprise security artifacts, correlates evidence, and writes a machine-checkable `final_report.json`. The environment then scores the agent with objective verifier rewards.

## Theme Alignment

Cyber-Sentinel targets two OpenEnv Hackathon themes:

- **Theme #3.1: Professional Tasks**
- **Theme #2: Long-Horizon Planning & Instruction Following**

The professional-task angle is SOC incident response: a real operational workflow involving logs, policies, alerts, and containment actions.

The long-horizon angle is that the model cannot solve the task in one guess. It has to explore, read, reason, and only then submit the final report. This is exactly the kind of multi-step behavior that LLM agents need to improve for real workplace use.

## What The Environment Looks Like

Each episode creates a fresh sandbox containing incident-response artifacts. The agent can run terminal commands such as:

```bash
find soc -maxdepth 5 -type f -print
cat soc/cases/INC-1042/message.eml
cat enterprise/policy/network_access_v3.md
python3 -c "import sqlite3; ..."
```

When ready, the agent writes:

```text
final_report.json
```

That report is verified programmatically. There is no subjective judge deciding whether the answer “sounds right.”

## The Three Tasks

Cyber-Sentinel currently contains three SOC workflows.

### 1. Phishing Triage

The agent investigates a suspicious payroll email and DNS telemetry.

It must identify the incident, malicious domain, blocking IP, and severity:

```json
{
  "incident_id": "INC-1042",
  "malicious_domain": "login-update.secure-mail.example",
  "block_ip": "203.0.113.77",
  "severity": "high"
}
```

This task teaches evidence discovery and phishing indicator extraction.

### 2. Policy Drift

The agent reads a changed network-access policy and endpoint session events.

It must identify that a contractor violated the current policy and produce a quarantine decision:

```json
{
  "user": "owen.contractor",
  "country": "RU",
  "quarantine": true,
  "reason": "policy_drift_export"
}
```

This task tests policy understanding, not just log search.

### 3. Incident Containment

The agent correlates SIEM, identity, and proxy data to build a containment plan.

It must identify the compromised user, source IP, session action, and domain block:

```json
{
  "incident_id": "INC-773",
  "user": "anika",
  "source_ip": "10.9.8.17",
  "revoke_session": true,
  "block_domains": ["exfil-drop.secure-mail.example"]
}
```

This is the hardest task because the answer is distributed across multiple systems.

## Reward Design

Cyber-Sentinel uses verifier-based rewards, not subjective scoring.

The reward function gives partial credit for real progress:

- discovering the relevant artifacts
- reading the correct evidence files
- querying the SIEM database
- connecting the right user, IP, domain, policy, or incident ID
- writing a valid `final_report.json`
- matching the expected containment action

The final score reaches `1.0` only when the investigation and report are both correct.

We also added anti-reward-hacking checks. For example, the model cannot get discovery credit by simply printing the expected answer:

```bash
echo INC-1042 login-update.secure-mail.example 203.0.113.77
```

That stays near the minimum reward. Process credit is only awarded after successful reads of real artifacts or real SIEM queries. Report credit is unlocked only after the corresponding evidence has been confirmed.

The environment also blocks unsafe or irrelevant actions such as network calls, destructive filesystem commands, host filesystem access, and long-running commands.

## Verifier Sanity Check

The verifier sanity check shows that rewards increase as the agent performs the right investigation steps. Discovery gives partial reward, reading evidence gives more reward, and a correct `final_report.json` reaches full reward.

![Verifier sanity check](https://huggingface.co/spaces/Dikz-1/cyber-sentinel-env30/resolve/main/verifier_probe_curve.png)

## Training

We trained using **Hugging Face TRL GRPO** against the live Cyber-Sentinel verifier.

The training loop follows the OpenEnv/RLVR pattern:

```text
agent action -> environment step -> verifier reward -> GRPO update
```

We used a small SOC prompt curriculum across phishing triage, policy drift, and incident containment. The model starts from a general instruction-following base model and learns to produce more useful terminal actions for this specific environment.

We intentionally used direct GRPO instead of SFT because we did not have a large dataset of ideal command traces. The environment itself provides objective feedback. That makes Cyber-Sentinel a natural fit for reinforcement learning with verifiable rewards.

## Training Results

During GRPO training, the reward curve improved from the near-minimum baseline toward higher verified reward as the model learned to issue better SOC commands and produce more useful final reports.

![Training reward curve](https://huggingface.co/spaces/Dikz-1/cyber-sentinel-env30/resolve/main/reward_curve.png)

The loss curve shows that the HF TRL training loop ran end-to-end.

![Training loss curve](https://huggingface.co/spaces/Dikz-1/cyber-sentinel-env30/resolve/main/loss_curve.png)

The before/after distribution shifted after training, showing that the trained policy was more likely to receive meaningful verifier reward than the untrained baseline.

![Before vs after reward distribution](https://huggingface.co/spaces/Dikz-1/cyber-sentinel-env30/resolve/main/before_after_rewards.png)

The exact before/after arrays and means are included in `before_after_rewards.json` in the Space repo.

## Why This Matters In The Real World

Security teams already use LLMs for summarization, triage, and investigation support. But a useful SOC agent cannot just sound confident. It needs to act safely inside tools, inspect evidence, follow changing policies, and produce decisions that can be verified.

Cyber-Sentinel is a small but realistic step toward that.

It creates a controlled environment where models can learn operational security behavior:

- investigate before answering
- ground decisions in evidence
- handle partially observable workflows
- avoid shortcuts and hallucinated conclusions
- produce structured outputs that downstream systems can use

This matters because real incident response is high-pressure, noisy, and expensive. If we want LLM agents to assist analysts responsibly, we need training environments that reward correct process, not just fluent explanations.

## What We Built

Cyber-Sentinel includes:

- an OpenEnv-style `reset`, `step`, and `state` interface
- a FastAPI server deployable on Hugging Face Spaces
- a live browser demo UI
- three SOC incident-response tasks
- structured JSON report verification
- process-aware partial rewards
- anti-reward-hacking checks
- session isolation for concurrent evaluators
- a Colab training notebook using HF TRL GRPO
- reward, loss, and before/after plots

## Links

- **Live Space:** https://Dikz-1-cyber-sentinel-env30.hf.space
- **Training Colab:** https://colab.research.google.com/drive/1iKvGT5XZi39vkFE759-rB9heZ8x5Ot7T?usp=sharing
- **Space Files:** https://huggingface.co/spaces/Dikz-1/cyber-sentinel-env30/tree/main

## Closing

Cyber-Sentinel is not another toy grid-world. It is a compact professional workflow environment where the model must behave like a careful SOC analyst: inspect, correlate, decide, and prove its answer through a verifier.

The core idea is simple:

> If we want reliable security agents, we need to train them in environments where correctness is earned through evidence.

Cyber-Sentinel does exactly that.
