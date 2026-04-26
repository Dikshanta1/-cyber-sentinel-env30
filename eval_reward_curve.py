import time
import os
from dataclasses import dataclass
from typing import List, Tuple, Union, Optional

import requests


@dataclass
class EvalConfig:
    url: str = "https://Dikz-1-cyber-sentinel-env30.hf.space/step"
    reset_url: str = "https://Dikz-1-cyber-sentinel-env30.hf.space/reset"
    connect_timeout_s: float = 5.0
    read_timeout_s: float = 12.0
    retries: int = 2
    backoff_s: float = 0.5
    sleep_between_calls_s: float = 0.15
    max_total_runtime_s: float = 90.0


def parse_reward_field(reward_field: Union[float, int, dict, None]) -> float:
    if isinstance(reward_field, (int, float)):
        return float(reward_field)
    if isinstance(reward_field, dict):
        if "score" in reward_field:
            return float(reward_field["score"])
    return 0.01


def post_step(session: requests.Session, cfg: EvalConfig, command: str) -> Tuple[float, dict]:
    payload = {"command": command}
    for attempt in range(cfg.retries):
        try:
            r = session.post(
                cfg.url,
                json=payload,
                timeout=(cfg.connect_timeout_s, cfg.read_timeout_s),
            )
            r.raise_for_status()
            data = r.json()
            reward = parse_reward_field(data.get("reward"))
            return reward, data
        except Exception as e:
            # keep training/eval fail-closed on transient network issues
            time.sleep(cfg.backoff_s * (2**attempt))
    return 0.01, {"error": "request_failed"}


def main() -> None:
    cfg = EvalConfig()
    s = requests.Session()
    # avoid proxy issues in some environments
    s.trust_env = False
    # Ensure matplotlib cache is writable when plotting.
    os.environ.setdefault("MPLCONFIGDIR", os.path.join(os.getcwd(), ".mplconfig"))

    # Always reset to start a fresh episode; the Space keeps env state between calls.
    try:
        r = s.post(cfg.reset_url, timeout=(cfg.connect_timeout_s, cfg.read_timeout_s))
        r.raise_for_status()
        print("Reset OK.", flush=True)
    except Exception as e:
        print("Reset failed (continuing anyway):", e, flush=True)

    # A small probe set: safe discovery + likely task-relevant actions.
    commands: List[str] = [
        "ls -la",
        "find soc -maxdepth 5 -type f -print || true",
        "cat soc/cases/INC-1042/message.eml || true",
        "cat soc/cases/INC-1042/dns.log || true",
        "printf %s '{\"incident_id\":\"INC-1042\",\"malicious_domain\":\"login-update.secure-mail.example\",\"block_ip\":\"203.0.113.77\",\"severity\":\"high\"}' > final_report.json",
    ]

    start = time.time()
    rewards: List[float] = []
    for i, cmd in enumerate(commands, 1):
        if (time.time() - start) > cfg.max_total_runtime_s:
            print("Stopping early: hit max_total_runtime_s", flush=True)
            break
        t0 = time.time()
        reward, data = post_step(s, cfg, cmd)
        dt = time.time() - t0
        info = data.get("info") if isinstance(data, dict) else None
        task = info.get("task") if isinstance(info, dict) else None
        done = data.get("done") if isinstance(data, dict) else None
        rewards.append(float(reward))
        print(
            f"[{i:02d}/{len(commands)}] reward={reward:.4f} task={task} done={done} t={dt:.2f}s cmd={cmd!r}",
            flush=True,
        )
        time.sleep(cfg.sleep_between_calls_s)
        if done:
            break

    try:
        import matplotlib.pyplot as plt

        plt.figure(figsize=(9, 3.8))
        plt.plot(list(range(1, len(rewards) + 1)), rewards, marker="o", linewidth=2)
        plt.ylim(0.0, 1.0)
        plt.title("Cyber-Sentinel SOC verifier: reward vs probe index")
        plt.xlabel("Probe index")
        plt.ylabel("Reward")
        plt.grid(True, alpha=0.3)
        plt.tight_layout()
        plt.savefig("verifier_probe_curve.png", dpi=200)
        print("Saved verifier_probe_curve.png")
    except Exception as e:
        print("Could not plot rewards (matplotlib missing?). Error:", e)

    if rewards:
        print("Summary:", {"min": min(rewards), "max": max(rewards), "mean": sum(rewards) / len(rewards)})
    else:
        print("Summary: no rewards collected (all requests failed?)")


if __name__ == "__main__":
    main()
