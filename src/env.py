import os
import tempfile
import shutil
import subprocess
from typing import Tuple, Dict, Any

from .models import Action, Observation, Reward
from .tasks import get_task

class CyberEnvironment:
    def __init__(self, task_name: str = "phishing_triage"):
        self.jail_dir = None
        self.current_cwd = None
        self.step_count = 0
        self.max_steps = 30
        
        # Load the specific task logic
        self.task = get_task(task_name)
        self.output_history = []
        self.evidence = set()

    def reset(self) -> Observation:
        """Creates a fresh sandbox and sets up the specific task files."""
        if self.jail_dir and os.path.exists(self.jail_dir):
            shutil.rmtree(self.jail_dir)

        self.jail_dir = tempfile.mkdtemp(prefix="cyber_jail_")
        self.current_cwd = self.jail_dir
        self.step_count = 0
        self.output_history = []
        self.evidence = set()

        # Run the specific task's setup logic
        self.task.setup(self.jail_dir)

        initial_msg = (
            f"System initialized. Task: {self.task.name} ({self.task.difficulty}).\n"
            f"Objective: {self.task.objective}\n"
            "Use bash commands to inspect the sandbox. When ready, write a JSON object to "
            "final_report.json in the current directory."
        )
        self.output_history.append(initial_msg)
        
        return Observation(output=initial_msg, error=False)

    def step(self, action: Action) -> Tuple[Observation, Reward, bool, Dict[str, Any]]:
        """Executes the action and runs the grader."""
        self.step_count += 1
        command = action.command
        self.output_history.append(f"> {command}")
        
        # 1. Handle "cd" manually
        if command.strip().startswith("cd "):
            target_dir = command.strip()[3:].strip()
            
            # Handle relative paths
            if target_dir.startswith("/"):
                # Absolute path - map it to jail_dir root
                new_path = os.path.abspath(os.path.join(self.jail_dir, target_dir.lstrip("/")))
            else:
                # Relative path
                new_path = os.path.abspath(os.path.join(self.current_cwd, target_dir))

            # Ensure we stay within the jail
            normalized_new_path = os.path.normpath(new_path)
            normalized_jail = os.path.normpath(self.jail_dir)
            
            if not normalized_new_path.startswith(normalized_jail):
                obs = Observation(output="Permission denied. Cannot escape jail.", error=True)
            elif os.path.isdir(new_path):
                self.current_cwd = new_path
                obs = Observation(output=f"Changed directory. Current: {self._get_virtual_path()}", error=False)
            else:
                obs = Observation(output=f"cd: {target_dir}: No such file or directory", error=True)
        
        # 2. Execute other bash commands
        else:
            try:
                blocked = self._blocked_command(command)
                if blocked:
                    obs = Observation(output=blocked, error=True)
                    self.output_history.append(obs.output)
                    current_score = self.task.grade(self.output_history, self.jail_dir, self.evidence)
                    reward = Reward(score=current_score)
                    done = self.step_count >= self.max_steps or current_score >= 1.0
                    return obs, reward, done, {"step_count": self.step_count, "task": self.task.name}

                result = subprocess.run(
                    command,
                    shell=True,
                    cwd=self.current_cwd,
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                output_text = result.stdout if result.stdout else result.stderr
                is_error = result.returncode != 0
                
                if not output_text.strip():
                    output_text = "[Command executed with no output]"
                    
                obs = Observation(output=output_text.strip(), error=is_error)
                self.evidence.update(self.task.evidence_from_step(command, obs.output, obs.error))
            except subprocess.TimeoutExpired:
                obs = Observation(output="Error: Command timed out.", error=True)
            except Exception as e:
                obs = Observation(output=f"System error: {str(e)}", error=True)

        self.output_history.append(obs.output)

        # 3. Calculate Reward using the Task's Grader
        current_score = self.task.grade(self.output_history, self.jail_dir, self.evidence)
        reward = Reward(score=current_score)

        # 4. Check termination conditions (Done if max steps reached OR if they won)
        done = self.step_count >= self.max_steps or current_score >= 1.0
        
        return obs, reward, done, {"step_count": self.step_count, "task": self.task.name}

    def state(self) -> Dict[str, Any]:
        return {
            "virtual_cwd": self._get_virtual_path(),
            "step_count": self.step_count,
            "max_steps": self.max_steps,
            "task_name": self.task.name,
            "evidence": sorted(self.evidence),
        }

    def _get_virtual_path(self) -> str:
        if self.current_cwd == self.jail_dir:
            return "/"
        return self.current_cwd.replace(self.jail_dir, "")

    def _blocked_command(self, command: str) -> str | None:
        """Lightweight guardrails for a local demo sandbox, not a replacement for containers."""
        lowered = command.lower()
        blocked_tokens = [
            " rm ",
            "rm -",
            "curl ",
            "wget ",
            "nc ",
            "netcat ",
            "ssh ",
            "scp ",
            "sudo ",
            "/users/",
            "/etc/",
            "/private/",
        ]
        padded = f" {lowered} "
        if any(token in padded for token in blocked_tokens):
            return "Blocked by sandbox policy: command is outside the allowed incident-response workflow."
        return None

# --- QUICK TEST BLOCK ---
if __name__ == "__main__":
    env = CyberEnvironment(task_name="phishing_triage")
    env.reset()
    
    print("Action: find soc -type f -maxdepth 4 -print")
    obs, rew, done, info = env.step(Action(command="find soc -type f -maxdepth 4 -print"))
    
    print("Action: cat soc/cases/INC-1042/dns.log")
    obs, rew, done, info = env.step(Action(command="cat soc/cases/INC-1042/dns.log"))

    report = (
        "'{\"incident_id\":\"INC-1042\",\"malicious_domain\":\"login-update.secure-mail.example\","
        "\"block_ip\":\"203.0.113.77\",\"severity\":\"high\"}'"
    )
    obs, rew, done, info = env.step(Action(command=f"printf %s {report} > final_report.json"))
    
    print(f"\nFinal Output: {obs.output}")
    print(f"Final Score: {rew.score} (Should be 1.0)")
    print(f"Is Done: {done} (Should be True)")
