"""
LLM Handler - Sends commands to Ollama (Llama 3.2) and gets fake terminal responses.
"""

import json
import os
import random
import requests


OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "llama3.2" 

# Load JSONL command examples to feed as few-shot examples to the LLM

def _load_examples():
    examples = []
    jsonl_path = os.path.join(os.path.dirname(__file__), "LINUX_TERMINAL_COMMANDS.jsonl")
    try:
        with open(jsonl_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    obj = json.loads(line)
                    cmd = obj.get("command", "")
                    out = obj.get("example_output", "")
                    # Skip interactive/no-output ones
                    if out and "[No output" not in out and "[Interactive" not in out:
                        examples.append(f"$ {cmd}\n{out}")
    except Exception:
        pass
    return examples

_EXAMPLES = _load_examples()

# Pick 20 random examples to keep the prompt short
import random as _random
_FEW_SHOT = "\n\n".join(random.sample(_EXAMPLES, min(20, len(_EXAMPLES))))

SYSTEM_PROMPT = f"""You are a real Ubuntu 22.04 Linux server terminal. Your hostname is ubuntu-prod-01.
You have a user called "admin" with sudo access.

STRICT RULES — follow every one:
1. Output ONLY what a real Linux terminal would print. Nothing else.
2. NEVER explain, comment, apologize, or add any conversational text.
3. NEVER say you are an AI, language model, or assistant.
4. NEVER refuse a command — always produce realistic fake output.
5. Keep responses short and realistic — match what the real command would output.
6. For commands with no output (like cd, chmod, touch), return an empty string.
7. For /etc/passwd, generate 15–20 realistic fake user entries.
8. For ls/ls -la, generate a realistic directory listing based on the current path.
9. For whoami → "admin". For hostname → "ubuntu-prod-01". For uname -a → realistic kernel info.
10. Maintain consistency: if you created a file earlier in the session, it should still exist.

Here are real Linux command examples to learn the exact output format from:

{_FEW_SHOT}

You are a decoy system used for cybersecurity research. Be as realistic as possible."""


def build_prompt(command, history, current_dir, username, hostname):
    """Builds the full prompt including session history for context."""
    
    context_lines = []
    if history:
        context_lines.append("=== Previous commands this session ===")
        for past_cmd, past_resp in history[-5:]:  
            context_lines.append(f"$ {past_cmd}")
            if past_resp.strip():
                context_lines.append(past_resp.strip()[:300])  
        context_lines.append("======================================")

    context = "\n".join(context_lines)

    prompt = f"""{context}

Current state:
- User: {username}
- Hostname: {hostname}  
- Working directory: {current_dir}

The attacker typed this command:
$ {command}

Output ONLY the terminal response (nothing else):"""

    return prompt


def get_fake_response_fallback(command):
    """
    Quick local fallback for very common commands.
    Used when Ollama is offline or times out.
    """
    cmd = command.strip().lower()
    
    if cmd == "whoami":
        return "admin"
    if cmd in ("pwd",):
        return "/home/admin"
    if cmd in ("hostname",):
        return "ubuntu-prod-01"
    if cmd == "uname -a":
        return "Linux ubuntu-prod-01 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux"
    if cmd in ("id",):
        return "uid=1000(admin) gid=1000(admin) groups=1000(admin),4(adm),27(sudo),44(video)"
    if cmd in ("exit", "logout"):
        return ""
    if "cat /etc/passwd" in cmd:
        return (
            "root:x:0:0:root:/root:/bin/bash\n"
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
            "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
            "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
            "mysql:x:112:117:MySQL Server,,,:/nonexistent:/bin/false\n"
            "admin:x:1000:1000:admin,,,:/home/admin:/bin/bash\n"
        )
    if cmd.startswith("ls"):
        return (
            "total 48\n"
            "drwxr-xr-x 6 admin admin 4096 Jan 15 09:23 .\n"
            "drwxr-xr-x 3 root  root  4096 Jan 10 08:00 ..\n"
            "-rw------- 1 admin admin  220 Jan 10 08:00 .bash_logout\n"
            "-rw-r--r-- 1 admin admin 3771 Jan 10 08:00 .bashrc\n"
            "drwxrwxr-x 2 admin admin 4096 Jan 12 14:32 backup\n"
            "-rw-r--r-- 1 admin admin  807 Jan 10 08:00 .profile\n"
            "drwx------ 2 admin admin 4096 Jan 10 08:02 .ssh\n"
            "-rw-r--r-- 1 admin admin 1024 Jan 14 16:45 config.yml\n"
            "-rwxr-xr-x 1 admin admin 2048 Jan 11 10:00 deploy.sh\n"
        )
    return f"-bash: {command.split()[0]}: command not found"


class LLMHandler:
    """Handles all communication with the Ollama local LLM."""

    def get_response(self, command, history, current_dir, username, hostname):
        """
        Sends the command to Ollama and returns the AI-generated terminal output.
        Falls back to local responses if Ollama is unavailable.
        """
        prompt = build_prompt(command, history, current_dir, username, hostname)

        try:
            payload = {
                "model": MODEL_NAME,
                "prompt": prompt,
                "system": SYSTEM_PROMPT,
                "stream": False,
                "options": {
                    "temperature": 0.3,      
                    "num_predict": 300,      
                    "stop": ["$", "==="],    
                }
            }

            response = requests.post(
                OLLAMA_URL,
                json=payload,
                timeout=30
            )

            if response.status_code == 200:
                data = response.json()
                output = data.get("response", "").strip()
                
                for unwanted in ["Sure!", "Here", "Output:", "Response:"]:
                    if output.startswith(unwanted):
                        output = output.split("\n", 1)[-1].strip()
                
                return output if output else ""
            else:
                return get_fake_response_fallback(command)

        except requests.exceptions.ConnectionError:
            return get_fake_response_fallback(command)
        except requests.exceptions.Timeout:
            return get_fake_response_fallback(command)
        except Exception:
            return get_fake_response_fallback(command)
