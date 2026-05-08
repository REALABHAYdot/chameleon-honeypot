"""
Session Handler - Manages each attacker's interactive shell session.
Reads keystrokes, sends commands to the AI, and streams responses back.
"""

import time
from llm_handler import LLMHandler


class HoneypotSession:
    """
    Represents one attacker's active session.
    Maintains command history so the AI stays context-aware.
    """

    def __init__(self, channel, client_ip, logger):
        self.channel = channel
        self.client_ip = client_ip
        self.logger = logger
        self.llm = LLMHandler()
        self.command_history = [] 
        self.current_dir = "/home/admin"
        self.username = "admin"
        self.hostname = "ubuntu-prod-01"

    def _send(self, text):
        """Safely send text back to the attacker."""
        try:
            self.channel.send(text)
        except Exception:
            pass

    def _prompt(self):
        """Return the fake shell prompt."""
        return f"\r\n{self.username}@{self.hostname}:{self.current_dir}$ "

    def _read_command(self):
        """
        Reads input character by character to support backspace, etc.
        Returns the full command string when Enter is pressed.
        """
        command = ""
        while True:
            try:
                char = self.channel.recv(1)
                if not char:
                    return None  

                if char in (b"\r", b"\n"):
                    self._send("\r\n")
                    return command.strip()

                if char in (b"\x7f", b"\x08"):
                    if command:
                        command = command[:-1]
                        self._send(b"\x08 \x08")  
                    continue

                if char == b"\x03":
                    self._send("^C")
                    return ""

                if char == b"\x04":
                    return "exit"

                decoded = char.decode("utf-8", errors="ignore")
                command += decoded
                self._send(char)

            except Exception:
                return None

    def _update_directory(self, command, response):
        """Track directory changes so the prompt stays realistic."""
        cmd = command.strip()
        if cmd.startswith("cd "):
            target = cmd[3:].strip()
            if target == "..":
                parts = self.current_dir.rsplit("/", 1)
                self.current_dir = parts[0] if parts[0] else "/"
            elif target == "~" or target == "":
                self.current_dir = f"/home/{self.username}"
            elif target.startswith("/"):
                self.current_dir = target
            else:
                self.current_dir = self.current_dir.rstrip("/") + "/" + target

    def start(self):
        """Main session loop."""
        motd = (
            "\r\nWelcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n"
            "\r\n"
            " * Documentation:  https://help.ubuntu.com\r\n"
            " * Management:     https://landscape.canonical.com\r\n"
            " * Support:        https://ubuntu.com/advantage\r\n"
            "\r\n"
            "  System information as of " + time.strftime("%a %b %d %H:%M:%S UTC %Y") + "\r\n"
            "\r\n"
            "  System load:  0.12              Users logged in:       1\r\n"
            "  Usage of /:   34.7% of 98.4GB   IPv4 address for eth0: 10.0.2.15\r\n"
            "  Memory usage: 23%               Swap usage:            0%\r\n"
            "  Processes:    142\r\n"
            "\r\n"
            "Last login: " + time.strftime("%a %b %d %H:%M:%S %Y") + " from 10.0.2.2\r\n"
        )
        self._send(motd)
        self._send(self._prompt())

        while True:
            command = self._read_command()

            if command is None:
                break

            if command == "":
                self._send(self._prompt())
                continue

            self.logger.log_command(self.client_ip, command)

            if command in ("exit", "logout", "quit"):
                self._send("logout\r\n")
                break

            response = self.llm.get_response(
                command=command,
                history=self.command_history,
                current_dir=self.current_dir,
                username=self.username,
                hostname=self.hostname,
            )

            response_display = response.replace("\n", "\r\n")
            self._send(response_display)

            self._update_directory(command, response)
            self.command_history.append((command, response))

            if len(self.command_history) > 10:
                self.command_history = self.command_history[-10:]

            self._send(self._prompt())

        self.channel.close()
        self.logger.log_event(self.client_ip, "DISCONNECT", "Session ended")
