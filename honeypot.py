import socket
import threading
import paramiko
import logging
from session_handler import HoneypotSession
from logger import HoneypotLogger

HOST_KEY = paramiko.RSAKey.generate(2048)

logging.getLogger("paramiko").setLevel(logging.WARNING)


class HoneypotSSHServer(paramiko.ServerInterface):

   def __init__(self, client_ip, honeypot_logger):
        self.client_ip = client_ip
        self.logger = honeypot_logger
        self.username = None
        self.password = None

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        self.username = username
        self.password = password
        self.logger.log_login_attempt(self.client_ip, username, password)
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_shell_request(self, channel):
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def get_allowed_auths(self, username):
        return "password"


def handle_client(client_socket, client_address, honeypot_logger):
    client_ip = client_address[0]
    print(f"[+] New connection from {client_ip}")
    honeypot_logger.log_event(client_ip, "CONNECTION", "New connection established")

    transport = None
    try:
        transport = paramiko.Transport(client_socket)
        transport.add_server_key(HOST_KEY)
        transport.local_version = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0."  

        server = HoneypotSSHServer(client_ip, honeypot_logger)
        transport.start_server(server=server)

        channel = transport.accept(30)
        if channel is None:
            print(f"[-] No channel opened by {client_ip}")
            return

        session = HoneypotSession(channel, client_ip, honeypot_logger)
        session.start()

    except Exception as e:
        honeypot_logger.log_event(client_ip, "ERROR", str(e))
    finally:
        if transport:
            transport.close()
        client_socket.close()
        print(f"[-] Connection from {client_ip} closed")


def start_server(host="0.0.0.0", port=2222):
    honeypot_logger = HoneypotLogger()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(5)

    print("=" * 55)
    print("    CHAMELEON HONEYPOT - AI-Powered SSH Decoy")
    print("=" * 55)
    print(f"   Listening on {host}:{port}")
    print(f"   Logs → history.log")
    print(f"   Press Ctrl+C to stop")
    print("=" * 55)

    try:
        while True:
            client_socket, client_address = server_socket.accept()
            thread = threading.Thread(
                target=handle_client,
                args=(client_socket, client_address, honeypot_logger),
                daemon=True
            )
            thread.start()
    except KeyboardInterrupt:
        print("\n[!] Honeypot stopped.")
    finally:
        server_socket.close()


if __name__ == "__main__":
    start_server()
