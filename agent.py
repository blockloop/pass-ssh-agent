import os
import socket
import struct
import sys
from paramiko.message import Message
from paramiko.agent import Agent
from paramiko.ed25519key import Ed25519Key
from paramiko.ssh_exception import SSHException
import subprocess
import io

class CustomSSHAgent(Agent):
    AGENTC_REQUEST_IDENTITIES = bytes([11])
    AGENTC_SIGN_REQUEST = bytes([13])
    AGENT_IDENTITIES_ANSWER = bytes([12])
    AGENT_SIGN_RESPONSE = bytes([14])

    def __init__(self, keys):
        self.keys = []
        for key in keys:
            try:
                if key["type"].lower() == "ed25519":
                    passphrase = self.get_passphrase(key["pass_key"], key["store_location"])
                    private_key_str = self.get_private_key(key["key_path"])
                    private_key_file = io.StringIO(private_key_str)
                    self.keys.append(Ed25519Key.from_private_key(private_key_file, password=passphrase))
            except SSHException as e:
                print(f"Error loading key from {key['key_path']}: {e}")

    def get_passphrase(self, pass_key, store_location):
        env = os.environ.copy()
        env['PASSWORD_STORE_DIR'] = store_location

        result = subprocess.run(['pass', pass_key], capture_output=True, text=True, env=env)
        if result.returncode != 0:
            print(f"Error retrieving passphrase for key {pass_key}: {result.stderr}")
            return None
        return result.stdout.strip()

    def get_private_key(self, key_path):
        result = subprocess.run(['pass', key_path], capture_output=True, text=True)
        if result.returncode != 0:
            print(f"Error retrieving private key for key_path {key_path}: {result.stderr}")
            return None
        return result.stdout.strip()

    def handle_message(self, msg):
        m = Message(msg)
        cmd = m.get_byte()

        if cmd == CustomSSHAgent.AGENTC_REQUEST_IDENTITIES:
            resp = Message()
            resp.add_byte(CustomSSHAgent.AGENT_IDENTITIES_ANSWER)
            resp.add_int(len(self.keys))
            for key in self.keys:
                resp.add_string(key.asbytes())
                resp.add_string(f"{key.get_name()} key loaded from {key}")
            return resp.asbytes()

        if cmd == CustomSSHAgent.AGENTC_SIGN_REQUEST:
            key_blob = m.get_string()
            data = m.get_string()
            flags = m.get_int()

            resp = Message()
            resp.add_byte(CustomSSHAgent.AGENT_SIGN_RESPONSE)
            for key in self.keys:
                if key_blob == key.asbytes():
                    sig = key.sign_ssh_data(data)
                    resp.add_string(sig)
                    return resp.asbytes()

        failure_response = Message()
        failure_response.add_byte(bytes([255]))  # Custom failure code, converted to bytes
        return failure_response.asbytes()

def handle_client(agent, conn, addr):
    try:
        while True:
            msg = conn.recv(4)
            if len(msg) == 0:
                break
            msg_len = struct.unpack(">I", msg)[0]
            msg = conn.recv(msg_len)
            response = agent.handle_message(msg)
            conn.send(struct.pack(">I", len(response)) + response)
    finally:
        conn.close()


KEYS = [
    {
        "type": "ed25519",
        "key_path": "your-key-path",
        "pass_key": "your-pass-key",
        "store_location": "/path/to/your/store"
    }
]

if __name__ == "__main__":
    agent = CustomSSHAgent(KEYS)

    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <socket_path>")
        sys.exit(1)

    socket_path = sys.argv[1]

    if os.path.exists(socket_path):
        os.unlink(socket_path)

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(socket_path)
    os.chmod(socket_path, 0o600)

    try:
        sock.listen(1)

        while True:
            conn, addr = sock.accept()
            handle_client(agent, conn, addr)
    finally:
        sock.close()
        os.unlink(socket_path)
