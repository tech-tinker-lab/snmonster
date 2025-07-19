"""
SSH utility functions and classes.
"""
# Place SSH connection, shell, and related helpers here.

# Example placeholder
import paramiko
import threading

class SSHClientHelper:
    def __init__(self):
        self.client = None
        self.channel = None
        self._lock = threading.Lock()

    def connect(self, host, username, password, port=22, timeout=10):
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client.connect(host, port=port, username=username, password=password, timeout=timeout)
        self.channel = self.client.invoke_shell()
        self.channel.settimeout(0.0)  # Non-blocking

    def send(self, data):
        with self._lock:
            if self.channel:
                self.channel.send(data)

    def recv(self, bufsize=1024):
        with self._lock:
            if self.channel and self.channel.recv_ready():
                return self.channel.recv(bufsize)
        return b''

    def close(self):
        with self._lock:
            if self.channel:
                self.channel.close()
            if self.client:
                self.client.close()
