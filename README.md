# Passwordstore SSH IdentityAgent

‼️ This project was writen entirely by ChatGPT ‼️

That includes this README (except for this part), the entirety of `agent.py`, and the systemd files.

The purpose of this agent is to provide `ssh` with ssh keys from [passwordstore](https://www.passwordstore.org/) without having to place the keys on the cclient. 

I have been actively using this agent on my personal and work machines since it was created. I would like to add support for more key types eventually and move the key configuration to a yaml file, but I haven't had the urge to do so since it's working perfectly fine.

Below this line is the original README written by ChatGPT. I wrote the systemd section.

---

This script provides an implementation of a custom SSH agent that retrieves private keys and their corresponding passphrases from [pass](https://www.passwordstore.org/), the standard Unix password manager. The script supports Ed25519 keys, listens on a Unix domain socket, and uses the Paramiko library for SSH key handling.

## Dependencies

- Python 3.6 or higher
- [Paramiko](https://www.paramiko.org/) library
- Cryptography

To install, run:

```bash
pip install paramiko cryptogragphy
```

## Usage

1. Edit the `KEYS` list in the script to include your key details:

```python
KEYS = [
    {
        "type": "ed25519",
        "key_path": "your-key-path",
        "pass_key": "your-pass-key",
        "store_location": "/path/to/your/store"
    }
]
```

2. Replace `your-key-path`, `your-pass-key`, and `/path/to/your/store` with the appropriate values for your key.

3. Run the script with the desired socket path as the command line argument:

```bash
python custom_ssh_agent.py <socket_path>
```

​	Replace `<socket_path>` with the desired path for the Unix domain socket.

4. Connect to the custom SSH agent using your SSH client by setting the `SSH_AUTH_SOCK` environment variable to the path of the Unix domain socket:

```bash
export SSH_AUTH_SOCK=<socket_path>
```

5. Your SSH client should now use the custom SSH agent for authentication.

## Example

Suppose you have an Ed25519 key with the following details:

- Key path in pass: `keys/ssh/id_ed25519`
- Passphrase path in pass: `keys/ssh/id_ed25519_passphrase`
- Password store location: `/home/user/.password-store`

Edit the `KEYS` list as follows:

```python
KEYS = [
    {
        "type": "ed25519",
        "key_path": "keys/ssh/id_ed25519",
        "pass_key": "keys/ssh/id_ed25519_passphrase",
        "store_location": "/home/user/.password-store"
    }
]
```

Run the script:

```bash
python custom_ssh_agent.py /tmp/custom_ssh_agent.sock
```

Set the `SSH_AUTH_SOCK` environment variable:

```bash
export SSH_AUTH_SOCK=/tmp/custom_ssh_agent.sock
```

Now, your SSH client will use the custom SSH agent for authentication.


## Make it automatic with systemd

```bash
# setup the virtualenv
mkdir -p ~/.ssh-pass-agent
cd ~/.ssh-pass-agent
python -m virtualenv .venv
source .venv/bin/activate
pip install paramiko cryptography
deactivate

# copy the agent to your local bin dir
cp agent.py ~/.ssh-pass-agent/agent.py

# IMPORANT !!
# make sure you modify the KEY variable in ~/.ssh-pass-agent/agent.py to 
# reflect your pass key information

# copy the files to systemd's config location
cp ./systemd/ssh-pass-agent.socket ~/.config/systemd/user/ 
cp ./systemd/ssh-pass-agent.service ~/.config/systemd/user/

# reload systemd daemon
systemctl --user daemon-reload

# start the socket and the service for good measure and enable them to start at boot
systemctl --user enable --now ssh-pass-agent.socket
systemctl --user enable --now ssh-pass-agent.service

# Tell SSH to use the socket
# (you might want to put this into your ~/.bashrc)
export SSH_AUTH_SOCK=/run/user/$(id -u)/ssh-pass-agent.sock
```

Now when you invoke `ssh <host>` the socket will be activated, the service will
be started and the only password prompt you should see is for the gpg
passphrase which unlocks the password store.
