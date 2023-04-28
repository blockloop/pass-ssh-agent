from typing import List
from unittest.mock import MagicMock, patch

import pytest
from paramiko import Ed25519Key
from paramiko.message import Message

import agent


def create_mock_key() -> Ed25519Key:
    key = MagicMock(spec=Ed25519Key)
    key.asbytes.return_value = b"mock_key"
    key.get_name.return_value = "Ed25519"
    key.sign_ssh_data.return_value = b"mock_signature"
    return key


def test_handle_message_request_identities():
    mock_key = create_mock_key()
    keys: List[Ed25519Key] = [mock_key]

    request_identities_msg = Message()
    request_identities_msg.add_byte(agent.AGENTC_REQUEST_IDENTITIES)

    response = agent.handle_message(request_identities_msg.asbytes(), keys)
    response_msg = Message(response)

    assert response_msg.get_byte() == agent.AGENT_IDENTITIES_ANSWER
    assert response_msg.get_int() == 1
    assert response_msg.get_string() == mock_key.asbytes()


def test_handle_message_sign_request():
    mock_key = create_mock_key()
    keys: List[Ed25519Key] = [mock_key]

    sign_request_msg = Message()
    sign_request_msg.add_byte(agent.AGENTC_SIGN_REQUEST)
    sign_request_msg.add_string(mock_key.asbytes())
    sign_request_msg.add_string(b"some_data")
    sign_request_msg.add_int(0)

    response = agent.handle_message(sign_request_msg.asbytes(), keys)
    response_msg = Message(response)

    assert response_msg.get_byte() == agent.AGENT_SIGN_RESPONSE
    assert response_msg.get_string() == mock_key.sign_ssh_data.return_value


def test_handle_message_failure():
    mock_key = create_mock_key()
    keys: List[Ed25519Key] = [mock_key]

    invalid_msg = Message()
    invalid_msg.add_byte(bytes([0]))  # Invalid command

    response = agent.handle_message(invalid_msg.asbytes(), keys)
    response_msg = Message(response)

    assert response_msg.get_byte() == agent.SSH_AGENT_FAILURE


def create_mock_ssh_key(key_type: str) -> agent.SSHKey:
    key = MagicMock(spec=agent.SSHKey)
    key.type = key_type
    key.key_path = f"/path/to/{key_type}_key"
    key.pass_key = f"{key_type}_pass_key"
    key.store_location = "/path/to/pass/store"
    return key


@patch("agent.get_private_key")
@patch("agent.get_passphrase")
def test_load_keys_with_ed25519_key(mock_get_passphrase, mock_get_private_key):
    # Mock the `get_passphrase` and `get_private_key` functions
    # to return valid data
    mock_get_passphrase.return_value = "passphrase"
    mock_get_private_key.return_value = "private_key"

    # Create a mock SSHKey object
    mock_key = create_mock_ssh_key("ed25519")

    # Create the expected Ed25519Key object
    expected_key = MagicMock(spec=Ed25519Key)
    expected_key.asbytes.return_value = b"mock_key"

    # Patch the `Ed25519Key.from_private_key` function to return the expected key
    with patch("agent.Ed25519Key.from_private_key") as mock_from_private_key:
        mock_from_private_key.return_value = expected_key

        # Call the `load_keys` function
        keys = agent.load_keys([mock_key])

        # Assertions
        assert len(keys) == 1
        assert keys[0] == expected_key


@patch.dict("os.environ", {"PASSWORD_STORE_DIR": "/path/to/pass/store"})
def test_get_passphrase_with_valid_key():
    # Mock the `subprocess.run` function to return valid data
    with patch("subprocess.run") as mock_subprocess:
        mock_subprocess.return_value.returncode = 0
        mock_subprocess.return_value.stdout = "passphrase\n"

        # Call the `get_passphrase` function
        passphrase = agent.get_passphrase("pass_key", "/path/to/pass/store")

        # Assertions
        assert passphrase == "passphrase"


@patch.dict("os.environ", {"PASSWORD_STORE_DIR": "/path/to/pass/store"})
def test_get_passphrase_with_invalid_key():
    # Mock the `subprocess.run` function to return an error
    with patch("subprocess.run") as mock_subprocess:
        mock_subprocess.return_value.returncode = 1
        mock_subprocess.return_value.stderr = "Error: Password not found\n"

        # Call the `get_passphrase` function and assert that it returns `None`
        passphrase = agent.get_passphrase("invalid_pass_key", "/path/to/pass/store")
        assert passphrase is None


def test_get_private_key_with_valid_key_path():
    # Mock the `subprocess.run` function to return valid data
    with patch("subprocess.run") as mock_subprocess:
        mock_subprocess.return_value.returncode = 0
        mock_subprocess.return_value.stdout = "private_key\n"

        # Call the `get_private_key` function
        private_key = agent.get_private_key("/path/to/private/key")

        # Assertions
        assert private_key == "private_key"


def test_get_private_key_with_invalid_key_path():
    # Mock the `subprocess.run` function to return an error
    with patch("subprocess.run") as mock_subprocess:
        mock_subprocess.return_value.returncode = 1
        mock_subprocess.return_value.stderr = "Error: Key not found\n"

        # Call the `get_private_key` function and assert that it returns `None`
        private_key = agent.get_private_key("/invalid/key/path")
        assert private_key is None
