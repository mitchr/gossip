# This code is modified from the progval/irctest controller for ergo:
# https://github.com/progval/irctest/blob/master/irctest/controllers/ergo.py

import copy
import json
import os
import shutil
import subprocess
from typing import Any, Dict, Optional, Set, Type, Union

from irctest.basecontrollers import (
    BaseServerController,
    DirectoryBasedController,
    NotImplementedByController,
)
from irctest.cases import BaseServerTestCase


BASE_CONFIG = {
  "network": "cafeteria",
  "name": "My.Little.Server",
  "port": ":6667",
  "tls": {
    "enabled": False,
    "port": ":6697",
    "pubkey": "",
    "privkey": "",
    "sts": {
      "enabled": False
    }
  },
  "motd": "",
  "ops": {
    "operuser": "JDJhJDEwJEQ0TldiOTJUVVR5MW1nQmtOZjNweXVkSTBHUjE4Y05jNlZYN1hpWDRndDcvUGFidjczZzhD" #operpassword
  }
}

def hash_password(password: Union[str, bytes]) -> str:
    if isinstance(password, str):
        password = password.encode("utf-8")
    # simulate entry of password and confirmation:
    input_ = password + b"\n" + password + b"\n"
    p = subprocess.Popen(
        ["gossip", "-s"], stdin=subprocess.PIPE, stdout=subprocess.PIPE
    )
    out, _ = p.communicate(input_)
    return out.decode("utf-8")


class GossipController(BaseServerController, DirectoryBasedController):
    software_name = "Gossip"
    _port_wait_interval = 0.01
    supported_sasl_mechanisms = {"PLAIN", "SCRAM-SHA-256"}
    supports_sts = True
    extban_mute_char = "m"

    def create_config(self) -> None:
        super().create_config()
        with self.open_file("ircd.json"):
            pass

    def run(
        self,
        hostname: str,
        port: int,
        *,
        password: Optional[str],
        ssl: bool,
        run_services: bool,
        valid_metadata_keys: Optional[Set[str]] = None,
        invalid_metadata_keys: Optional[Set[str]] = None,
        restricted_metadata_keys: Optional[Set[str]] = None,
        faketime: Optional[str],
        config: Optional[Any] = None,
    ) -> None:
        if valid_metadata_keys or invalid_metadata_keys:
            raise NotImplementedByController(
                "Defining valid and invalid METADATA keys."
            )

        self.create_config()
        if config is None:
            config = copy.deepcopy(BASE_CONFIG)

        assert self.directory

        self.port = port
        config["port"]=":%s" % port
        bind_address = "127.0.0.1:%s" % (port,)
        listener_conf = None  # plaintext
        if ssl:
            self.key_path = self.directory / "ssl.key"
            self.pem_path = self.directory / "ssl.pem"
            config["tls"]["enabled"] = True
            config["tls"]["pubkey"] = self.pem_path
            config["tls"]["privkey"] = self.key_path

        # config["datastore"]["path"] = os.path.join(  # type: ignore
        #     self.directory, "ircd.db"
        # )

        assert self.proc is None

        if password is not None:
            # password
            config["password"] = "JDJhJDEyJFVTVFMvb01IRWMvUGx5M29BZ00wYWVHREMuSjlWSUx2TkVWOEV2akVyVEw3enRmc1JRbjgu"

        self._config_path = self.directory / "config.json"
        self._config = config
        self._write_config()

        if faketime and shutil.which("faketime"):
            faketime_cmd = ["faketime", "-f", faketime]
            self.faketime_enabled = True
        else:
            faketime_cmd = []

        self.proc = subprocess.Popen(
            [*faketime_cmd, "gossip", "-conf", self._config_path]
        )

    def wait_for_services(self) -> None:
        pass

    def registerUser(
        self,
        case: BaseServerTestCase,
        username: str,
        password: Optional[str] = None,
    ) -> None:
        # XXX: Move this somewhere else when
        # https://github.com/ircv3/ircv3-specifications/pull/152 becomes
        # part of the specification
        if not case.run_services:
            # Ergo does not actually need this, but other controllers do, so we
            # are checking it here as well for tests that aren't tested with other
            # controllers.
            raise ValueError(
                "Attempted to register a nick, but `run_services` it not True."
            )
        client = case.addClient(show_io=False)
        case.sendLine(client, "CAP LS 302")
        case.sendLine(client, "NICK " + username)
        case.sendLine(client, "USER r e g :user")
        case.sendLine(client, "CAP END")
        while case.getRegistrationMessage(client).command != "001":
            pass
        case.getMessages(client)
        assert password
        case.sendLine(client, "REGISTER PASS " + password)
        msg = case.getMessage(client)
        assert msg.params == ["Registered"]
        case.sendLine(client, "QUIT")
        case.assertDisconnected(client)

    def _write_config(self) -> None:
        with open(self._config_path, "w") as fd:
            json.dump(self._config, fd)


def get_irctest_controller_class() -> Type[GossipController]:
    return GossipController
