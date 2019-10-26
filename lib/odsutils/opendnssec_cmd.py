# vim: autoindent tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python

import os
import subprocess
from enum import Enum
from datetime import datetime
from .key import *


class ODS:
    """
    This is the ods-enforcer -command -based helper class.
    """

    class OdsEnforcerOps(Enum):
        LIST_KEYS = 1

    def __init__(self, ZoneName: str):
        self.zone = ZoneName

        self.keys = self._get_zone_info()
        if not self.keys:
            raise ValueError("Zone %s doesn't exist!" % self.zone)

    def get_active_key(self):
        for keytag in self.keys:
            key = self.keys[keytag]
            if key.state == OdsKey.ODS_ZONE_STATUS_ACTIVE:
                return key

        return None

    def _get_zone_info(self):
        info = self._ods_enforcer_helper(ODS.OdsEnforcerOps.LIST_KEYS, self.zone)
        if not info:
            return None

        return info

    def _ods_enforcer_helper(self, operation: OdsEnforcerOps, zone: str):
        if operation == ODS.OdsEnforcerOps.LIST_KEYS:
            cmd_args = ['key list', '--verbose', '--keytype', 'ksk', '--zone', zone]
        else:
            raise ValueError("Unknown ODS enforcer operation! Op: %d" % operation)

        result = subprocess.run(['ods-enforcer'] + cmd_args, stdout=subprocess.PIPE)

        if operation == ODS.OdsEnforcerOps.LIST_KEYS:
            return self._ods_enforcer_cmd_list_keys_result(result.stdout.decode('utf-8'), zone)

        return False

    @staticmethod
    def _ods_enforcer_cmd_list_keys_result(output: str, zone: str):
        keys = {}
        for line in output.splitlines():
            line_parts = line.split()
            if not line_parts[0] == zone or not line_parts[1] == 'KSK':
                continue
            keytag = line_parts[9]
            keystate = line_parts[2]
            keybits = int(line_parts[5])
            keyalgo = int(line_parts[6])

            next_transition_str = '%s %s' % (line_parts[3], line_parts[4])
            next_transition = datetime.strptime(next_transition_str, '%Y-%m-%d %H:%M:%S')

            key = OdsKey(Type='KSK', Tag=keytag, State=keystate, Bits=keybits, Algorithm=keyalgo, NextTransition=next_transition)
            keys[keytag] = key

        if not keys:
            return None

        return keys
