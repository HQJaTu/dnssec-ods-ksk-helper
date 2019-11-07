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
        LIST_KSK_KEYS = 1,
        LIST_KSK_KEYS_DEBUG = 2,
        GET_PUBLISH_KSK_KEY = 3,
        GET_READY_KSK_KEY = 4,
        GET_RETIRED_KSK_KEY = 5

    def __init__(self, ZoneName: str):
        self.zone = ZoneName

        self.keys = self._get_zone_info()
        if not self.keys:
            raise ValueError("Zone %s doesn't exist!" % self.zone)

    def get_active_key(self):
        return self._get_key_with_state(OdsKey.ODS_ZONE_STATUS_ACTIVE)

    def get_key_to_publish(self):
        key = self._get_key_with_state(OdsKey.ODS_ZONE_STATUS_PUBLISH)
        if not key:
            return None

        keys_info = self._ods_enforcer_helper(ODS.OdsEnforcerOps.GET_PUBLISH_KSK_KEY, self.zone)
        if str(key.tag) in keys_info:
            key_info = keys_info[key.tag]
            key.ds_digest = key_info[1]

        return key

    def get_ready_key(self):
        key = self._get_key_with_state(OdsKey.ODS_ZONE_STATUS_READY)
        if not key:
            return None

        keys_info = self._ods_enforcer_helper(ODS.OdsEnforcerOps.GET_READY_KSK_KEY, self.zone)
        if str(key.tag) in keys_info:
            key_info = keys_info[key.tag]
            key.ds_digest = key_info[1]

        return key

    def get_retired_keys(self):
        keys = self._get_keys_with_state(OdsKey.ODS_ZONE_STATUS_RETIRE)
        if not keys:
            return None

        keys_info = self._ods_enforcer_helper(ODS.OdsEnforcerOps.GET_RETIRED_KSK_KEY, self.zone)
        for key_tag in keys:
            key = keys[key_tag]
            if str(key.tag) in keys_info:
                key_info = keys_info[key.tag]
                key.ds_digest = key_info[1]

        return keys

    def _get_key_with_state(self, state: str):
        for keytag in self.keys:
            key = self.keys[keytag]
            if key.state == state:
                return key

        return None

    def _get_keys_with_state(self, state: str):
        ret_keys = {}
        for keytag in self.keys:
            key = self.keys[keytag]
            if key.state == state:
                ret_keys[int(keytag)] = key

        return ret_keys

    def _get_zone_info(self):
        info = self._ods_enforcer_helper(ODS.OdsEnforcerOps.LIST_KSK_KEYS, self.zone)
        if not info:
            return None

        return info

    def _ods_enforcer_helper(self, operation: OdsEnforcerOps, zone: str):
        if operation == ODS.OdsEnforcerOps.LIST_KSK_KEYS:
            cmd_args = ['key list', '--verbose', '--keytype', 'ksk', '--zone', zone]
        elif operation == ODS.OdsEnforcerOps.LIST_KSK_KEYS_DEBUG:
            cmd_args = ['key list', '--verbose', '--keytype', 'ksk', '--zone', zone, '--debug']
        elif operation == ODS.OdsEnforcerOps.GET_PUBLISH_KSK_KEY:
            cmd_args = ['key export', '--zone', zone, '--keytype ksk --keystate publish --ds']
        elif operation == ODS.OdsEnforcerOps.GET_READY_KSK_KEY:
            cmd_args = ['key export', '--zone', zone, '--keytype ksk --keystate ready --ds']
        elif operation == ODS.OdsEnforcerOps.GET_RETIRED_KSK_KEY:
            cmd_args = ['key export', '--zone', zone, '--keytype ksk --keystate retire --ds']
        else:
            raise ValueError("Unknown ODS enforcer operation! Op: %d" % operation)

        result = subprocess.run(['ods-enforcer'] + cmd_args, stdout=subprocess.PIPE)

        if operation == ODS.OdsEnforcerOps.LIST_KSK_KEYS:
            return self._ods_enforcer_cmd_list_keys_result(result.stdout.decode('utf-8'), zone)
        elif operation == ODS.OdsEnforcerOps.LIST_KSK_KEYS_DEBUG:
            return self._ods_enforcer_cmd_list_keys_debug_result(result.stdout.decode('utf-8'), zone)
        elif operation == ODS.OdsEnforcerOps.GET_PUBLISH_KSK_KEY:
            return self._ods_enforcer_cmd_key_export_result(result.stdout.decode('utf-8'), zone)
        elif operation == ODS.OdsEnforcerOps.GET_READY_KSK_KEY:
            return self._ods_enforcer_cmd_key_export_result(result.stdout.decode('utf-8'), zone)
        elif operation == ODS.OdsEnforcerOps.GET_RETIRED_KSK_KEY:
            return self._ods_enforcer_cmd_key_export_result(result.stdout.decode('utf-8'), zone)

        return False

    @staticmethod
    def _ods_enforcer_cmd_list_keys_result(output: str, zone: str):
        keys = {}
        for line in output.splitlines():
            line_parts = line.split()
            if not line_parts[0] == zone or not line_parts[1] == 'KSK':
                continue
            keystate = line_parts[2]
            bits_idx = 5
            do_transition = True
            while not line_parts[bits_idx].isdigit():
                bits_idx += 1
                do_transition = False
            keytag = line_parts[bits_idx + 4]
            keybits = int(line_parts[bits_idx])
            keyalgo = int(line_parts[bits_idx + 1])

            if do_transition:
                next_transition_str = '%s %s' % (line_parts[3], line_parts[4])
                next_transition = datetime.strptime(next_transition_str, '%Y-%m-%d %H:%M:%S')
            else:
                next_transition = None

            # Note: This output does NOT display the key digest algorithm.
            key = OdsKey(Type='KSK', Tag=keytag, State=keystate, Bits=keybits, Algorithm=keyalgo,
                         NextTransition=next_transition)
            keys[keytag] = key

        if not keys:
            return None

        return keys

    @staticmethod
    def _ods_enforcer_cmd_key_export_result(output: str, zone: str):
        keyinfo = {}
        for line in output.splitlines():
            line_parts = line.split()
            if not (line_parts[0] == '%s.' % zone and line_parts[2] == 'IN' and line_parts[3] == 'DS'):
                continue
            keytag = line_parts[4]
            keyalgo = int(line_parts[5])
            keydigest_type = int(line_parts[6])
            keydigest = line_parts[7]

            keyinfo[keytag] = [keyalgo, keydigest_type, keydigest]

        if not keyinfo:
            return None

        return keyinfo

    def _ods_enforcer_cmd_list_keys_debug_result(output: str, zone: str):
        keyinfo = {}
        for line in output.splitlines():
            line_parts = line.split()
            if not line_parts[0] == zone or not line_parts[1] == 'KSK':
                continue

            # Note: ZSKs don't have DS, only KSKs do
            ds_state = line_parts[2]
            if ds_state == 'NA':
                ds_state = None
            dnskey = line_parts[3]
            rrsigndnskey = line_parts[4]
            rrsig = line_parts[5]
            # Note: KSKs don't have RRSIG, only ZSK do
            if rrsig == 'NA':
                rrsig = None
            pub = int(line_parts[6])
            act = int(line_parts[7])
            id = line_parts[8]

            keyinfo[id] = [ds_state, dnskey, rrsigndnskey, rrsig, pub, act]

        if not keyinfo:
            return None

        return keyinfo
