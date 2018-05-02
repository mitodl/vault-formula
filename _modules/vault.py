# -*- coding: utf-8 -*-
"""
This module provides methods for interacting with Hashicorp Vault via the HVAC
library.
"""
from __future__ import absolute_import

import logging
from datetime import datetime, timedelta
import salt.loader

log = logging.getLogger(__name__)
EXCLUDED_HVAC_FUNCTIONS = ['initialize']

try:
    import hvac
    import requests
    DEPS_INSTALLED = True
except ImportError:
    log.debug('Unable to import the HVAC library.')
    DEPS_INSTALLED = False

__all__ = ['initialize', 'is_initialized']

__utils__ = {}


def __init__(opts):
    global __utils__
    __utils__.update(salt.loader.utils(opts))

    if DEPS_INSTALLED:
        _register_functions()


class InsufficientParameters(Exception):
    pass


def __virtual__():
    return DEPS_INSTALLED


def initialize(secret_shares=5, secret_threshold=3, pgp_keys=None,
               keybase_users=None, unseal=True):
    success = True
    if keybase_users and isinstance(keybase_users, list):
        keybase_keys = []
        for user in keybase_users:
            log.debug('Retrieving public keys for Keybase user {}.'
                      .format(user))
            keybase_keys.append(__utils__['vault.get_keybase_pubkey'](user))
        pgp_keys = pgp_keys or []
        pgp_keys.extend(keybase_keys)
    if pgp_keys and len(pgp_keys) < secret_shares:
        raise InsufficientParameters('The number of PGP keys does not match'
                                     ' the number of secret shares.')
    client = __utils__['vault.build_client']()
    try:
        if pgp_keys and not unseal:
            secrets = client.initialize(secret_shares, secret_threshold,
                                        pgp_keys)
        else:
            secrets = client.initialize(secret_shares, secret_threshold)
        sealing_keys = secrets['keys']
        root_token = secrets['root_token']
        if unseal:
            __utils__['vault.wait_after_init'](client)
            log.debug('Unsealing Vault with generated sealing keys.')
            __utils__['vault.unseal'](sealing_keys)
    except hvac.exceptions.VaultError as e:
        log.exception(e)
        success = False
        sealing_keys = None
    try:
        if pgp_keys and unseal:
            __utils__['vault.wait_after_init'](client)
            log.debug('Regenerating PGP encrypted keys and backing them up.')
            log.debug('PGP keys: {}'.format(pgp_keys))
            client.token = root_token
            __utils__['vault.rekey'](secret_shares, secret_threshold,
                                     sealing_keys, pgp_keys, root_token)
            encrypted_sealing_keys = client.get_backed_up_keys()['keys']
            if encrypted_sealing_keys:
                sealing_keys = encrypted_sealing_keys
    except hvac.exceptions.VaultError as e:
        log.error('Vault was initialized but PGP encrypted keys were not able to'
                  ' be generated after unsealing.')
        log.debug('Failed to rekey and backup the sealing keys.')
        log.exception(e)
    client.token = root_token
    return success, sealing_keys, root_token


def scan_leases(prefix='', time_horizon=0, send_events=True):
    """Scan all leases and generate an event for any that are near expiration

    :param prefix: The prefix path of leases that you want to scan
    :param time_horizon: How far in advance you want to be alerted for expiring leases (seconds)
    :returns: List of lease info for leases expiring soon
    :rtype: list

    """
    client = __utils__['vault.build_client']()
    try:
        prefixes = client.list('sys/leases/lookup/{0}'.format(prefix))
    except hvac.exceptions.VaultError as e:
        log.exception('Failed to retrieve lease information for prefix %s',
                      prefix)
        return []
    if prefixes:
        prefixes = prefixes.get('data', {}).get('keys', [])
    else:
        prefixes = []
    expiring_leases = []
    for node in prefixes:
        if node.endswith('/'):
            log.debug('Recursing into path %s for prefix %s', node, prefix)
            expiring_leases.extend(scan_leases('{0}/{1}'.format(
                prefix.strip('/'), node), time_horizon))
        else:
            log.debug('Retrieving lease information for %s/%s', prefix, node)
            try:
                lease_info = client.write(
                    'sys/leases/lookup',
                    lease_id='{0}/{1}'.format(prefix.strip('/'), node))
            except hvac.exceptions.VaultError as e:
                log.exception('Failed to retrieve lease information for %s',
                              '{0}/{1}'.format(prefix.strip('/'), node))
                continue
            lease_expiry = datetime.strptime(
                lease_info.get('data', {}).get('expire_time')[:-4],
                '%Y-%m-%dT%H:%M:%S.%f')
            lease_lifetime = lease_expiry - datetime.utcnow()
            if lease_lifetime < timedelta(seconds=time_horizon):
                if send_events:
                    __salt__['event.send'](
                        'vault/lease/expiring/{0}/{1}'.format(prefix, node),
                        data=lease_info.get('data', {}))
                expiring_leases.append(lease_info.get('data', {}))
    return expiring_leases


def clean_expired_leases(prefix='', time_horizon=0):
    """Scan all leases and delete any that have an expiration beyond the specified time horizon

    :param prefix: The prefix path of leases that you want to scan
    :param time_horizon: How far in advance you want to be alerted for expiring leases (seconds)
    :returns: List of lease info for leases that were deleted
    :rtype: list

    """
    client = __utils__['vault.build_client']()
    expired_leases = scan_leases(prefix, time_horizon, send_events=False)
    for index, lease in enumerate(expired_leases):
        try:
            client.write('sys/leases/revoke', lease_id=lease['id'])
        except hvac.exceptions.VaultError:
            log.exception('Failed to revoke lease %s', lease['id'])
            expired_leases.pop(index)
            continue
    return expired_leases


def _register_functions():
    log.info('Utils object is: {0}'.format(__utils__))
    for method_name in dir(__utils__['vault.VaultClient']):
        if not method_name.startswith('_'):
            method = getattr(__utils__['vault.VaultClient'], method_name)
            if (not isinstance(method, property) and
                    method_name not in EXCLUDED_HVAC_FUNCTIONS):
                if method_name == 'list':
                    method_name = 'list_values'
                globals()[method_name] = __utils__['vault.bind_client'](method)
