# -*- coding: utf-8 -*-
"""
This module provides methods for interacting with Hashicorp Vault via the HVAC
library.
"""
from __future__ import absolute_import

import logging
import inspect
import time
from functools import wraps
from datetime import datetime, timedelta

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

class InsufficientParameters(Exception):
    pass

def __virtual__():
    return DEPS_INSTALLED


def _cache_client(client_builder):
    _client = []
    @wraps(client_builder)
    def get_client(*args, **kwargs):
        if not _client:
            _client.append(client_builder(*args, **kwargs))
        return _client[0]
    return get_client


@_cache_client
def _build_client(url='https://localhost:8200', token=None, cert=None,
                  verify=True, timeout=30, proxies=None, allow_redirects=True,
                  session=None):
    client_kwargs = locals()
    for k, v in client_kwargs.items():
        if k.startswith('_'):
            continue
        arg_val = __salt__['config.get']('vault.{key}'.format(key=k), v)
        log.debug('Setting {0} parameter for HVAC client to {1}.'
                  .format(k, arg_val))
        client_kwargs[k] = arg_val
    return hvac.Client(**client_kwargs)


def _bind_client(unbound_function):
    @wraps(unbound_function)
    def bound_function(*args, **kwargs):
        filtered_kwargs = {k: v for k, v in kwargs.items() if not k.startswith('_')}
        ignore_invalid = filtered_kwargs.pop('ignore_invalid', None)
        client = _build_client()
        try:
            return unbound_function(client, *args, **filtered_kwargs)
        except hvac.exceptions.InvalidRequest:
            if ignore_invalid:
                return None
            else:
                raise
    return bound_function


def _get_keybase_pubkey(username):
    """
    Return the base64 encoded public PGP key for a keybase user.
    """
    # Retrieve the text of the public key stored in Keybase
    user = requests.get('https://keybase.io/{username}/key.asc'.format(
        username=username))
    # Explicitly raise an exception if there is an HTTP error. No-op if no error
    user.raise_for_status()
    # Process the key to only include the contents and not the wrapping
    # contents (e.g. ----BEGIN PGP KEY---)
    user_key = user.text
    key_lines = user.text.strip('\n').split('\n')
    key_lines = key_lines[key_lines.index(''):-2]
    return ''.join(key_lines)


def _unseal(sealing_keys):
    client = _build_client()
    client.unseal_multi(sealing_keys)


def _rekey(secret_shares, secret_threshold, sealing_keys, pgp_keys, root_token):
    client = _build_client(token=root_token)
    rekey = client.start_rekey(secret_shares, secret_threshold, pgp_keys,
                               backup=True)
    client.rekey_multi(sealing_keys, nonce=rekey['nonce'])


def _wait_after_init(client, retries=5):
    '''This function will allow for a configurable delay before attempting
    to issue requests after an initialization. This is necessary because when
    running on an HA backend there is a short period where the Vault instance
    will be on standby while it acquires the lock.'''
    ready = False
    while retries > 0 and not ready:
        try:
            status = client.read('sys/health')
            ready = (status.get('initialized') and not status.get('sealed')
                     and not status.get('standby'))
        except hvac.exceptions.VaultError:
            pass
        if ready:
            break
        retries -= 1
        time.sleep(1)

def initialize(secret_shares=5, secret_threshold=3, pgp_keys=None,
               keybase_users=None, unseal=True):
    success = True
    if keybase_users and isinstance(keybase_users, list):
        keybase_keys = []
        for user in keybase_users:
            log.debug('Retrieving public keys for Keybase user {}.'
                      .format(user))
            keybase_keys.append(_get_keybase_pubkey(user))
        pgp_keys = pgp_keys or []
        pgp_keys.extend(keybase_keys)
    if pgp_keys and len(pgp_keys) < secret_shares:
        raise InsufficientParameters('The number of PGP keys does not match'
                                     ' the number of secret shares.')
    client = _build_client()
    try:
        if pgp_keys and not unseal:
            secrets = client.initialize(secret_shares, secret_threshold,
                                        pgp_keys)
        else:
            secrets = client.initialize(secret_shares, secret_threshold)
        sealing_keys = secrets['keys']
        root_token = secrets['root_token']
        if unseal:
            _wait_after_init(client)
            log.debug('Unsealing Vault with generated sealing keys.')
            _unseal(sealing_keys)
    except hvac.exceptions.VaultError as e:
        log.exception(e)
        success = False
        sealing_keys = None
    try:
        if pgp_keys and unseal:
            _wait_after_init(client)
            log.debug('Regenerating PGP encrypted keys and backing them up.')
            log.debug('PGP keys: {}'.format(pgp_keys))
            client.token = root_token
            _rekey(secret_shares, secret_threshold, sealing_keys,
                   pgp_keys, root_token)
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
    client = _build_client()
    try:
        prefixes = client.list('sys/leases/lookup/{0}'.format(prefix))
    except hvac.exceptions.VaultError as e:
        log.exception('Failed to retrieve lease information for prefix %s', prefix)
        return []
    if prefixes:
        prefixes = prefixes.get('data', {}).get('keys', [])
    else:
        prefixes = []
    expiring_leases = []
    for node in prefixes:
        if node.endswith('/'):
            log.debug('Recursing into path %s for prefix %s', node, prefix)
            expiring_leases.extend(scan_leases('{0}/{1}'.format(prefix.strip('/'), node), time_horizon))
        else:
            log.debug('Retrieving lease information for %s/%s', prefix, node)
            try:
                lease_info = client.write('sys/leases/lookup', lease_id='{0}/{1}'.format(prefix.strip('/'), node))
            except hvac.exceptions.VaultError as e:
                log.exception('Failed to retrieve lease information for %s',
                              '{0}/{1}'.format(prefix.strip('/'), node))
                continue
            lease_expiry = datetime.strptime(lease_info.get('data', {}).get('expire_time')[:-4], '%Y-%m-%dT%H:%M:%S.%f')
            lease_lifetime = lease_expiry - datetime.utcnow()
            if lease_lifetime < timedelta(seconds=time_horizon):
                if send_events:
                    __salt__['event.send']('vault/lease/expiring/{0}/{1}'.format(prefix, node), data=lease_info.get('data', {}))
                expiring_leases.append(lease_info.get('data', {}))
    return expiring_leases


def clean_expired_leases(prefix='', time_horizon=0):
    """Scan all leases and delete any that have an expiration beyond the specified time horizon

    :param prefix: The prefix path of leases that you want to scan
    :param time_horizon: How far in advance you want to be alerted for expiring leases (seconds)
    :returns: List of lease info for leases that were deleted
    :rtype: list

    """
    client = _build_client()
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
    method_dict = {}
    for method_name in dir(hvac.Client):
        if not method_name.startswith('_'):
            method = getattr(hvac.Client, method_name)
            if (not isinstance(method, property) and
                  method_name not in EXCLUDED_HVAC_FUNCTIONS):
                if method_name == 'list':
                    method_name = 'list_values'
                globals()[method_name] = _bind_client(method)

if DEPS_INSTALLED:
    _register_functions()
