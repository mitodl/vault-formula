# -*- coding: utf-8 -*-
"""
This module provides methods for interacting with Hashicorp Vault via the HVAC
library.
"""
from __future__ import absolute_import

import logging
from datetime import datetime, timedelta

log = logging.getLogger(__name__)

try:
    import requests
    DEPS_INSTALLED = True
except ImportError:
    log.debug('Unable to import the requests library.')
    DEPS_INSTALLED = False

__all__ = ['initialize', 'is_initialized']

SEVEN_DAYS = (7 * 24 * 60 * 60)


def __init__(opts):
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
    except __utils__['vault.vault_error']() as e:
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
    except __utils__['vault.vault_error']() as e:
        log.error('Vault was initialized but PGP encrypted keys were not able to'
                  ' be generated after unsealing.')
        log.debug('Failed to rekey and backup the sealing keys.')
        log.exception(e)
    client.token = root_token
    return success, sealing_keys, root_token


def scan_leases(prefix='', time_horizon=SEVEN_DAYS, send_events=True):
    """Scan all leases and generate an event for any that are near expiration

    :param prefix: The prefix path of leases that you want to scan
    :param time_horizon: How far in advance you want to be alerted for expiring leases (seconds)
    :param send_events: Boolean to specify whether to fire events for matched leases
    :returns: List of lease info for leases expiring soon
    :rtype: list

    """
    client = __utils__['vault.build_client']()
    try:
        prefixes = client.list('sys/leases/lookup/{0}'.format(prefix))
    except __utils__['vault.vault_error']() as e:
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
            except __utils__['vault.vault_error']() as e:
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
        except __utils__['vault.vault_error']():
            log.exception('Failed to revoke lease %s', lease['id'])
            expired_leases.pop(index)
            continue
    return expired_leases


def check_cached_lease(path, cache_prefix='', **kwargs):
    """Check whether cached leases have expired and if they are renewable.

    :param path: path to the full vault cache path
    :param cache_prefix: usually the minion_id
    :param **kwargs: other data that the function might require
    :rtype: list, dict

    """
    lease_valid = None
    cache_base_path = __opts__.get('vault.cache_base_path',
                                   'secret/pillar_cache')
    cache_path = '/'.join((cache_base_path, cache_prefix, path))
    renewal_threshold = __opts__.get('vault.lease_renewal_threshold',
                                    {'days': 7})
    vault_client = __utils__['vault.build_client']()

    vault_data = vault_client.read(cache_path)

    if vault_data:
        vault_data = vault_data['data']['value']
        lease = vault_client.get_lease(vault_data['lease_id'])

        if (lease and timedelta(seconds=lease['data']['ttl']) >
                timedelta(**renewal_threshold)):
            lease_valid = True
        else:
            lease_valid = False
            vault_client.delete(cache_path)
            vault_data = None

    if not vault_data or not lease_valid:
        __salt__['event.send'](
            'vault/cache/miss/{0}'.format(cache_path),
            data={'message': 'The cached lease at {0} is either invalid or '
                             'expired and not renewable. It will be '
                             'regenerated and cached with new data.'
                             .format(cache_path)})
    return cache_path, vault_client, vault_data


def cached_read(path, cache_prefix='', **kwargs):
    """Generate new secret through vault read function and copy it to the vault
    cache path.

    :param path: path to the full vault cache path
    :param cache_prefix: usually the minion_id
    :param **kwargs: other data that the function might require
    :rtype: list, dict

    """
    cache_path, vault_client, vault_data = check_cached_lease(path,
                                                              cache_prefix=cache_prefix,
                                                              **kwargs)
    if not vault_data:
        vault_data = vault_client.read(path)
        vault_data['created'] = datetime.utcnow().isoformat()
        vault_client.write(cache_path, value=vault_data)
        vault_data = vault_client.read(cache_path)['data']['value']

    return vault_data


def cached_write(path, cache_prefix='', **kwargs):
    """Generate new secret through vault write function and copy it to the vault
    cache path.

    :param path: path to the full vault cache path
    :param cache_prefix: usually the minion_id
    :param **kwargs: other data that the function might require
    :rtype: list, dict

    """
    cache_path, vault_client, vault_data = check_cached_lease(path,
                                                              cache_prefix=cache_prefix,
                                                              **kwargs)
    if not vault_data:
        vault_data = vault_client.write(path, **kwargs)
        vault_data['created'] = datetime.utcnow().isoformat()
        vault_client.write(cache_path, value=vault_data)
        vault_data = vault_client.read(cache_path)['data']['value']

    return vault_data


def list_cache_paths(prefix=None, cache_filter=''):
    client = __utils__['vault.build_client']()
    if not prefix:
        prefix = __opts__.get('vault.cache_base_path',
                              'secret/pillar_cache')

    caches = client.list(
        prefix
    ).get('data', {}).get('keys', [])
    cache_paths = []
    for node in caches:
        if node.endswith('/'):
            log.debug('Recursing into path %s for prefix %s', node, prefix)
            cache_paths.extend(list_cache_paths(prefix='{0}/{1}'.format(
                prefix.strip('/'), node), cache_filter=cache_filter))
        else:
            cache_paths.append('{0}/{1}'.format(prefix.strip('/'), node))

    cache_paths = [path for path in cache_paths if cache_filter in path]
    return cache_paths


def list_cached_data(prefix=None, cache_filter='', attribute_path=''):
    client = __utils__['vault.build_client']()
    cache_paths = list_cache_paths(prefix, cache_filter)
    cached_data = []
    for path in cache_paths:
        cache_data = client.read(path)
        if attribute_path:
            cache_data = __utils__['data.traverse_dict'](cache_data,
                                                         attribute_path)
        cached_data.append((path, cache_data))
    return cached_data


def purge_cache_data(cache_filter):
    """Scan cached leases and delete any that match the given prefix

    :param prefix: The prefix path of cached leases that you want to purge
    :returns: List of lease ids that were deleted
    :rtype: list

    """
    client = __utils__['vault.build_client']()
    cached_leases = list_cache_paths(cache_filter=cache_filter)
    for path in cached_leases:
        client.delete(path)

    return cached_leases


def _register_functions():
    log.info('Utils object is: {0}'.format(__utils__))
    for method_name in dir(__utils__['vault.vault_client']()):
        if not method_name.startswith('_'):
            method = getattr(__utils__['vault.vault_client'](), method_name)
            if not isinstance(method, property):
                if method_name == 'list':
                    method_name = 'list_values'
                globals()[method_name] = __utils__['vault.bind_client'](method)
