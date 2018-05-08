# -*- coding: utf-8 -*-

'''
Supported Syntax

__vault__:cache:path/to/data>attribute>subattribute
__vault__:gen_if_missing[32]:path/to/key>attribute
'''
import logging
from datetime import datetime, timedelta

import six
import salt.loader

log = logging.getLogger(__name__)
local_cache = {}
renewal_threshold = {'days: 7'}

__utils__ = {}


def __init__(opts):
    global __utils__
    __utils__.update(salt.loader.utils(opts))


def _read(path, *args):
    vault_client = __utils__['vault.build_client']()
    try:
        vault_data = local_cache[path]
    except KeyError:
        vault_data = local_cache[path] = vault_client.read(path)
    return vault_data


def _cached_read(path, cache_prefix=None):
    cache_base_path = __opts__.get('vault.cache_base_path', 'secret/cache')
    cache_path = '/'.join((cache_base_path, cache_prefix, path))
    vault_client = __utils__['vault.build_client']()

    try:
        vault_data = local_cache[path]
    except KeyError:
        vault_data = local_cache[path] = vault_client.read(cache_path)

    if vault_data:
        lease_info = vault_client.write('sys/leases/lookup',
                                        lease_id=vault_data.lease_id)
        lease_valid = (datetime.strptime(
            lease_info['data']['expire_time'].split('.')[0],
            '%Y-%m-%dT%H:%M:%S') > (datetime.utcnow()
                                    + timedelta(**renewal_threshold)))

    if not vault_data or not lease_valid:
        vault_data = local_cache[path] = vault_client.read(path)
        vault_client.write(cache_path, vault_data)

    return vault_data


def _gen_if_missing(path, string_length=42):
    vault_client = __utils__['vault.build_client']()
    try:
        vault_data = local_cache[path]
    except KeyError:
        vault_data = local_cache[path] = vault_client.read(path)

    if not vault_data:
        new_value = __salt__['random.get_str'](string_length)
        vault_client.write(path, value=new_value)
        vault_data = local_cache[path] = vault_client.read(path)

    return vault_data

dispatch = {
    '': _read,
    'cache': _cached_read,
    'gen_if_missing': _gen_if_missing
}


def leaf_filter(leaf_data):
    return (isinstance(leaf_data, six.string_types)
            and leaf_data.startswith('__vault__'))


def render(data,
           saltenv='base',
           sls='',
           argline='',
           cache_prefix=None,
           **kwargs):
    # Traverse data structure to leaf nodes
    for leaf_node, location, container in __utils__[
            'data_structures.traverse_leaf_nodes'](
                data, leaf_filter):
        # Parse leaf nodes
        instructions, path = leaf_node.split(':', 2)[1:]
        # Replace values in matching leaf nodes
        parsed_path = path.split('>')
        vault_data = dispatch[instructions](parsed_path[0])
        container[location] = __utils__['data.traverse_dict'](
            vault_data, ':'.join(parsed_path[1:]))
    return data