# -*- coding: utf-8 -*-

'''
Supported Syntax

__vault__:cache:path/to/data>attribute>subattribute
__vault__:gen_if_missing[32]:path/to/key>attribute
'''
import logging
from datetime import datetime, timedelta

log = logging.getLogger(__name__)
local_cache = {}
cache_base_path = __opts__['vault.cache_base_path']
renewal_threshold = {'days: 7'}


def _read(path, *args):
    vault_client = __utils__['vault.build_client']()
    vault_data = local_cache.get(path, vault_client.read(cache_path))
    return vault_client.read(path)


def _cached_read(path, cache_prefix=None):
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


# def _gen_if_missing(path, *attrs):
#     vault_client = __utils__['vault.build_client']()
#     try:
#         local_cache[path]
        

dispatch = {
    '': _read,
    'cache': _cached_read,
    # 'gen_if_missing': _gen_if_missing
}


def render(data,
           saltenv='base',
           sls='',
           argline='',
           cache_prefix=None,
           **kwargs):
    # Traverse data structure to leaf nodes
    for leaf_node, location, container in __utils__[
            'data_structures.traverse_leaf_nodes'](
                data, lambda x: x.startswith('__vault__')):
        # Parse leaf nodes
        instructions, path = leaf_node.split(':', 2)[1:]
        # Replace values in matching leaf nodes
        parsed_path = path.split('>')
        vault_data = dispatch[instructions](parsed_path[0])
        container[location] = __utils__['data.traverse_dict'](
            vault_data, ':'.join(parsed_path[1:]))
    return data
