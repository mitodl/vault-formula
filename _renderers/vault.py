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

__utils__ = {}


def __init__(opts):
    global __utils__
    __utils__.update(salt.loader.utils(opts))


def _read(path, *args, **kwargs):
    vault_client = __utils__['vault.build_client']()
    try:
        vault_data = local_cache[path]
    except KeyError:
        vault_data = local_cache[path] = vault_client.read(path)
    return vault_data


def _gen_if_missing(path, string_length=42, **kwargs):
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


def dispatch(func_name):
    func_dict = {
        '': _read,
        'cache': __salt__['vault.cached_read'],
        'gen_if_missing': _gen_if_missing
        }
    return func_dict[func_name]


def leaf_filter(leaf_data):
    return (isinstance(leaf_data, six.string_types)
            and leaf_data.startswith('__vault__'))


def render(data,
           saltenv='base',
           sls='',
           argline='',
           cache_prefix='',
           **kwargs):
    # Traverse data structure to leaf nodes
    for leaf_node, location, container in __utils__[
            'data_structures.traverse_leaf_nodes'](
                data, leaf_filter):
        # Parse leaf nodes
        instructions, path = leaf_node.split(':', 2)[1:]
        # Replace values in matching leaf nodes
        parsed_path = path.split('>')
        log.debug("Trying to load data from Vault at path %s", parsed_path[0])
        vault_data = dispatch(instructions)(parsed_path[0],
                                            cache_prefix=cache_prefix,
                                            **kwargs)
        container[location] = __utils__['data.traverse_dict'](
            vault_data, ':'.join(parsed_path[1:]))
    return data
