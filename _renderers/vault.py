# -*- coding: utf-8 -*-

'''
Supported Syntax

__vault__:cached:path/to/data[attribute.subattribute]
__vault__:gen_if_missing[32]:path/to/key[attribute]
__vault__:get[default]:path/to/key[attribute]
__vault__:post[post_data]:path/to/endpoint[attribute]
'''

import logging

log = logging.getLogger(__name__)


def render(data,
           saltenv='base',
           sls='',
           argline='',
           cache_prefix=None,
           **kwargs):
    # Traverse data structure to leaf nodes
    for leaf_node, location, container in traverse_leaf_nodes(
            data, lambda x: x.startswith('__vault__')):
        # Parse leaf nodes
        parsed_node = leaf_node.lsplit(':', 2)[1:]
        # Replace values in matching leaf nodes
