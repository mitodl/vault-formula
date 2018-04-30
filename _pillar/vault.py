# -*- coding: utf-8 -*-

'''
Retrieve data from Hashicorp Vault with the option of caching returned data

To retrieve data from Vault you can write your pillar as follows:

.. code:: yaml

    foo_pillar:
      - static_value: __vault__::secret/value[data.value]
      - dynamic_user: __vault__:cached:rabbitmq/creds/user[data.username]
      - dynamic_password: __vault__:cached:rabbitmq/creds/user[data.password]

'''

from __future__ import absolute_import, print_function, unicode_literals
import logging

import salt.loader

log = logging.getLogger(__name__)


def ext_pillar(minion_id, pillar, *args, **kwargs):
    render_function = salt.loader.render(__opts__, __salt__).get("vault")
    return render_function(pillar, cache_prefix=minion_id)
