===============
vault
===============

SaltStack formula to install and configure Vault from Hashicorp for managing secrets in your infrastructure

.. note::

    See the full `Salt Formulas installation and usage instructions
    <http://docs.saltstack.com/en/latest/topics/development/conventions/formulas.html>`_.


Available states
================

.. contents::
    :local:

``vault``
-------------------

Install and start the Vault server

``vault.configure``
------------------------

Create a configuration file for the installed Vault server and restart the Vault service

``vault.initialize``
--------------------

Initialize and optionally unseal the installed Vault server. If PGP public keys or Keybase usernames are provided then the sealing keys will be regenerated after unsealing and then backed up to the Vault server.

``vault.tests``
----------------

Execute the tests for the associated state files.


Template
========

This formula was created from a cookiecutter template.

See https://github.com/mitodl/saltstack-formula-cookiecutter.
