===============
vault
===============

SaltStack formula to install and configure Vault from Hashicorp for managing secrets in your infrastructure

.. note::

   This formula includes custom execution and state modules that must be synced to the target minion/master prior to executing the formula. These modules additionally require the `hvac` library to be installed for the extensions to be made available.


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

``vault.upgrade``
-----------------

Do an in place upgrade of Vault to the version specified in the `vault:overrides:version` pillar value.

``vault.tests``
----------------

Execute the tests for the associated state files.


Template
========

This formula was created from a cookiecutter template.

See https://github.com/mitodl/saltstack-formula-cookiecutter.
