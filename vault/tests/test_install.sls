{% from "vault/map.jinja" import vault, vault_service with context %}

test_vault_is_installed:
  testinfra.file:
    - name: /usr/local/bin/vault
    - exists: True
    - mode:
        expected: 493
        comparison: eq

test_vault_service_script_present:
  testinfra.file:
    - name: /usr/local/bin/vaultserver
    - exists: True
    - is_file: True
    - mode:
        expected: 493
        comparison: eq

test_vault_service_init_file_present:
  testinfra.file:
    - name: {{ vault_service.init_file }}
    - exists: True
    - is_file: True

test_vault_service_enabled:
  testinfra.service:
    - name: vault
    - is_enabled: True
    - is_running: True
