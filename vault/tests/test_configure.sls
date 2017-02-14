test_config_file_present:
  testinfra.file:
    - name: /etc/vault/vault.json
    - exists: True
    - is_file: True
