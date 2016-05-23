{% from "hashicorp-vault/map.jinja" import hashicorp-vault, hashicorp-vault_config with context %}

include:
  - hashicorp-vault

hashicorp-vault-config:
  file.managed:
    - name: {{ hashicorp-vault.conf_file }}
    - source: salt://hashicorp-vault/templates/conf.jinja
    - template: jinja
    - context:
      config: {{ hashicorp-vault_config }}
    - watch_in:
      - service: hashicorp-vault
    - require:
      - pkg: hashicorp-vault
