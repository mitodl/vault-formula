{% from "vault/map.jinja" import vault, vault_config with context %}

include:
  - vault

vault-config:
  file.managed:
    - name: {{ vault.conf_file }}
    - source: salt://vault/templates/conf.jinja
    - template: jinja
    - context:
      config: {{ vault_config }}
    - watch_in:
      - service: vault
    - require:
      - pkg: vault
