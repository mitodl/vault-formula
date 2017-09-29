{% from "vault/map.jinja" import vault with context %}

include:
  - .service

configure_vault_server:
  file.managed:
    - name: /etc/vault/vault.json
    - makedirs: True
    - contents: |
        {{ vault.config | json(indent=2, sort_keys=True) | indent(8) }}
    - watch_in:
      - service: vault_service_running
    - require_in:
      - service: vault_service_running
