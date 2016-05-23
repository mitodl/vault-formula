{% from "vault/map.jinja" import vault with context %}

vault:
  pkg.installed:
    - pkgs: {{ vault.pkgs }}
  service:
    - running
    - name: {{ vault.service }}
    - enable: True
    - require:
      - pkg: vault
