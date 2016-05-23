{% from "hashicorp-vault/map.jinja" import hashicorp-vault with context %}

hashicorp-vault:
  pkg.installed:
    - pkgs: {{ hashicorp-vault.pkgs }}
  service:
    - running
    - name: {{ hashicorp-vault.service }}
    - enable: True
    - require:
      - pkg: hashicorp-vault
