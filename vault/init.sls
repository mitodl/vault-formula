{% from "vault/map.jinja" import vault, vault_service with context %}

include:
  - .configure
  - .service

install_vault_binary:
  archive.extracted:
    - name: /usr/local/bin/
    - source: https://releases.hashicorp.com/vault/{{ vault.version }}/vault_{{ vault.version }}_linux_{{ grains['osarch'] }}.zip
    - source_hash: https://releases.hashicorp.com/vault/{{ vault.version }}/vault_{{ vault.version }}_SHA256SUMS
    - archive_format: zip
    - if_missing: /usr/local/bin/vault
  file.managed:
    - name: /usr/local/bin/vault
    - mode: '0755'
    - require:
      - archive: install_vault_binary
    - require_in:
      - file: configure_vault_server

install_vault_server_management_script:
  file.managed:
    - name: /usr/local/bin/vaultserver
    - source: salt://vault/files/vault_service.sh
    - mode: '0755'
    - require_in:
      - service: vault_service_running

install_vault_init_configuration:
  file.managed:
    - name: {{ vault_service.init_file }}
    - source: {{ vault_service.init_source }}
    - require_in:
      - service: vault_service_running

{% if salt.grains.get('init') == 'systemd' %}
reload_systemd_units:
  cmd.wait:
    - name: systemctl daemon-reload
    - watch:
      - file: install_vault_init_configuration
    - require_in:
      - service: vault_service_running
{% endif %}

ensure_vault_ssl_directory:
  file.directory:
    - name: {{ vault.ssl_directory }}/certs
    - makedirs: True

{% if vault.ssl.get('cert_source') or vault.ssl.get('cert_contents') %}
setup_vault_ssl_cert:
  file.managed:
    - name: {{vault.ssl_directory}}/certs/{{ vault.ssl.cert_file }}
    {% if vault.ssl.get('cert_source') %}
    - source: {{ vault.ssl.cert_source }}
    {% elif vault.ssl.get('cert_contents') %}
    - contents: |
        {{ vault.ssl.cert_contents | indent(8) }}
    {% endif %}
    - makedirs: True
    - require_in:
      - service: vault_service_running

setup_vault_ssl_key:
  file.managed:
    - name: {{vault.ssl_directory}}/certs/{{ vault.ssl.key_file }}
    {% if vault.ssl.get('key_source') %}
    - source: {{ vault.ssl.key_source }}
    {% elif vault.ssl.get('key_contents') %}
    - contents: |
        {{ vault.ssl.key_contents | indent(8) }}
    {% endif %}
    - makedirs: True
    - require_in:
      - service: vault_service_running
{% else %}
setup_vault_ssl_cert:
  module.run:
    - name: tls.create_self_signed_cert
    - tls_dir: ''
    - cacert_path: {{ vault.ssl_directory }}
    - makedirs: True
    {% for arg, val in salt.pillar.get('vault:ssl:cert_params',
       {'CN': 'vault.example.com'}).items() -%}
    - {{ arg }}: {{ val }}
    {% endfor -%}
    - require_in:
      - service: vault_service_running
{% endif %}
