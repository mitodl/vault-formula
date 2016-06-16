{% from "vault/map.jinja" import vault with context %}

include:
  - .install_module_dependencies

install_hvac_library:
  pip.installed:
    - name: git+https://github.com/mitodl/hvac
    - reload_modules: True

initialize_vault_server:
  vault.initialized:
    - secret_shares: {{ vault.secret_shares }}
    - secret_threshold: {{ vault.secret_threshold }}
    - unseal: {{ vault.unseal }}
    - pgp_keys: {{ vault.pgp_keys }}
    - keybase_users: {{ vault.keybase_users }}
