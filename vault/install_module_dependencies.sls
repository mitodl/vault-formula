{% from "vault/map.jinja" import vault, vault_service with context %}

install_package_dependencies:
  pkg.installed:
    - pkgs: {{ vault.module_dependencies.pkgs }}
    - reload_modules: True

install_pip_executable:
  cmd.run:
    - name: |
        curl -L "https://bootstrap.pypa.io/get-pip.py" > get_pip.py
        sudo python get_pip.py
        rm get_pip.py
    - reload_modules: True
    - unless: which pip
