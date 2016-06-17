include:
  - vault.install_module_dependencies

install_testinfra_library:
  pip.installed:
    - name: git+https://github.com/mitodl/testinfra
    - reload_modules: True
