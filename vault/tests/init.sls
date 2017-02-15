include:
  - vault.install_module_dependencies
  - .test_install
  - .test_configure

install_testinfra_library_for_vault_testing:
  pip.installed:
    - name: testinfra
    - reload_modules: True
    - order: 1
