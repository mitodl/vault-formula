include:
  - .init

test_hvac_library_installed:
  testinfra.python_package:
    - name: hvac
    - is_installed: True
