# FastAPI Keycloak Manager

# How to install

## TestPyPI 
- [fastapi-keycloak-manager](https://test.pypi.org/project/fastapi-keycloak-manager/)

From repository:
```shell
pip install -i https://test.pypi.org/simple/ fastapi-keycloak-manager
```

### Using TestPyPI with pip
You can tell pip to download packages from TestPyPI instead of PyPI by specifying the --index-url flag:

#### Unix/macOS
```shell
python3 -m pip install --index-url https://test.pypi.org/simple/ fastapi-keycloak-manager
```

#### Windows
```shell
py -m pip install --index-url https://test.pypi.org/simple/ fastapi-keycloak-manager
```

If you want to allow pip to also download packages from PyPI, you can specify --extra-index-url to point to PyPI. 
This is useful when the package you’re testing has dependencies:

#### Unix/macOS
```shell
python3 -m pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ fastapi-keycloak-manager
```

Windows
```shell
py -m pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ fastapi-keycloak-manager
```

### Help TestPyPL
- [Using TestPyPI](https://packaging.python.org/en/latest/guides/using-testpypi/)

