"""  
setup.py  
  
created by dromakin as 12.10.2022  
Project fastapi-keycloak  
"""

__author__ = 'dromakin'
__maintainer__ = 'dromakin'
__credits__ = ['dromakin', ]
__copyright__ = "Echelon, Inc, 2022"
__status__ = 'Development'
__version__ = 20221012

# Always prefer setuptools over distutils
from setuptools import setup, find_packages

# To use a consistent encoding
from codecs import open
from os import path

# The directory containing this file
HERE = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(HERE, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

# This call to setup() does all the work
setup(
    name="fastapi-keycloak-manager",
    version="1.0.0",
    description="fastapi-keycloak-manager is a Python package that integrate FastAPI app and Keycloak IAM system.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://fastapi-keycloak-manager.readthedocs.io/",
    author="Dmitriy Romakin",
    author_email="dvromakin@gmail.com",
    license="MIT",
    keywords=["keycloak", "openid", "oidc", "fastapi", 'Authentication', 'Authorization', 'Keycloak', 'FastAPI'],
    classifiers=[
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Development Status :: 3 - Alpha",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Operating System :: MacOS",
        "Operating System :: Unix",
        "Operating System :: Microsoft :: Windows",
    ],
    packages=find_packages(include=['fastapi_keycloak_manager']),
    include_package_data=True,
    install_requires=[
        "anyio>=3.4.0",
        "asgiref>=3.4.1",
        "certifi>=2021.10.8",
        "charset-normalizer>=2.0.9",
        "click>=8.0.3",
        "ecdsa>=0.17.0",
        "fastapi>=0.70.1",
        "idna>=3.3",
        "pyasn1>=0.4.8",
        "pydantic>=1.5a1",
        "python-jose>=3.3.0",
        "requests>=2.26.0",
        "rsa>=4.8",
        "six>=1.16.0",
        "sniffio>=1.2.0",
        "starlette>=0.16.0",
        "typing_extensions>=4.0.1",
        "urllib3>=1.26.7",
        "uvicorn>=0.16.0",
    ]
)
