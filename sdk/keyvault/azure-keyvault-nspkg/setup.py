#!/usr/bin/env python

# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------
import sys
from setuptools import setup

# azure v0.x is not compatible with this package
# azure v0.x used to have a __version__ attribute (newer versions don't)
try:
    import azure

    try:
        ver = azure.__version__
        raise Exception(
            "This package is incompatible with azure=={}. ".format(ver) + 'Uninstall it with "pip uninstall azure".'
        )
    except AttributeError:
        pass
except ImportError:
    pass

PACKAGES = []
# Do an empty package on Python 3 and not python_requires, since not everybody is ready
# https://github.com/Azure/azure-sdk-for-python/issues/3447
# https://github.com/Azure/azure-sdk-for-python/issues/3481
if sys.version_info[0] < 3:
    PACKAGES = ["azure.keyvault"]

setup(
    name="azure-keyvault-nspkg",
    version="3.0.0",
    description="Microsoft Azure Key Vault Namespace Package [Internal]",
    long_description=open("README.md", "r").read(),
    long_description_content_type="text/markdown",
    license="MIT License",
    author="Microsoft Corporation",
    author_email="azurekeyvault@microsoft.com",
    url="https://github.com/Azure/azure-sdk-for-python/tree/master/sdk/keyvault",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Programming Language :: Python",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "License :: OSI Approved :: MIT License",
    ],
    zip_safe=False,
    packages=PACKAGES,
    install_requires=["azure-nspkg>=3.0.0"],
)
