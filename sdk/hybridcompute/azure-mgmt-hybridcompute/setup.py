# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
#
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------
# coding: utf-8

from setuptools import setup, find_packages

NAME = "azure-mgmt-hybridcompute"
VERSION = "2019-08-02-preview"

# To install the library, run the following
#
# python setup.py install
#
# prerequisite: setuptools
# http://pypi.python.org/pypi/setuptools

REQUIRES = ["msrestazure>=0.4.32"]

setup(
    name=NAME,
    version=VERSION,
    description="HybridComputeManagementClient",
    author_email="",
    url="",
    keywords=["Swagger", "HybridComputeManagementClient"],
    install_requires=REQUIRES,
    packages=find_packages(),
    include_package_data=True,
    long_description="""\
    The Hybrid Compute Management Client.
    """
)
