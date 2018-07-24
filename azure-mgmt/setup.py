#!/usr/bin/env python

#-------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
#--------------------------------------------------------------------------

from setuptools import setup

setup(
    name='azure-mgmt',
    version='4.0.0',
    description='Microsoft Azure Resource Management Client Libraries for Python',
    long_description=open('README.rst', 'r').read(),
    license='MIT License',
    author='Microsoft Corporation',
    author_email='azpysdkhelp@microsoft.com',
    url='https://github.com/Azure/azure-sdk-for-python',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'License :: OSI Approved :: MIT License',
    ],
    zip_safe=False,
    install_requires=[
        'azure-mgmt-advisor~=1.0',
        'azure-mgmt-applicationinsights~=0.1.1',
        'azure-mgmt-authorization~=0.30.0',
        'azure-mgmt-batch~=5.0',
        'azure-mgmt-batchai~=0.2.0',
        'azure-mgmt-billing~=0.1.0',
        'azure-mgmt-cdn~=2.0',
        'azure-mgmt-cognitiveservices~=2.0',
        'azure-mgmt-commerce~=1.0',
        'azure-mgmt-compute~=3.0',
        'azure-mgmt-consumption~=2.0',
        'azure-mgmt-containerinstance~=0.3.1',
        'azure-mgmt-containerregistry~=1.0',
        'azure-mgmt-containerservice~=3.0',
        'azure-mgmt-cosmosdb~=0.3.1',
        'azure-mgmt-datafactory~=0.4.0',
        'azure-mgmt-datalake-analytics~=0.3.0',
        'azure-mgmt-datalake-store~=0.3.0',
        'azure-mgmt-devtestlabs~=2.1',
        'azure-mgmt-dns~=1.2',
        'azure-mgmt-eventgrid~=0.4.0',
        'azure-mgmt-eventhub~=1.2',
        'azure-mgmt-hanaonazure~=0.1.0',
        'azure-mgmt-iothub~=0.4.0',
        'azure-mgmt-iothubprovisioningservices~=0.1.0',
        'azure-mgmt-keyvault~=0.40.0',
        'azure-mgmt-loganalytics~=0.1.0',
        'azure-mgmt-logic~=2.1',
        'azure-mgmt-machinelearningcompute~=0.4.0',
        'azure-mgmt-managementpartner~=0.1.0',
        'azure-mgmt-marketplaceordering~=0.1.0',
        'azure-mgmt-media~=0.2.0',
        'azure-mgmt-monitor~=0.4.0',
        'azure-mgmt-msi~=0.1.0',
        'azure-mgmt-network~=1.7',
        'azure-mgmt-notificationhubs~=1.0',
        'azure-mgmt-powerbiembedded~=1.0',
        'azure-mgmt-rdbms~=0.1.0',
        'azure-mgmt-recoveryservices~=0.2.0',
        'azure-mgmt-recoveryservicesbackup~=0.1.1',
        'azure-mgmt-redis~=5.0',
        'azure-mgmt-relay~=0.1.0',
        'azure-mgmt-reservations~=0.1.0',
        'azure-mgmt-resource~=1.2',
        'azure-mgmt-scheduler~=1.1',
        'azure-mgmt-search~=1.0',
        'azure-mgmt-servermanager~=1.2',
        'azure-mgmt-servicebus~=0.4.0',
        'azure-mgmt-servicefabric~=0.1.0',
        'azure-mgmt-sql~=0.8.5',
        'azure-mgmt-storage~=1.5',
        'azure-mgmt-subscription~=0.1.0',
        'azure-mgmt-trafficmanager~=0.40.0',
        'azure-mgmt-web~=0.34.1',
    ],
)
