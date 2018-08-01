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
        'azure-mgmt-authorization~=0.50.0',
        'azure-mgmt-batch~=5.0',
        'azure-mgmt-batchai~=2.0',
        'azure-mgmt-billing~=0.2.0',
        'azure-mgmt-cdn~=3.0',
        'azure-mgmt-cognitiveservices~=3.0',
        'azure-mgmt-commerce~=1.0',
        'azure-mgmt-compute~=4.0',
        'azure-mgmt-consumption~=2.0',
        'azure-mgmt-containerinstance~=1.0',
        'azure-mgmt-containerregistry~=2.1',
        'azure-mgmt-containerservice~=4.2',
        'azure-mgmt-cosmosdb~=0.4.1',
        'azure-mgmt-datafactory~=0.6.0',
        'azure-mgmt-datalake-analytics~=0.6.0',
        'azure-mgmt-datalake-store~=0.5.0',
        'azure-mgmt-datamigration~=1.0',
        'azure-mgmt-devspaces~=0.1.0',
        'azure-mgmt-devtestlabs~=2.2',
        'azure-mgmt-dns~=1.2',
        'azure-mgmt-eventgrid~=1.0',
        'azure-mgmt-eventhub~=2.1',
        'azure-mgmt-hanaonazure~=0.1.1',
        'azure-mgmt-iotcentral~=0.1.0',
        'azure-mgmt-iothub~=0.5.0',
        'azure-mgmt-iothubprovisioningservices~=0.2.0',
        'azure-mgmt-keyvault~=1.0',
        'azure-mgmt-loganalytics~=0.2.0',
        'azure-mgmt-logic~=3.0',
        'azure-mgmt-machinelearningcompute~=0.4.1',
        'azure-mgmt-managementgroups~=0.1.0',
        'azure-mgmt-managementpartner~=0.1.0',
        'azure-mgmt-maps~=0.1.0',
        'azure-mgmt-marketplaceordering~=0.1.0',
        'azure-mgmt-media~=0.2.0',
        'azure-mgmt-monitor~=0.5.2',
        'azure-mgmt-msi~=0.2.0',
        'azure-mgmt-network~=2.0',
        'azure-mgmt-notificationhubs~=2.0',
        'azure-mgmt-policyinsights~=0.1.0',
        'azure-mgmt-powerbiembedded~=2.0',
        'azure-mgmt-rdbms~=1.2',
        'azure-mgmt-recoveryservices~=0.3.0',
        'azure-mgmt-recoveryservicesbackup~=0.3.0',
        'azure-mgmt-redis~=5.0',
        'azure-mgmt-relay~=0.1.0',
        'azure-mgmt-reservations~=0.2.1',
        'azure-mgmt-resource~=2.0',
        'azure-mgmt-scheduler~=2.0',
        'azure-mgmt-search~=2.0',
        'azure-mgmt-servicebus~=0.5.1',
        'azure-mgmt-servicefabric~=0.1.0',
        'azure-mgmt-signalr~=0.1.0',
        'azure-mgmt-sql~=0.9.1',
        'azure-mgmt-storage~=2.0',
        'azure-mgmt-subscription~=0.2.0',
        'azure-mgmt-trafficmanager~=0.50.0',
        'azure-mgmt-web~=0.35.0',
    ],
)
