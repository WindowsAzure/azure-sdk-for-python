#!/usr/bin/env python

# -------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# --------------------------------------------------------------------------


import os
import re

from setuptools import setup, find_packages


# Change the PACKAGE_NAME only to change folder and different name
PACKAGE_NAME = "azure-storage-file-datalake"
NAMESPACE_NAME = "azure.storage.filedatalake"
PACKAGE_PPRINT_NAME = "Azure File DataLake Storage"

# a-b-c => a/b/c
package_folder_path = NAMESPACE_NAME.replace('.', '/')


# azure v0.x is not compatible with this package
# azure v0.x used to have a __version__ attribute (newer versions don't)
try:
    import azure

    try:
        ver = azure.__version__
        raise Exception(
            'This package is incompatible with azure=={}. '.format(ver) +
            'Uninstall it with "pip uninstall azure".'
        )
    except AttributeError:
        pass
except ImportError:
    pass

# azure-storage v0.36.0 and prior are not compatible with this package
try:
    import azure.storage

    try:
        ver = azure.storage.__version__
        raise Exception(
            'This package is incompatible with azure-storage=={}. '.format(ver) +
            ' Uninstall it with "pip uninstall azure-storage".'
        )
    except AttributeError:
        pass
except ImportError:
    pass

# Version extraction inspired from 'requests'
with open(os.path.join(package_folder_path, '_version.py'), 'r') as fd:
    version = re.search(r'^VERSION\s*=\s*[\'"]([^\'"]*)[\'"]',
                        fd.read(), re.MULTILINE).group(1)

if not version:
    raise RuntimeError('Cannot find version information')

setup(
    name=PACKAGE_NAME,
    version=version,
    description='Microsoft {} Client Library for Python'.format(PACKAGE_PPRINT_NAME),
    long_description=open('README.md', 'r').read(),
    long_description_content_type='text/markdown',
    license='MIT License',
    author='Microsoft Corporation',
    author_email='ascl@microsoft.com',
    url='https://github.com/Azure/azure-sdk-for-python',
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'License :: OSI Approved :: MIT License',
    ],
    zip_safe=False,
    packages=find_packages(exclude=[
        # Exclude packages that will be covered by PEP420 or nspkg
        'azure',
        'azure.storage',
        'tests',
    ]),
    install_requires=[
        "azure-core<2.0.0,>=1.9.0",
        "msrest>=0.6.10",
        "azure-storage-blob<13.0.0,>=12.6.0"
    ],
    extras_require={
        ":python_version<'3.0'": ['futures', 'azure-storage-nspkg<4.0.0,>=3.0.0'],
        ":python_version<'3.4'": ['enum34>=1.0.4'],
        ":python_version<'3.5'": ["typing"]
    },
)
