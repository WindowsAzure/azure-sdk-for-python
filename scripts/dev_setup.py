#!/usr/bin/env python

# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

from __future__ import print_function

import sys
import glob
import os
from subprocess import check_call, CalledProcessError

root_dir = os.path.abspath(os.path.join(os.path.abspath(__file__), '..', '..'))


def pip_command(command):
    try:
        print('Executing: ' + command)
        check_call([sys.executable, '-m', 'pip'] + command.split(), cwd=root_dir)
        print()
    except CalledProcessError as err:
        print(err, file=sys.stderr)
        sys.exit(1)

packages = [os.path.dirname(p) for p in glob.glob('azure*/setup.py')]

# Extract nspkg and sort nspkg by number of "-"
nspkg_packages = [p for p in packages if "nspkg" in p]
nspkg_packages.sort(key = lambda x: len([c for c in x if c == '-']))

# Manually push meta-packages at the end, in reverse dependency order
meta_packages = ['azure-mgmt', 'azure']

content_packages = [p for p in packages if p not in nspkg_packages+meta_packages]
# Put azure-common in front
content_packages.remove("azure-common")
content_packages.insert(0, "azure-common")

print('Running dev setup...')
print('Root directory \'{}\'\n'.format(root_dir))

# install private whls if there are any
privates_dir = os.path.join(root_dir, 'privates')
if os.path.isdir(privates_dir) and os.listdir(privates_dir):
    whl_list = ' '.join([os.path.join(privates_dir, f) for f in os.listdir(privates_dir)])
    pip_command('install {}'.format(whl_list))

# install nspkg only on py2
if sys.version_info < (3, ):
    for package_name in nspkg_packages:
        pip_command('install -e {}'.format(package_name))
else:
    # We need the azure-nspkg, at least until storage is gone with the new system
    # Will be removed later
    pip_command('install --ignore-requires-python -e azure-nspkg')

# install packages
for package_name in content_packages:
    pip_command('install -e {}'.format(package_name))

print('Finished dev setup.')
