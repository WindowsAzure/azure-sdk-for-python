#!/usr/bin/env python

# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

from __future__ import print_function

import sys
import glob
import os
import argparse
from collections import Counter
from subprocess import check_call, CalledProcessError

root_dir = os.path.abspath(os.path.join(os.path.abspath(__file__), '..', '..'))

def pip_command(command, error_ok=False):
    try:
        print('Executing: ' + command)
        check_call([sys.executable, '-m', 'pip'] + command.split(), cwd=root_dir)
        print()
    except CalledProcessError as err:
        print(err, file=sys.stderr)
        if not error_ok:
            sys.exit(1)

def expand_dependencies(targeted_packages):
    expanded_package_list = targeted_packages[:]
    for package_name in targeted_packages: 
        if os.path.isfile('{}/dev_requirements.txt'.format(package_name)):
            expanded_package_list.extend([line.rstrip('\n') for line in open('{}/dev_requirements.txt'.format(package_name))])
            expanded_package_list = list(set(expanded_package_list))

    # if our set of packages has expanded, recurse, otherwise we are guaranteed to be done. 
    # worst case in this situation is that we include all azure* packages anyway.
    if Counter(targeted_packages) != Counter(expanded_package_list):
        return expand_dependencies(expanded_package_list)
    else: 
        return expanded_package_list

# optional argument in a situation where we want to build a single package
parser = argparse.ArgumentParser(description='Set up the dev environment for selected packages.')
parser.add_argument('--globArg', '-g', dest='globArg', default='azure*', help='Defaulted to "azure*", used to limit the number of packages that dependencies will be installed for. ')
args = parser.parse_args()

packages = [os.path.dirname(p) for p in glob.glob('azure*/setup.py')]

# keep targeted packages separate. python2 needs the nspkgs to work properly.
targeted_packages = expand_dependencies([os.path.dirname(p) for p in glob.glob('{0}/setup.py'.format(args.globArg))])

# Extract nspkg and sort nspkg by number of "-"
nspkg_packages = [p for p in packages if 'nspkg' in p]
nspkg_packages.sort(key = lambda x: len([c for c in x if c == '-']))

# Manually push meta-packages at the end, in reverse dependency order
meta_packages = ['azure-mgmt', 'azure']

content_packages = [p for p in packages if p not in nspkg_packages+meta_packages and p in targeted_packages]

# Put azure-common in front
if 'azure-common' in content_packages:
    content_packages.remove('azure-common')
content_packages.insert(0, 'azure-common')

print('Running dev setup...')
print('Root directory \'{}\'\n'.format(root_dir))

# install private whls if there are any
privates_dir = os.path.join(root_dir, 'privates')
if os.path.isdir(privates_dir) and os.listdir(privates_dir):
    whl_list = ' '.join([os.path.join(privates_dir, f) for f in os.listdir(privates_dir)])
    pip_command('install {}'.format(whl_list))

# install nspkg only on py2, but in wheel mode (not editable mode)
if sys.version_info < (3, ):
    for package_name in nspkg_packages:
        pip_command('install ./{}/'.format(package_name))

# install packages
for package_name in content_packages:
    pip_command('install --ignore-requires-python -e {}'.format(package_name))

# On Python 3, uninstall azure-nspkg if he got installed
if sys.version_info >= (3, ):
    pip_command('uninstall -y azure-nspkg', error_ok=True)


print('Finished dev setup.')
