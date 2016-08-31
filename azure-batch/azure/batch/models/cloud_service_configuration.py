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

from msrest.serialization import Model


class CloudServiceConfiguration(Model):
    """The configuration for nodes in a pool based on the Azure Cloud Services
    platform.

    :param os_family: The Azure Guest OS family to be installed on the
     virtual machines in the pool.
    :type os_family: str
    :param target_os_version: The Azure Guest OS version to be installed on
     the virtual machines in the pool. The default value is * which specifies
     the latest operating system version for the specified OS family.
    :type target_os_version: str
    :param current_os_version: The Azure Guest OS Version currently installed
     on the virtual machines in the pool. This may differ from
     TargetOSVersion if the pool state is Upgrading.
    :type current_os_version: str
    """ 

    _validation = {
        'os_family': {'required': True},
    }

    _attribute_map = {
        'os_family': {'key': 'osFamily', 'type': 'str'},
        'target_os_version': {'key': 'targetOSVersion', 'type': 'str'},
        'current_os_version': {'key': 'currentOSVersion', 'type': 'str'},
    }

    def __init__(self, os_family, target_os_version=None, current_os_version=None):
        self.os_family = os_family
        self.target_os_version = target_os_version
        self.current_os_version = current_os_version
