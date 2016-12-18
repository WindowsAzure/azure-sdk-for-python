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

    :param os_family: The Azure Guest OS family to be installed on the virtual
     machines in the pool. Possible values are: 2 – OS Family 2, equivalent to
     Windows Server 2008 R2 SP1. 3 – OS Family 3, equivalent to Windows Server
     2012. 4 – OS Family 4, equivalent to Windows Server 2012 R2. For more
     information, see Azure Guest OS Releases
     (https://azure.microsoft.com/documentation/articles/cloud-services-guestos-update-matrix/#releases).
    :type os_family: str
    :param target_os_version: The Azure Guest OS version to be installed on
     the virtual machines in the pool. The default value is * which specifies
     the latest operating system version for the specified OS family.
    :type target_os_version: str
    :param current_os_version: The Azure Guest OS Version currently installed
     on the virtual machines in the pool. This may differ from targetOSVersion
     if the pool state is Upgrading. In this case some virtual machines may be
     on the targetOSVersion and some may be on the currentOSVersion during the
     upgrade process. Once all virtual machines have upgraded, currentOSVersion
     is updated to be the same as targetOSVersion.
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
