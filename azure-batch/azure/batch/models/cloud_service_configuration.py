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

    All required parameters must be populated in order to send to Azure.

    :param os_family: Required. The Azure Guest OS family to be installed on
     the virtual machines in the pool. Possible values are:
     2 - OS Family 2, equivalent to Windows Server 2008 R2 SP1.
     3 - OS Family 3, equivalent to Windows Server 2012.
     4 - OS Family 4, equivalent to Windows Server 2012 R2.
     5 - OS Family 5, equivalent to Windows Server 2016. For more information,
     see Azure Guest OS Releases
     (https://azure.microsoft.com/documentation/articles/cloud-services-guestos-update-matrix/#releases).
    :type os_family: str
    :param os_version: The Azure Guest OS version to be installed on the
     virtual machines in the pool. The default value is * which specifies the
     latest operating system version for the specified OS family.
    :type os_version: str
    """

    _validation = {
        'os_family': {'required': True},
    }

    _attribute_map = {
        'os_family': {'key': 'osFamily', 'type': 'str'},
        'os_version': {'key': 'osVersion', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(CloudServiceConfiguration, self).__init__(**kwargs)
        self.os_family = kwargs.get('os_family', None)
        self.os_version = kwargs.get('os_version', None)
