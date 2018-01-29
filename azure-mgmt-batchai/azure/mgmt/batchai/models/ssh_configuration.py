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


class SshConfiguration(Model):
    """SSH configuration settings for the VM.

    :param public_ips_to_allow: List of source IP ranges to allow SSH
     connection to VM. Default value is '*' can be used to match all source
     IPs. Maximum number of publicIPs that can be specified are 400.
    :type public_ips_to_allow: list[str]
    :param user_account_settings: Settings for user account of VMs.
    :type user_account_settings:
     ~azure.mgmt.batchai.models.UserAccountSettings
    """

    _validation = {
        'user_account_settings': {'required': True},
    }

    _attribute_map = {
        'public_ips_to_allow': {'key': 'publicIPsToAllow', 'type': '[str]'},
        'user_account_settings': {'key': 'userAccountSettings', 'type': 'UserAccountSettings'},
    }

    def __init__(self, user_account_settings, public_ips_to_allow=None):
        super(SshConfiguration, self).__init__()
        self.public_ips_to_allow = public_ips_to_allow
        self.user_account_settings = user_account_settings
