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


class P2SVpnProfileParameters(Model):
    """Vpn Client Parameters for package generation.

    :param authentication_method: VPN client Authentication Method. Possible
     values are: 'EAPTLS' and 'EAPMSCHAPv2'. Possible values include: 'EAPTLS',
     'EAPMSCHAPv2'
    :type authentication_method: str or
     ~azure.mgmt.network.v2018_10_01.models.AuthenticationMethod
    """

    _attribute_map = {
        'authentication_method': {'key': 'authenticationMethod', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(P2SVpnProfileParameters, self).__init__(**kwargs)
        self.authentication_method = kwargs.get('authentication_method', None)
