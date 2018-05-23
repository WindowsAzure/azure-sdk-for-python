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


class ServiceBusAuthentication(Model):
    """ServiceBusAuthentication.

    :param sas_key: Gets or sets the SAS key.
    :type sas_key: str
    :param sas_key_name: Gets or sets the SAS key name.
    :type sas_key_name: str
    :param type: Gets or sets the authentication type. Possible values
     include: 'NotSpecified', 'SharedAccessKey'
    :type type: str or
     ~azure.mgmt.scheduler.models.ServiceBusAuthenticationType
    """

    _attribute_map = {
        'sas_key': {'key': 'sasKey', 'type': 'str'},
        'sas_key_name': {'key': 'sasKeyName', 'type': 'str'},
        'type': {'key': 'type', 'type': 'ServiceBusAuthenticationType'},
    }

    def __init__(self, *, sas_key: str=None, sas_key_name: str=None, type=None, **kwargs) -> None:
        super(ServiceBusAuthentication, self).__init__(**kwargs)
        self.sas_key = sas_key
        self.sas_key_name = sas_key_name
        self.type = type
