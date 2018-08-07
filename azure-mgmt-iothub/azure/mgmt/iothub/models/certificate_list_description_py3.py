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


class CertificateListDescription(Model):
    """The JSON-serialized array of Certificate objects.

    :param value: The array of Certificate objects.
    :type value: list[~azure.mgmt.iothub.models.CertificateDescription]
    """

    _attribute_map = {
        'value': {'key': 'value', 'type': '[CertificateDescription]'},
    }

    def __init__(self, *, value=None, **kwargs) -> None:
        super(CertificateListDescription, self).__init__(**kwargs)
        self.value = value
