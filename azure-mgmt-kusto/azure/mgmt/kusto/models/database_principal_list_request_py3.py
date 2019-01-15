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


class DatabasePrincipalListRequest(Model):
    """The list Kusto database principals operation request.

    :param value: The list of Kusto database principals.
    :type value: list[~azure.mgmt.kusto.models.DatabasePrincipal]
    """

    _attribute_map = {
        'value': {'key': 'value', 'type': '[DatabasePrincipal]'},
    }

    def __init__(self, *, value=None, **kwargs) -> None:
        super(DatabasePrincipalListRequest, self).__init__(**kwargs)
        self.value = value
