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


class ResourceManagementErrorWithDetails(Model):
    """ResourceManagementErrorWithDetails.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar code: The error code returned when exporting the template.
    :vartype code: str
    :ivar message: The error message describing the export error.
    :vartype message: str
    :ivar target: The target of the error.
    :vartype target: str
    :ivar details: Validation error.
    :vartype details:
     list[~azure.mgmt.resource.resources.v2016_09_01.models.ResourceManagementErrorWithDetails]
    """

    _validation = {
        'code': {'readonly': True},
        'message': {'readonly': True},
        'target': {'readonly': True},
        'details': {'readonly': True},
    }

    _attribute_map = {
        'code': {'key': 'code', 'type': 'str'},
        'message': {'key': 'message', 'type': 'str'},
        'target': {'key': 'target', 'type': 'str'},
        'details': {'key': 'details', 'type': '[ResourceManagementErrorWithDetails]'},
    }

    def __init__(self, **kwargs):
        super(ResourceManagementErrorWithDetails, self).__init__(**kwargs)
        self.code = None
        self.message = None
        self.target = None
        self.details = None
