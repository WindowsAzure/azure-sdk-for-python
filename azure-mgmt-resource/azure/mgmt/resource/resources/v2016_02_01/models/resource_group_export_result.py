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


class ResourceGroupExportResult(Model):
    """ResourceGroupExportResult.

    :param template: The template content.
    :type template: object
    :param error: The error.
    :type error:
     ~azure.mgmt.resource.resources.v2016_02_01.models.ResourceManagementErrorWithDetails
    """

    _attribute_map = {
        'template': {'key': 'template', 'type': 'object'},
        'error': {'key': 'error', 'type': 'ResourceManagementErrorWithDetails'},
    }

    def __init__(self, **kwargs):
        super(ResourceGroupExportResult, self).__init__(**kwargs)
        self.template = kwargs.get('template', None)
        self.error = kwargs.get('error', None)
