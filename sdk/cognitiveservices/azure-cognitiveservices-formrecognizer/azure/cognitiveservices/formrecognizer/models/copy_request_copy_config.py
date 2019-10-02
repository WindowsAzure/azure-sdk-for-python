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


class CopyRequestCopyConfig(Model):
    """Copy operation options.

    All required parameters must be populated in order to send to Azure.

    :param delete_source: Required. Indicate deletion of source model
     artifacts. Default value: False .
    :type delete_source: bool
    :param support_cross_tenant_copy: Indicate copy target tenancy
     requirement. Default value: False .
    :type support_cross_tenant_copy: bool
    :param target_model_metadata: Metadata for copied model to Target
    :type target_model_metadata:
     ~azure.cognitiveservices.formrecognizer.models.CopyRequestCopyConfigTargetModelMetadata
    """

    _validation = {
        'delete_source': {'required': True},
    }

    _attribute_map = {
        'delete_source': {'key': 'deleteSource', 'type': 'bool'},
        'support_cross_tenant_copy': {'key': 'supportCrossTenantCopy', 'type': 'bool'},
        'target_model_metadata': {'key': 'targetModelMetadata', 'type': 'CopyRequestCopyConfigTargetModelMetadata'},
    }

    def __init__(self, **kwargs):
        super(CopyRequestCopyConfig, self).__init__(**kwargs)
        self.delete_source = kwargs.get('delete_source', False)
        self.support_cross_tenant_copy = kwargs.get('support_cross_tenant_copy', False)
        self.target_model_metadata = kwargs.get('target_model_metadata', None)
