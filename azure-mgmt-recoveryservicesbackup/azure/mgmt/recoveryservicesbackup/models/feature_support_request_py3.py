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


class FeatureSupportRequest(Model):
    """Base class for feature request.

    You probably want to use the sub-classes and not this class directly. Known
    sub-classes are: AzureBackupGoalFeatureSupportRequest,
    AzureVMResourceFeatureSupportRequest

    All required parameters must be populated in order to send to Azure.

    :param feature_type: Required. Constant filled by server.
    :type feature_type: str
    """

    _validation = {
        'feature_type': {'required': True},
    }

    _attribute_map = {
        'feature_type': {'key': 'featureType', 'type': 'str'},
    }

    _subtype_map = {
        'feature_type': {'AzureBackupGoals': 'AzureBackupGoalFeatureSupportRequest', 'AzureVMResourceBackup': 'AzureVMResourceFeatureSupportRequest'}
    }

    def __init__(self, **kwargs) -> None:
        super(FeatureSupportRequest, self).__init__(**kwargs)
        self.feature_type = None
