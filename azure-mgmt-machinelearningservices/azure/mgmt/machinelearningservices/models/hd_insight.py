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

from .compute import Compute


class HDInsight(Compute):
    """A HDInsight compute.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :param compute_location: Location for the underlying compute
    :type compute_location: str
    :ivar provisioning_state: The provision state of the cluster. Valid values
     are Unknown, Updating, Provisioning, Succeeded, and Failed. Possible
     values include: 'Unknown', 'Updating', 'Creating', 'Deleting',
     'Succeeded', 'Failed', 'Canceled'
    :vartype provisioning_state: str or
     ~azure.mgmt.machinelearningservices.models.ProvisioningState
    :param description: The description of the Machine Learning compute.
    :type description: str
    :ivar created_on: The date and time when the compute was created.
    :vartype created_on: datetime
    :ivar modified_on: The date and time when the compute was last modified.
    :vartype modified_on: datetime
    :param resource_id: ARM resource id of the compute
    :type resource_id: str
    :ivar provisioning_errors: Errors during provisioning
    :vartype provisioning_errors:
     list[~azure.mgmt.machinelearningservices.models.MachineLearningServiceError]
    :param compute_type: Required. Constant filled by server.
    :type compute_type: str
    :param properties:
    :type properties:
     ~azure.mgmt.machinelearningservices.models.HDInsightProperties
    """

    _validation = {
        'provisioning_state': {'readonly': True},
        'created_on': {'readonly': True},
        'modified_on': {'readonly': True},
        'provisioning_errors': {'readonly': True},
        'compute_type': {'required': True},
    }

    _attribute_map = {
        'compute_location': {'key': 'computeLocation', 'type': 'str'},
        'provisioning_state': {'key': 'provisioningState', 'type': 'str'},
        'description': {'key': 'description', 'type': 'str'},
        'created_on': {'key': 'createdOn', 'type': 'iso-8601'},
        'modified_on': {'key': 'modifiedOn', 'type': 'iso-8601'},
        'resource_id': {'key': 'resourceId', 'type': 'str'},
        'provisioning_errors': {'key': 'provisioningErrors', 'type': '[MachineLearningServiceError]'},
        'compute_type': {'key': 'computeType', 'type': 'str'},
        'properties': {'key': 'properties', 'type': 'HDInsightProperties'},
    }

    def __init__(self, **kwargs):
        super(HDInsight, self).__init__(**kwargs)
        self.properties = kwargs.get('properties', None)
        self.compute_type = 'HDInsight'
