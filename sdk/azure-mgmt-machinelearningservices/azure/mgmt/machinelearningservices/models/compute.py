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


class Compute(Model):
    """Machine Learning compute object.

    You probably want to use the sub-classes and not this class directly. Known
    sub-classes are: AKS, AmlCompute, VirtualMachine, HDInsight, DataFactory,
    Databricks, DataLakeAnalytics

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
    :param resource_id: ARM resource id of the underlying compute
    :type resource_id: str
    :ivar provisioning_errors: Errors during provisioning
    :vartype provisioning_errors:
     list[~azure.mgmt.machinelearningservices.models.MachineLearningServiceError]
    :ivar is_attached_compute: Indicating whether the compute was provisioned
     by user and brought from outside if true, or machine learning service
     provisioned it if false.
    :vartype is_attached_compute: bool
    :param compute_type: Required. Constant filled by server.
    :type compute_type: str
    """

    _validation = {
        'provisioning_state': {'readonly': True},
        'created_on': {'readonly': True},
        'modified_on': {'readonly': True},
        'provisioning_errors': {'readonly': True},
        'is_attached_compute': {'readonly': True},
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
        'is_attached_compute': {'key': 'isAttachedCompute', 'type': 'bool'},
        'compute_type': {'key': 'computeType', 'type': 'str'},
    }

    _subtype_map = {
        'compute_type': {'AKS': 'AKS', 'AmlCompute': 'AmlCompute', 'VirtualMachine': 'VirtualMachine', 'HDInsight': 'HDInsight', 'DataFactory': 'DataFactory', 'Databricks': 'Databricks', 'DataLakeAnalytics': 'DataLakeAnalytics'}
    }

    def __init__(self, **kwargs):
        super(Compute, self).__init__(**kwargs)
        self.compute_location = kwargs.get('compute_location', None)
        self.provisioning_state = None
        self.description = kwargs.get('description', None)
        self.created_on = None
        self.modified_on = None
        self.resource_id = kwargs.get('resource_id', None)
        self.provisioning_errors = None
        self.is_attached_compute = None
        self.compute_type = None
