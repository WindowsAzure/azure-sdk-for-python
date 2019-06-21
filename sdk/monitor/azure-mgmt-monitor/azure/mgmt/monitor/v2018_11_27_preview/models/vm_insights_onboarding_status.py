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

from .proxy_resource import ProxyResource


class VMInsightsOnboardingStatus(ProxyResource):
    """VM Insights onboarding status for a resource.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Azure resource Id
    :vartype id: str
    :ivar name: Azure resource name
    :vartype name: str
    :ivar type: Azure resource type
    :vartype type: str
    :param resource_id: Required. Azure Resource Manager identifier of the
     resource whose onboarding status is being represented.
    :type resource_id: str
    :param onboarding_status: Required. The onboarding status for the
     resource. Note that, a higher level scope, e.g., resource group or
     subscription, is considered onboarded if at least one resource under it is
     onboarded. Possible values include: 'onboarded', 'notOnboarded', 'unknown'
    :type onboarding_status: str or
     ~azure.mgmt.monitor.v2018_11_27_preview.models.OnboardingStatus
    :param data_status: Required. The status of VM Insights data from the
     resource. When reported as `present` the data array will contain
     information about the data containers to which data for the specified
     resource is being routed. Possible values include: 'present', 'notPresent'
    :type data_status: str or
     ~azure.mgmt.monitor.v2018_11_27_preview.models.DataStatus
    :param data: Containers that currently store VM Insights data for the
     specified resource.
    :type data:
     list[~azure.mgmt.monitor.v2018_11_27_preview.models.DataContainer]
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'resource_id': {'required': True},
        'onboarding_status': {'required': True},
        'data_status': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'resource_id': {'key': 'properties.resourceId', 'type': 'str'},
        'onboarding_status': {'key': 'properties.onboardingStatus', 'type': 'str'},
        'data_status': {'key': 'properties.dataStatus', 'type': 'str'},
        'data': {'key': 'properties.data', 'type': '[DataContainer]'},
    }

    def __init__(self, **kwargs):
        super(VMInsightsOnboardingStatus, self).__init__(**kwargs)
        self.resource_id = kwargs.get('resource_id', None)
        self.onboarding_status = kwargs.get('onboarding_status', None)
        self.data_status = kwargs.get('data_status', None)
        self.data = kwargs.get('data', None)
