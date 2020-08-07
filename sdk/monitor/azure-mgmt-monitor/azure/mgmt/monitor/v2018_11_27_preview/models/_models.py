# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from azure.core.exceptions import HttpResponseError
import msrest.serialization


class DataContainer(msrest.serialization.Model):
    """Information about a container with data for a given resource.

    All required parameters must be populated in order to send to Azure.

    :param workspace: Required. Log Analytics workspace information.
    :type workspace: ~$(python-base-namespace).v2018_11_27_preview.models.WorkspaceInfo
    """

    _validation = {
        'workspace': {'required': True},
    }

    _attribute_map = {
        'workspace': {'key': 'workspace', 'type': 'WorkspaceInfo'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(DataContainer, self).__init__(**kwargs)
        self.workspace = kwargs['workspace']


class Error(msrest.serialization.Model):
    """Error details.

    All required parameters must be populated in order to send to Azure.

    :param code: Required. Error code identifying the specific error.
    :type code: str
    :param message: Error message in the caller's locale.
    :type message: str
    """

    _validation = {
        'code': {'required': True},
    }

    _attribute_map = {
        'code': {'key': 'code', 'type': 'str'},
        'message': {'key': 'message', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(Error, self).__init__(**kwargs)
        self.code = kwargs['code']
        self.message = kwargs.get('message', None)


class ProxyResource(msrest.serialization.Model):
    """An azure resource object.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar id: Azure resource Id.
    :vartype id: str
    :ivar name: Azure resource name.
    :vartype name: str
    :ivar type: Azure resource type.
    :vartype type: str
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(ProxyResource, self).__init__(**kwargs)
        self.id = None
        self.name = None
        self.type = None


class ResponseWithError(msrest.serialization.Model):
    """An error response from the API.

    All required parameters must be populated in order to send to Azure.

    :param error: Required. Error information.
    :type error: ~$(python-base-namespace).v2018_11_27_preview.models.Error
    """

    _validation = {
        'error': {'required': True},
    }

    _attribute_map = {
        'error': {'key': 'error', 'type': 'Error'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(ResponseWithError, self).__init__(**kwargs)
        self.error = kwargs['error']


class VMInsightsOnboardingStatus(ProxyResource):
    """VM Insights onboarding status for a resource.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar id: Azure resource Id.
    :vartype id: str
    :ivar name: Azure resource name.
    :vartype name: str
    :ivar type: Azure resource type.
    :vartype type: str
    :param resource_id: Azure Resource Manager identifier of the resource whose onboarding status
     is being represented.
    :type resource_id: str
    :param onboarding_status: The onboarding status for the resource. Note that, a higher level
     scope, e.g., resource group or subscription, is considered onboarded if at least one resource
     under it is onboarded. Possible values include: "onboarded", "notOnboarded", "unknown".
    :type onboarding_status: str or ~$(python-base-
     namespace).v2018_11_27_preview.models.OnboardingStatus
    :param data_status: The status of VM Insights data from the resource. When reported as
     ``present`` the data array will contain information about the data containers to which data for
     the specified resource is being routed. Possible values include: "present", "notPresent".
    :type data_status: str or ~$(python-base-namespace).v2018_11_27_preview.models.DataStatus
    :param data: Containers that currently store VM Insights data for the specified resource.
    :type data: list[~$(python-base-namespace).v2018_11_27_preview.models.DataContainer]
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
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

    def __init__(
        self,
        **kwargs
    ):
        super(VMInsightsOnboardingStatus, self).__init__(**kwargs)
        self.resource_id = kwargs.get('resource_id', None)
        self.onboarding_status = kwargs.get('onboarding_status', None)
        self.data_status = kwargs.get('data_status', None)
        self.data = kwargs.get('data', None)


class WorkspaceInfo(msrest.serialization.Model):
    """Information about a Log Analytics Workspace.

    All required parameters must be populated in order to send to Azure.

    :param id: Required. Azure Resource Manager identifier of the Log Analytics Workspace.
    :type id: str
    :param location: Required. Location of the Log Analytics workspace.
    :type location: str
    :param customer_id: Required. Log Analytics workspace identifier.
    :type customer_id: str
    """

    _validation = {
        'id': {'required': True},
        'location': {'required': True},
        'customer_id': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'customer_id': {'key': 'properties.customerId', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(WorkspaceInfo, self).__init__(**kwargs)
        self.id = kwargs['id']
        self.location = kwargs['location']
        self.customer_id = kwargs['customer_id']
