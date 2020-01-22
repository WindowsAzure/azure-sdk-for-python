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

from msrest.paging import Paged


class OperationPaged(Paged):
    """
    A paging container for iterating over a list of :class:`Operation <azure.mgmt.iothub.models.Operation>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[Operation]'}
    }

    def __init__(self, *args, **kwargs):

        super(OperationPaged, self).__init__(*args, **kwargs)
class IotHubDescriptionPaged(Paged):
    """
    A paging container for iterating over a list of :class:`IotHubDescription <azure.mgmt.iothub.models.IotHubDescription>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[IotHubDescription]'}
    }

    def __init__(self, *args, **kwargs):

        super(IotHubDescriptionPaged, self).__init__(*args, **kwargs)
class IotHubSkuDescriptionPaged(Paged):
    """
    A paging container for iterating over a list of :class:`IotHubSkuDescription <azure.mgmt.iothub.models.IotHubSkuDescription>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[IotHubSkuDescription]'}
    }

    def __init__(self, *args, **kwargs):

        super(IotHubSkuDescriptionPaged, self).__init__(*args, **kwargs)
class EventHubConsumerGroupInfoPaged(Paged):
    """
    A paging container for iterating over a list of :class:`EventHubConsumerGroupInfo <azure.mgmt.iothub.models.EventHubConsumerGroupInfo>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[EventHubConsumerGroupInfo]'}
    }

    def __init__(self, *args, **kwargs):

        super(EventHubConsumerGroupInfoPaged, self).__init__(*args, **kwargs)
class JobResponsePaged(Paged):
    """
    A paging container for iterating over a list of :class:`JobResponse <azure.mgmt.iothub.models.JobResponse>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[JobResponse]'}
    }

    def __init__(self, *args, **kwargs):

        super(JobResponsePaged, self).__init__(*args, **kwargs)
class IotHubQuotaMetricInfoPaged(Paged):
    """
    A paging container for iterating over a list of :class:`IotHubQuotaMetricInfo <azure.mgmt.iothub.models.IotHubQuotaMetricInfo>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[IotHubQuotaMetricInfo]'}
    }

    def __init__(self, *args, **kwargs):

        super(IotHubQuotaMetricInfoPaged, self).__init__(*args, **kwargs)
class SharedAccessSignatureAuthorizationRulePaged(Paged):
    """
    A paging container for iterating over a list of :class:`SharedAccessSignatureAuthorizationRule <azure.mgmt.iothub.models.SharedAccessSignatureAuthorizationRule>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[SharedAccessSignatureAuthorizationRule]'}
    }

    def __init__(self, *args, **kwargs):

        super(SharedAccessSignatureAuthorizationRulePaged, self).__init__(*args, **kwargs)
