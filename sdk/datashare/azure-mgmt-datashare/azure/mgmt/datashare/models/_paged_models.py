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


class AccountPaged(Paged):
    """
    A paging container for iterating over a list of :class:`Account <azure.mgmt.datashare.models.Account>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[Account]'}
    }

    def __init__(self, *args, **kwargs):

        super(AccountPaged, self).__init__(*args, **kwargs)
class ConsumerInvitationPaged(Paged):
    """
    A paging container for iterating over a list of :class:`ConsumerInvitation <azure.mgmt.datashare.models.ConsumerInvitation>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[ConsumerInvitation]'}
    }

    def __init__(self, *args, **kwargs):

        super(ConsumerInvitationPaged, self).__init__(*args, **kwargs)
class DataSetPaged(Paged):
    """
    A paging container for iterating over a list of :class:`DataSet <azure.mgmt.datashare.models.DataSet>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[DataSet]'}
    }

    def __init__(self, *args, **kwargs):

        super(DataSetPaged, self).__init__(*args, **kwargs)
class DataSetMappingPaged(Paged):
    """
    A paging container for iterating over a list of :class:`DataSetMapping <azure.mgmt.datashare.models.DataSetMapping>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[DataSetMapping]'}
    }

    def __init__(self, *args, **kwargs):

        super(DataSetMappingPaged, self).__init__(*args, **kwargs)
class InvitationPaged(Paged):
    """
    A paging container for iterating over a list of :class:`Invitation <azure.mgmt.datashare.models.Invitation>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[Invitation]'}
    }

    def __init__(self, *args, **kwargs):

        super(InvitationPaged, self).__init__(*args, **kwargs)
class OperationModelPaged(Paged):
    """
    A paging container for iterating over a list of :class:`OperationModel <azure.mgmt.datashare.models.OperationModel>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[OperationModel]'}
    }

    def __init__(self, *args, **kwargs):

        super(OperationModelPaged, self).__init__(*args, **kwargs)
class SharePaged(Paged):
    """
    A paging container for iterating over a list of :class:`Share <azure.mgmt.datashare.models.Share>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[Share]'}
    }

    def __init__(self, *args, **kwargs):

        super(SharePaged, self).__init__(*args, **kwargs)
class ShareSynchronizationPaged(Paged):
    """
    A paging container for iterating over a list of :class:`ShareSynchronization <azure.mgmt.datashare.models.ShareSynchronization>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[ShareSynchronization]'}
    }

    def __init__(self, *args, **kwargs):

        super(ShareSynchronizationPaged, self).__init__(*args, **kwargs)
class SynchronizationDetailsPaged(Paged):
    """
    A paging container for iterating over a list of :class:`SynchronizationDetails <azure.mgmt.datashare.models.SynchronizationDetails>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[SynchronizationDetails]'}
    }

    def __init__(self, *args, **kwargs):

        super(SynchronizationDetailsPaged, self).__init__(*args, **kwargs)
class ProviderShareSubscriptionPaged(Paged):
    """
    A paging container for iterating over a list of :class:`ProviderShareSubscription <azure.mgmt.datashare.models.ProviderShareSubscription>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[ProviderShareSubscription]'}
    }

    def __init__(self, *args, **kwargs):

        super(ProviderShareSubscriptionPaged, self).__init__(*args, **kwargs)
class SourceShareSynchronizationSettingPaged(Paged):
    """
    A paging container for iterating over a list of :class:`SourceShareSynchronizationSetting <azure.mgmt.datashare.models.SourceShareSynchronizationSetting>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[SourceShareSynchronizationSetting]'}
    }

    def __init__(self, *args, **kwargs):

        super(SourceShareSynchronizationSettingPaged, self).__init__(*args, **kwargs)
class ShareSubscriptionSynchronizationPaged(Paged):
    """
    A paging container for iterating over a list of :class:`ShareSubscriptionSynchronization <azure.mgmt.datashare.models.ShareSubscriptionSynchronization>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[ShareSubscriptionSynchronization]'}
    }

    def __init__(self, *args, **kwargs):

        super(ShareSubscriptionSynchronizationPaged, self).__init__(*args, **kwargs)
class ShareSubscriptionPaged(Paged):
    """
    A paging container for iterating over a list of :class:`ShareSubscription <azure.mgmt.datashare.models.ShareSubscription>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[ShareSubscription]'}
    }

    def __init__(self, *args, **kwargs):

        super(ShareSubscriptionPaged, self).__init__(*args, **kwargs)
class ConsumerSourceDataSetPaged(Paged):
    """
    A paging container for iterating over a list of :class:`ConsumerSourceDataSet <azure.mgmt.datashare.models.ConsumerSourceDataSet>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[ConsumerSourceDataSet]'}
    }

    def __init__(self, *args, **kwargs):

        super(ConsumerSourceDataSetPaged, self).__init__(*args, **kwargs)
class SynchronizationSettingPaged(Paged):
    """
    A paging container for iterating over a list of :class:`SynchronizationSetting <azure.mgmt.datashare.models.SynchronizationSetting>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[SynchronizationSetting]'}
    }

    def __init__(self, *args, **kwargs):

        super(SynchronizationSettingPaged, self).__init__(*args, **kwargs)
class TriggerPaged(Paged):
    """
    A paging container for iterating over a list of :class:`Trigger <azure.mgmt.datashare.models.Trigger>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[Trigger]'}
    }

    def __init__(self, *args, **kwargs):

        super(TriggerPaged, self).__init__(*args, **kwargs)
