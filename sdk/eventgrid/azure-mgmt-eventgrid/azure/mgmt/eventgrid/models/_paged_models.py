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


class DomainPaged(Paged):
    """
    A paging container for iterating over a list of :class:`Domain <azure.mgmt.eventgrid.models.Domain>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[Domain]'}
    }

    def __init__(self, *args, **kwargs):

        super(DomainPaged, self).__init__(*args, **kwargs)
class DomainTopicPaged(Paged):
    """
    A paging container for iterating over a list of :class:`DomainTopic <azure.mgmt.eventgrid.models.DomainTopic>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[DomainTopic]'}
    }

    def __init__(self, *args, **kwargs):

        super(DomainTopicPaged, self).__init__(*args, **kwargs)
class EventChannelPaged(Paged):
    """
    A paging container for iterating over a list of :class:`EventChannel <azure.mgmt.eventgrid.models.EventChannel>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[EventChannel]'}
    }

    def __init__(self, *args, **kwargs):

        super(EventChannelPaged, self).__init__(*args, **kwargs)
class EventSubscriptionPaged(Paged):
    """
    A paging container for iterating over a list of :class:`EventSubscription <azure.mgmt.eventgrid.models.EventSubscription>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[EventSubscription]'}
    }

    def __init__(self, *args, **kwargs):

        super(EventSubscriptionPaged, self).__init__(*args, **kwargs)
class OperationPaged(Paged):
    """
    A paging container for iterating over a list of :class:`Operation <azure.mgmt.eventgrid.models.Operation>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[Operation]'}
    }

    def __init__(self, *args, **kwargs):

        super(OperationPaged, self).__init__(*args, **kwargs)
class PartnerNamespacePaged(Paged):
    """
    A paging container for iterating over a list of :class:`PartnerNamespace <azure.mgmt.eventgrid.models.PartnerNamespace>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[PartnerNamespace]'}
    }

    def __init__(self, *args, **kwargs):

        super(PartnerNamespacePaged, self).__init__(*args, **kwargs)
class PartnerRegistrationPaged(Paged):
    """
    A paging container for iterating over a list of :class:`PartnerRegistration <azure.mgmt.eventgrid.models.PartnerRegistration>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[PartnerRegistration]'}
    }

    def __init__(self, *args, **kwargs):

        super(PartnerRegistrationPaged, self).__init__(*args, **kwargs)
class PartnerTopicPaged(Paged):
    """
    A paging container for iterating over a list of :class:`PartnerTopic <azure.mgmt.eventgrid.models.PartnerTopic>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[PartnerTopic]'}
    }

    def __init__(self, *args, **kwargs):

        super(PartnerTopicPaged, self).__init__(*args, **kwargs)
class PrivateEndpointConnectionPaged(Paged):
    """
    A paging container for iterating over a list of :class:`PrivateEndpointConnection <azure.mgmt.eventgrid.models.PrivateEndpointConnection>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[PrivateEndpointConnection]'}
    }

    def __init__(self, *args, **kwargs):

        super(PrivateEndpointConnectionPaged, self).__init__(*args, **kwargs)
class PrivateLinkResourcePaged(Paged):
    """
    A paging container for iterating over a list of :class:`PrivateLinkResource <azure.mgmt.eventgrid.models.PrivateLinkResource>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[PrivateLinkResource]'}
    }

    def __init__(self, *args, **kwargs):

        super(PrivateLinkResourcePaged, self).__init__(*args, **kwargs)
class SystemTopicPaged(Paged):
    """
    A paging container for iterating over a list of :class:`SystemTopic <azure.mgmt.eventgrid.models.SystemTopic>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[SystemTopic]'}
    }

    def __init__(self, *args, **kwargs):

        super(SystemTopicPaged, self).__init__(*args, **kwargs)
class TopicPaged(Paged):
    """
    A paging container for iterating over a list of :class:`Topic <azure.mgmt.eventgrid.models.Topic>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[Topic]'}
    }

    def __init__(self, *args, **kwargs):

        super(TopicPaged, self).__init__(*args, **kwargs)
class EventTypePaged(Paged):
    """
    A paging container for iterating over a list of :class:`EventType <azure.mgmt.eventgrid.models.EventType>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[EventType]'}
    }

    def __init__(self, *args, **kwargs):

        super(EventTypePaged, self).__init__(*args, **kwargs)
class TopicTypeInfoPaged(Paged):
    """
    A paging container for iterating over a list of :class:`TopicTypeInfo <azure.mgmt.eventgrid.models.TopicTypeInfo>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[TopicTypeInfo]'}
    }

    def __init__(self, *args, **kwargs):

        super(TopicTypeInfoPaged, self).__init__(*args, **kwargs)
