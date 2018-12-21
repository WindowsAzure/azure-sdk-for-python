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


class EventSubscriptionFilter(Model):
    """Filter for the Event Subscription.

    :param subject_begins_with: An optional string to filter events for an
     event subscription based on a resource path prefix.
     The format of this depends on the publisher of the events.
     Wildcard characters are not supported in this path.
    :type subject_begins_with: str
    :param subject_ends_with: An optional string to filter events for an event
     subscription based on a resource path suffix.
     Wildcard characters are not supported in this path.
    :type subject_ends_with: str
    :param included_event_types: A list of applicable event types that need to
     be part of the event subscription.
     If it is desired to subscribe to all event types, the string "all" needs
     to be specified as an element in this list.
    :type included_event_types: list[str]
    :param is_subject_case_sensitive: Specifies if the SubjectBeginsWith and
     SubjectEndsWith properties of the filter
     should be compared in a case sensitive manner. Default value: False .
    :type is_subject_case_sensitive: bool
    :param advanced_filters: A list of advanced filters.
    :type advanced_filters: list[~azure.mgmt.eventgrid.models.AdvancedFilter]
    """

    _attribute_map = {
        'subject_begins_with': {'key': 'subjectBeginsWith', 'type': 'str'},
        'subject_ends_with': {'key': 'subjectEndsWith', 'type': 'str'},
        'included_event_types': {'key': 'includedEventTypes', 'type': '[str]'},
        'is_subject_case_sensitive': {'key': 'isSubjectCaseSensitive', 'type': 'bool'},
        'advanced_filters': {'key': 'advancedFilters', 'type': '[AdvancedFilter]'},
    }

    def __init__(self, *, subject_begins_with: str=None, subject_ends_with: str=None, included_event_types=None, is_subject_case_sensitive: bool=False, advanced_filters=None, **kwargs) -> None:
        super(EventSubscriptionFilter, self).__init__(**kwargs)
        self.subject_begins_with = subject_begins_with
        self.subject_ends_with = subject_ends_with
        self.included_event_types = included_event_types
        self.is_subject_case_sensitive = is_subject_case_sensitive
        self.advanced_filters = advanced_filters
