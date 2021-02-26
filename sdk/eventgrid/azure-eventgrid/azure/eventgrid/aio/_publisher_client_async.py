# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from typing import Any, Union, List, Dict, cast
from azure.core.credentials import AzureKeyCredential, AzureSasCredential
from azure.core.tracing.decorator_async import distributed_trace_async
from azure.core.pipeline.policies import (
    RequestIdPolicy,
    HeadersPolicy,
    AsyncRedirectPolicy,
    AsyncRetryPolicy,
    ContentDecodePolicy,
    CustomHookPolicy,
    NetworkTraceLoggingPolicy,
    ProxyPolicy,
    DistributedTracingPolicy,
    HttpLoggingPolicy,
    UserAgentPolicy
)
from .._policies import CloudEventDistributedTracingPolicy
from .._models import CloudEvent, EventGridEvent
from .._helpers import (
    _get_endpoint_only_fqdn,
    _get_authentication_policy,
    _is_cloud_event,
    _is_eventgrid_event,
    _eventgrid_data_typecheck
)
from .._generated.aio import EventGridPublisherClient as EventGridPublisherClientAsync
from .._generated.models import CloudEvent as InternalCloudEvent
from .._version import VERSION

SendType = Union[
    CloudEvent,
    EventGridEvent,
    Dict,
    List[CloudEvent],
    List[EventGridEvent],
    List[Dict]
]

ListEventType = Union[
    List[CloudEvent],
    List[EventGridEvent],
    List[Dict]
]

class EventGridPublisherClient():
    """Asynchronous EventGridPublisherClient publishes events to an EventGrid topic or domain.
    It can be used to publish either an EventGridEvent, a CloudEvent or a Custom Schema.

    :param str endpoint: The topic endpoint to send the events to.
    :param credential: The credential object used for authentication which implements
     SAS key authentication or SAS token authentication.
    :type credential: ~azure.core.credentials.AzureKeyCredential or ~azure.core.credentials.AzureSasCredential
    :rtype: None

    .. admonition:: Example:

        .. literalinclude:: ../samples/async_samples/sample_authentication_async.py
            :start-after: [START client_auth_with_key_cred_async]
            :end-before: [END client_auth_with_key_cred_async]
            :language: python
            :dedent: 0
            :caption: Creating the EventGridPublisherClient with an endpoint and AzureKeyCredential.

        .. literalinclude:: ../samples/async_samples/sample_authentication_async.py
            :start-after: [START client_auth_with_sas_cred_async]
            :end-before: [END client_auth_with_sas_cred_async]
            :language: python
            :dedent: 0
            :caption: Creating the EventGridPublisherClient with an endpoint and AzureSasCredential.
    """

    def __init__(
        self,
        endpoint: str,
        credential: Union[AzureKeyCredential, AzureSasCredential],
        **kwargs: Any) -> None:
        self._client = EventGridPublisherClientAsync(
            policies=EventGridPublisherClient._policies(credential, **kwargs),
            **kwargs
            )
        endpoint = _get_endpoint_only_fqdn(endpoint)
        self._endpoint = endpoint

    @staticmethod
    def _policies(
        credential: Union[AzureKeyCredential, AzureSasCredential],
        **kwargs: Any
        ) -> List[Any]:
        auth_policy = _get_authentication_policy(credential)
        sdk_moniker = 'eventgridpublisherclient/{}'.format(VERSION)
        policies = [
            RequestIdPolicy(**kwargs),
            HeadersPolicy(**kwargs),
            UserAgentPolicy(sdk_moniker=sdk_moniker, **kwargs),
            ProxyPolicy(**kwargs),
            ContentDecodePolicy(**kwargs),
            AsyncRedirectPolicy(**kwargs),
            AsyncRetryPolicy(**kwargs),
            auth_policy,
            CustomHookPolicy(**kwargs),
            NetworkTraceLoggingPolicy(**kwargs),
            DistributedTracingPolicy(**kwargs),
            CloudEventDistributedTracingPolicy(),
            HttpLoggingPolicy(**kwargs)
        ]
        return policies

    @distributed_trace_async
    async def send(
        self,
        events: SendType,
        **kwargs: Any) -> None:
        """Sends events to a topic or a domain specified during the client initialization.

        A single instance or a list of dictionaries, CloudEvents or EventGridEvents are accepted.

        .. admonition:: Example:

            .. literalinclude:: ../samples/async_samples/sample_publish_eg_events_to_a_topic_async.py
                :start-after: [START publish_eg_event_to_topic_async]
                :end-before: [END publish_eg_event_to_topic_async]
                :language: python
                :dedent: 0
                :caption: Publishing an EventGridEvent.

            .. literalinclude:: ../samples/async_samples/sample_publish_events_using_cloud_events_1.0_schema_async.py
                :start-after: [START publish_cloud_event_to_topic_async]
                :end-before: [END publish_cloud_event_to_topic_async]
                :language: python
                :dedent: 0
                :caption: Publishing a CloudEvent.

        Dict representation of respective serialized models is accepted as CloudEvent(s) or
        EventGridEvent(s) apart from the strongly typed objects.

        .. admonition:: Example:

            .. literalinclude:: ../samples/async_samples/sample_publish_eg_event_using_dict_async.py
                :start-after: [START publish_eg_event_dict_async]
                :end-before: [END publish_eg_event_dict_async]
                :language: python
                :dedent: 0
                :caption: Publishing an EventGridEvent using a dict-like representation.

            .. literalinclude:: ../samples/async_samples/sample_publish_cloud_event_using_dict_async.py
                :start-after: [START publish_cloud_event_dict_async]
                :end-before: [END publish_cloud_event_dict_async]
                :language: python
                :dedent: 0
                :caption: Publishing a CloudEvent using a dict-like representation.

        When publishing a Custom Schema Event(s), dict-like representation is accepted.
        Either a single dictionary or a list of dictionaries can be passed.

        .. admonition:: Example:

            .. literalinclude:: ../samples/async_samples/sample_publish_custom_schema_to_a_topic_async.py
                :start-after: [START publish_custom_schema_async]
                :end-before: [END publish_custom_schema_async]
                :language: python
                :dedent: 0
                :caption: Publishing a Custom Schema event.

        **WARNING**: To gain the best performance when sending multiple events at one time,
        it is highly recommended to send a list of events instead of iterating over and sending each event in a loop.

        :param events: A single instance or a list of dictionaries/CloudEvent/EventGridEvent to be sent.
        :type events: SendType
        :keyword str content_type: The type of content to be used to send the events.
         Has default value "application/json; charset=utf-8" for EventGridEvents,
         with "cloudevents-batch+json" for CloudEvents
        :rtype: None
         """
        if not isinstance(events, list):
            events = cast(ListEventType, [events])

        if isinstance(events[0], CloudEvent) or _is_cloud_event(events[0]):
            try:
                events = [cast(CloudEvent, e)._to_generated(**kwargs) for e in events] # pylint: disable=protected-access
            except AttributeError:
                pass # means it's a dictionary
            kwargs.setdefault("content_type", "application/cloudevents-batch+json; charset=utf-8")
            return await self._client.publish_cloud_event_events(
                self._endpoint,
                cast(List[InternalCloudEvent], events),
                **kwargs
                )
        kwargs.setdefault("content_type", "application/json; charset=utf-8")
        if isinstance(events[0], EventGridEvent) or _is_eventgrid_event(events[0]):
            for event in events:
                _eventgrid_data_typecheck(event)
        return await self._client.publish_custom_event_events(self._endpoint, cast(List, events), **kwargs)

    async def __aenter__(self) -> "EventGridPublisherClient":
        await self._client.__aenter__()
        return self

    async def __aexit__(self, *args: "Any") -> None:
        await self._client.__aexit__(*args)

    async def close(self) -> None:
        """Close the :class:`~azure.eventgrid.aio.EventGridPublisherClient` session.
        """
        await self._client.__aexit__()
