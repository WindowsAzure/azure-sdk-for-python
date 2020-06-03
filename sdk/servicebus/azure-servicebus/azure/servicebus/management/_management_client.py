# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------
from contextlib import contextmanager
from copy import copy
from typing import TYPE_CHECKING, Dict, Any, Union, List, cast, Type
from xml.etree.ElementTree import ElementTree, Element

from azure.core.exceptions import ResourceNotFoundError, HttpResponseError
from azure.core.pipeline import Pipeline
from azure.core.pipeline.policies import HttpLoggingPolicy, DistributedTracingPolicy, ContentDecodePolicy, \
    RequestIdPolicy, BearerTokenCredentialPolicy
from azure.core.pipeline.transport import RequestsTransport
from azure.servicebus import ServiceBusSharedKeyCredential
from msrest.serialization import Model

from .._common.constants import JWT_TOKEN_SCOPE
from .._common.utils import parse_conn_str
from ._shared_key_policy import ServiceBusSharedKeyCredentialPolicy
from ._generated._configuration import ServiceBusManagementClientConfiguration
from ._generated.models import CreateQueueBody, CreateQueueBodyContent, \
    QueueDescription, QueueRuntimeInfo
from ._generated._service_bus_management_client import ServiceBusManagementClient as ServiceBusManagementClientImpl
from . import _constants as constants

if TYPE_CHECKING:
    from azure.core.credentials import TokenCredential  # pylint:disable=ungrouped-imports


@contextmanager
def _handle_response_error():
    try:
        yield
    except HttpResponseError as response_error:
        try:
            new_response_error = HttpResponseError(
                message=response_error.model.detail,
                response=response_error.response,
                model=response_error.model
            )
        except AttributeError:
            new_response_error = response_error
        raise new_response_error


def _convert_xml_to_object(queue_name, et, clazz):
    # type: (str, Union[Element, ElementTree], Type[Model]) -> Union[QueueDescription, QueueRuntimeInfo]
    content_ele = cast(ElementTree, et).find(constants.CONTENT_TAG)
    if not content_ele:
        raise ResourceNotFoundError("Queue '{}' does not exist".format(queue_name))
    qc_ele = content_ele.find(constants.QUEUE_DESCRIPTION_TAG)
    obj = clazz.deserialize(qc_ele)
    obj.queue_name = queue_name
    return obj


class ServiceBusManagementClient:

    def __init__(self, fully_qualified_namespace, credential, **kwargs):
        # type: (str, Union[TokenCredential, ServiceBusSharedKeyCredential], Dict[str, Any]) -> None
        """
        :param fully_qualified_namespace:
        :param kwargs:
        """
        self.fully_qualified_namespace = fully_qualified_namespace
        self._credential = credential
        self._endpoint = "https://" + fully_qualified_namespace
        self._config = ServiceBusManagementClientConfiguration(self._endpoint, **kwargs)
        self._pipeline = self._build_pipeline()
        self._impl = ServiceBusManagementClientImpl(endpoint=fully_qualified_namespace, pipeline=self._pipeline)

    def _build_pipeline(self, **kwargs):  # pylint: disable=no-self-use
        transport = kwargs.get('transport')
        policies = kwargs.get('policies')
        credential_policy = ServiceBusSharedKeyCredentialPolicy(self._endpoint, self._credential, "Authorization") \
            if isinstance(self._credential, ServiceBusSharedKeyCredential) \
            else BearerTokenCredentialPolicy(self._credential, JWT_TOKEN_SCOPE)
        if policies is None:  # [] is a valid policy list
            policies = [
                RequestIdPolicy(**kwargs),
                self._config.headers_policy,
                self._config.user_agent_policy,
                self._config.proxy_policy,
                ContentDecodePolicy(**kwargs),
                self._config.redirect_policy,
                self._config.retry_policy,
                credential_policy,
                self._config.logging_policy,
                DistributedTracingPolicy(**kwargs),
                HttpLoggingPolicy(**kwargs),
            ]
        if not transport:
            transport = RequestsTransport(**kwargs)
        return Pipeline(transport, policies)

    @classmethod
    def from_connection_string(cls, connection_string):
        # type: (str) -> ServiceBusManagementClient
        """

        :param str connection_string:
        :return:
        """
        endpoint, shared_access_key_name, shared_access_key, _ = parse_conn_str(connection_string)
        if "//" in endpoint:
            endpoint = endpoint[endpoint.index("//")+2:]
        return cls(endpoint, ServiceBusSharedKeyCredential(shared_access_key_name, shared_access_key))

    def _get_queue_object(self, queue_name, clazz):
        # type: (str, Type[Model]) -> Union[QueueDescription, QueueRuntimeInfo]

        if not queue_name:
            raise ValueError("queue_name must be a non-empty str")

        with _handle_response_error():
            et = cast(
                ElementTree,
                self._impl.queue.get(queue_name, enrich=False, api_version=constants.API_VERSION)
            )
        return _convert_xml_to_object(queue_name, et, clazz)

    def _list_queues(self, skip, max_count, clazz):
        # type: (int, int, Type[Model]) -> Union[List[QueueDescription], List[QueueRuntimeInfo]]
        with _handle_response_error():
            et = cast(
                ElementTree,
                self._impl.list_entities(
                    entity_type="queues", skip=skip, top=max_count, api_version=constants.API_VERSION
                )
            )
        entries = et.findall(constants.ENTRY_TAG)
        queues = []
        for entry in entries:
            entity_name = entry.find(constants.TITLE_TAG).text  # type: ignore
            queue_description = _convert_xml_to_object(
                entity_name,   # type: ignore
                cast(Element, entry),
                clazz
            )
            queues.append(queue_description)
        return queues

    def get_queue(self, queue_name):
        # type: (str) -> QueueDescription
        return self._get_queue_object(queue_name, QueueDescription)

    def get_queue_runtime_info(self, queue_name):
        # type: (str) -> QueueRuntimeInfo
        return self._get_queue_object(queue_name, QueueRuntimeInfo)

    def create_queue(self, queue):
        # type: (Union[str, QueueDescription]) -> QueueDescription
        """Create a queue"""

        try:  # queue is a QueueDescription
            queue_name = queue.queue_name
            to_create = copy(queue)
            to_create.queue_name = None
        except AttributeError:  # str expected. But if not str, it might work and might not work.
            queue_name = queue
            to_create = QueueDescription()
        if queue_name is None:
            raise ValueError("queue should be a non-empty str or a QueueDescription with non-empty queue_name")

        create_entity_body = CreateQueueBody(
            content=CreateQueueBodyContent(
                queue_description=to_create,
            )
        )
        request_body = create_entity_body.serialize(is_xml=True)

        with _handle_response_error():
            et = cast(
                ElementTree,
                self._impl.queue.put(queue_name, request_body, api_version=constants.API_VERSION)
            )
        return _convert_xml_to_object(queue_name, et, QueueDescription)

    def update_queue(self, queue_description):
        # type: (QueueDescription) -> QueueDescription
        """Update a queue"""
        if not queue_description.queue_name:
            raise ValueError("queue_description must have a non-empty queue_name")

        to_update = copy(queue_description)
        to_update.queue_name = None
        create_entity_body = CreateQueueBody(
            content=CreateQueueBodyContent(
                queue_description=to_update
            )
        )
        request_body = create_entity_body.serialize(is_xml=True)
        with _handle_response_error():
            et = cast(
                ElementTree,
                self._impl.queue.put(
                queue_description.queue_name,  # type: ignore
                request_body,
                api_version=constants.API_VERSION,
                if_match="*"
                )
            )
        return _convert_xml_to_object(queue_description.queue_name, et, QueueDescription)

    def delete_queue(self, queue_name):
        # type: (str) -> None
        """Create a queue"""

        if not queue_name:
            raise ValueError("queue_name must not be None or empty")
        with _handle_response_error():
            self._impl.queue.delete(queue_name, api_version=constants.API_VERSION)

    def list_queues(self, skip=0, max_count=100):
        # type: (int, int) -> List[QueueDescription]
        return self._list_queues(skip, max_count, QueueDescription)

    def list_queues_runtime_info(self, skip=0, max_count=100):
        # type: (int, int) -> List[QueueRuntimeInfo]
        return self._list_queues(skip, max_count, QueueRuntimeInfo)
