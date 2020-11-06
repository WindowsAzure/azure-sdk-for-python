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

from msrest.pipeline import ClientRawResponse

from .. import models


class KnowledgebaseOperations(object):
    """KnowledgebaseOperations operations.

    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An object model deserializer.
    """

    models = models

    def __init__(self, client, config, serializer, deserializer):

        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer

        self.config = config

    def list_all(
            self, custom_headers=None, raw=False, **operation_config):
        """Gets all knowledgebases for a user.

        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: KnowledgebasesDTO or ClientRawResponse if raw=true
        :rtype:
         ~azure.cognitiveservices.knowledge.qnamaker.authoring.models.KnowledgebasesDTO
         or ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorResponseException<azure.cognitiveservices.knowledge.qnamaker.authoring.models.ErrorResponseException>`
        """
        # Construct URL
        url = self.list_all.metadata['url']
        path_format_arguments = {
            'Endpoint': self._serialize.url("self.config.endpoint", self.config.endpoint, 'str', skip_quote=True)
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}

        # Construct headers
        header_parameters = {}
        header_parameters['Accept'] = 'application/json'
        if custom_headers:
            header_parameters.update(custom_headers)

        # Construct and send request
        request = self._client.get(url, query_parameters, header_parameters)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200]:
            raise models.ErrorResponseException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('KnowledgebasesDTO', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    list_all.metadata = {'url': '/knowledgebases'}

    def get_details(
            self, kb_id, custom_headers=None, raw=False, **operation_config):
        """Gets details of a specific knowledgebase.

        :param kb_id: Knowledgebase id.
        :type kb_id: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: KnowledgebaseDTO or ClientRawResponse if raw=true
        :rtype:
         ~azure.cognitiveservices.knowledge.qnamaker.authoring.models.KnowledgebaseDTO
         or ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorResponseException<azure.cognitiveservices.knowledge.qnamaker.authoring.models.ErrorResponseException>`
        """
        # Construct URL
        url = self.get_details.metadata['url']
        path_format_arguments = {
            'Endpoint': self._serialize.url("self.config.endpoint", self.config.endpoint, 'str', skip_quote=True),
            'kbId': self._serialize.url("kb_id", kb_id, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}

        # Construct headers
        header_parameters = {}
        header_parameters['Accept'] = 'application/json'
        if custom_headers:
            header_parameters.update(custom_headers)

        # Construct and send request
        request = self._client.get(url, query_parameters, header_parameters)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200]:
            raise models.ErrorResponseException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('KnowledgebaseDTO', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    get_details.metadata = {'url': '/knowledgebases/{kbId}'}

    def delete(
            self, kb_id, custom_headers=None, raw=False, **operation_config):
        """Deletes the knowledgebase and all its data.

        :param kb_id: Knowledgebase id.
        :type kb_id: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: None or ClientRawResponse if raw=true
        :rtype: None or ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorResponseException<azure.cognitiveservices.knowledge.qnamaker.authoring.models.ErrorResponseException>`
        """
        # Construct URL
        url = self.delete.metadata['url']
        path_format_arguments = {
            'Endpoint': self._serialize.url("self.config.endpoint", self.config.endpoint, 'str', skip_quote=True),
            'kbId': self._serialize.url("kb_id", kb_id, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}

        # Construct headers
        header_parameters = {}
        if custom_headers:
            header_parameters.update(custom_headers)

        # Construct and send request
        request = self._client.delete(url, query_parameters, header_parameters)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [204]:
            raise models.ErrorResponseException(self._deserialize, response)

        if raw:
            client_raw_response = ClientRawResponse(None, response)
            return client_raw_response
    delete.metadata = {'url': '/knowledgebases/{kbId}'}

    def publish(
            self, kb_id, custom_headers=None, raw=False, **operation_config):
        """Publishes all changes in test index of a knowledgebase to its prod
        index.

        :param kb_id: Knowledgebase id.
        :type kb_id: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: None or ClientRawResponse if raw=true
        :rtype: None or ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorResponseException<azure.cognitiveservices.knowledge.qnamaker.authoring.models.ErrorResponseException>`
        """
        # Construct URL
        url = self.publish.metadata['url']
        path_format_arguments = {
            'Endpoint': self._serialize.url("self.config.endpoint", self.config.endpoint, 'str', skip_quote=True),
            'kbId': self._serialize.url("kb_id", kb_id, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}

        # Construct headers
        header_parameters = {}
        if custom_headers:
            header_parameters.update(custom_headers)

        # Construct and send request
        request = self._client.post(url, query_parameters, header_parameters)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [204]:
            raise models.ErrorResponseException(self._deserialize, response)

        if raw:
            client_raw_response = ClientRawResponse(None, response)
            return client_raw_response
    publish.metadata = {'url': '/knowledgebases/{kbId}'}

    def replace(
            self, kb_id, qn_alist, custom_headers=None, raw=False, **operation_config):
        """Replace knowledgebase contents.

        :param kb_id: Knowledgebase id.
        :type kb_id: str
        :param qn_alist: List of Q-A (QnADTO) to be added to the
         knowledgebase. Q-A Ids are assigned by the service and should be
         omitted.
        :type qn_alist:
         list[~azure.cognitiveservices.knowledge.qnamaker.authoring.models.QnADTO]
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: None or ClientRawResponse if raw=true
        :rtype: None or ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorResponseException<azure.cognitiveservices.knowledge.qnamaker.authoring.models.ErrorResponseException>`
        """
        replace_kb = models.ReplaceKbDTO(qn_alist=qn_alist)

        # Construct URL
        url = self.replace.metadata['url']
        path_format_arguments = {
            'Endpoint': self._serialize.url("self.config.endpoint", self.config.endpoint, 'str', skip_quote=True),
            'kbId': self._serialize.url("kb_id", kb_id, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}

        # Construct headers
        header_parameters = {}
        header_parameters['Content-Type'] = 'application/json; charset=utf-8'
        if custom_headers:
            header_parameters.update(custom_headers)

        # Construct body
        body_content = self._serialize.body(replace_kb, 'ReplaceKbDTO')

        # Construct and send request
        request = self._client.put(url, query_parameters, header_parameters, body_content)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [204]:
            raise models.ErrorResponseException(self._deserialize, response)

        if raw:
            client_raw_response = ClientRawResponse(None, response)
            return client_raw_response
    replace.metadata = {'url': '/knowledgebases/{kbId}'}

    def update(
            self, kb_id, update_kb, custom_headers=None, raw=False, **operation_config):
        """Asynchronous operation to modify a knowledgebase.

        :param kb_id: Knowledgebase id.
        :type kb_id: str
        :param update_kb: Post body of the request.
        :type update_kb:
         ~azure.cognitiveservices.knowledge.qnamaker.authoring.models.UpdateKbOperationDTO
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: Operation or ClientRawResponse if raw=true
        :rtype:
         ~azure.cognitiveservices.knowledge.qnamaker.authoring.models.Operation
         or ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorResponseException<azure.cognitiveservices.knowledge.qnamaker.authoring.models.ErrorResponseException>`
        """
        # Construct URL
        url = self.update.metadata['url']
        path_format_arguments = {
            'Endpoint': self._serialize.url("self.config.endpoint", self.config.endpoint, 'str', skip_quote=True),
            'kbId': self._serialize.url("kb_id", kb_id, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}

        # Construct headers
        header_parameters = {}
        header_parameters['Accept'] = 'application/json'
        header_parameters['Content-Type'] = 'application/json; charset=utf-8'
        if custom_headers:
            header_parameters.update(custom_headers)

        # Construct body
        body_content = self._serialize.body(update_kb, 'UpdateKbOperationDTO')

        # Construct and send request
        request = self._client.patch(url, query_parameters, header_parameters, body_content)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [202]:
            raise models.ErrorResponseException(self._deserialize, response)

        deserialized = None
        header_dict = {}

        if response.status_code == 202:
            deserialized = self._deserialize('Operation', response)
            header_dict = {
                'Location': 'str',
            }

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            client_raw_response.add_headers(header_dict)
            return client_raw_response

        return deserialized
    update.metadata = {'url': '/knowledgebases/{kbId}'}

    def create(
            self, create_kb_payload, custom_headers=None, raw=False, **operation_config):
        """Asynchronous operation to create a new knowledgebase.

        :param create_kb_payload: Post body of the request.
        :type create_kb_payload:
         ~azure.cognitiveservices.knowledge.qnamaker.authoring.models.CreateKbDTO
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: Operation or ClientRawResponse if raw=true
        :rtype:
         ~azure.cognitiveservices.knowledge.qnamaker.authoring.models.Operation
         or ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorResponseException<azure.cognitiveservices.knowledge.qnamaker.authoring.models.ErrorResponseException>`
        """
        # Construct URL
        url = self.create.metadata['url']
        path_format_arguments = {
            'Endpoint': self._serialize.url("self.config.endpoint", self.config.endpoint, 'str', skip_quote=True)
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}

        # Construct headers
        header_parameters = {}
        header_parameters['Accept'] = 'application/json'
        header_parameters['Content-Type'] = 'application/json; charset=utf-8'
        if custom_headers:
            header_parameters.update(custom_headers)

        # Construct body
        body_content = self._serialize.body(create_kb_payload, 'CreateKbDTO')

        # Construct and send request
        request = self._client.post(url, query_parameters, header_parameters, body_content)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [202]:
            raise models.ErrorResponseException(self._deserialize, response)

        deserialized = None

        if response.status_code == 202:
            deserialized = self._deserialize('Operation', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    create.metadata = {'url': '/knowledgebases/create'}

    def download(
            self, kb_id, environment, source=None, changed_since=None, custom_headers=None, raw=False, **operation_config):
        """Download the knowledgebase.

        :param kb_id: Knowledgebase id.
        :type kb_id: str
        :param environment: Specifies whether environment is Test or Prod.
         Possible values include: 'Prod', 'Test'
        :type environment: str or
         ~azure.cognitiveservices.knowledge.qnamaker.authoring.models.EnvironmentType
        :param source: The source property filter to apply.
        :type source: str
        :param changed_since: The last changed status property filter to
         apply.
        :type changed_since: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: QnADocumentsDTO or ClientRawResponse if raw=true
        :rtype:
         ~azure.cognitiveservices.knowledge.qnamaker.authoring.models.QnADocumentsDTO
         or ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorResponseException<azure.cognitiveservices.knowledge.qnamaker.authoring.models.ErrorResponseException>`
        """
        # Construct URL
        url = self.download.metadata['url']
        path_format_arguments = {
            'Endpoint': self._serialize.url("self.config.endpoint", self.config.endpoint, 'str', skip_quote=True),
            'kbId': self._serialize.url("kb_id", kb_id, 'str'),
            'environment': self._serialize.url("environment", environment, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        if source is not None:
            query_parameters['source'] = self._serialize.query("source", source, 'str')
        if changed_since is not None:
            query_parameters['changedSince'] = self._serialize.query("changed_since", changed_since, 'str')

        # Construct headers
        header_parameters = {}
        header_parameters['Accept'] = 'application/json'
        if custom_headers:
            header_parameters.update(custom_headers)

        # Construct and send request
        request = self._client.get(url, query_parameters, header_parameters)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200]:
            raise models.ErrorResponseException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('QnADocumentsDTO', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    download.metadata = {'url': '/knowledgebases/{kbId}/{environment}/qna'}

    def generate_answer(
            self, kb_id, generate_answer_payload, custom_headers=None, raw=False, **operation_config):
        """GenerateAnswer call to query knowledgebase (QnA Maker Managed).

        :param kb_id: Knowledgebase id.
        :type kb_id: str
        :param generate_answer_payload: Post body of the request.
        :type generate_answer_payload:
         ~azure.cognitiveservices.knowledge.qnamaker.authoring.models.QueryDTO
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: QnASearchResultList or ClientRawResponse if raw=true
        :rtype:
         ~azure.cognitiveservices.knowledge.qnamaker.authoring.models.QnASearchResultList
         or ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorResponseException<azure.cognitiveservices.knowledge.qnamaker.authoring.models.ErrorResponseException>`
        """
        # Construct URL
        url = self.generate_answer.metadata['url']
        path_format_arguments = {
            'Endpoint': self._serialize.url("self.config.endpoint", self.config.endpoint, 'str', skip_quote=True),
            'kbId': self._serialize.url("kb_id", kb_id, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}

        # Construct headers
        header_parameters = {}
        header_parameters['Accept'] = 'application/json'
        header_parameters['Content-Type'] = 'application/json; charset=utf-8'
        if custom_headers:
            header_parameters.update(custom_headers)

        # Construct body
        body_content = self._serialize.body(generate_answer_payload, 'QueryDTO')

        # Construct and send request
        request = self._client.post(url, query_parameters, header_parameters, body_content)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200]:
            raise models.ErrorResponseException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('QnASearchResultList', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    generate_answer.metadata = {'url': '/knowledgebases/{kbId}/generateAnswer'}

    def train(
            self, kb_id, feedback_records=None, custom_headers=None, raw=False, **operation_config):
        """Train call to add suggestions to knowledgebase (QnAMaker Managed).

        :param kb_id: Knowledgebase id.
        :type kb_id: str
        :param feedback_records: List of feedback records.
        :type feedback_records:
         list[~azure.cognitiveservices.knowledge.qnamaker.authoring.models.FeedbackRecordDTO]
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: None or ClientRawResponse if raw=true
        :rtype: None or ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorResponseException<azure.cognitiveservices.knowledge.qnamaker.authoring.models.ErrorResponseException>`
        """
        train_payload = models.FeedbackRecordsDTO(feedback_records=feedback_records)

        # Construct URL
        url = self.train.metadata['url']
        path_format_arguments = {
            'Endpoint': self._serialize.url("self.config.endpoint", self.config.endpoint, 'str', skip_quote=True),
            'kbId': self._serialize.url("kb_id", kb_id, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}

        # Construct headers
        header_parameters = {}
        header_parameters['Content-Type'] = 'application/json; charset=utf-8'
        if custom_headers:
            header_parameters.update(custom_headers)

        # Construct body
        body_content = self._serialize.body(train_payload, 'FeedbackRecordsDTO')

        # Construct and send request
        request = self._client.post(url, query_parameters, header_parameters, body_content)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [204]:
            raise models.ErrorResponseException(self._deserialize, response)

        if raw:
            client_raw_response = ClientRawResponse(None, response)
            return client_raw_response
    train.metadata = {'url': '/knowledgebases/{kbId}/train'}
