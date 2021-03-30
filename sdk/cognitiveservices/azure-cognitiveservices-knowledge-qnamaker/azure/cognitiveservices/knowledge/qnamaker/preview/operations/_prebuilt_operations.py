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


class PrebuiltOperations(object):
    """PrebuiltOperations operations.

    You should not instantiate directly this class, but create a Client instance that will create it for you and attach it as attribute.

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

    def generate_answer(
            self, prebuilt_generate_answer_payload, string_index_type="TextElements_v8", custom_headers=None, raw=False, **operation_config):
        """GenerateAnswer call to query text in documents.

        :param prebuilt_generate_answer_payload: Post body of the request.
        :type prebuilt_generate_answer_payload:
         ~azure.cognitiveservices.knowledge.qnamaker.preview.models.PrebuiltQuery
        :param string_index_type: (Optional) Specifies the method used to
         interpret string offsets.  Defaults to Text Elements (Graphemes)
         according to Unicode v8.0.0. Possible values include:
         'TextElements_v8', 'UnicodeCodePoint', 'Utf16CodeUnit'
        :type string_index_type: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: object or ClientRawResponse if raw=true
        :rtype: object or ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorResponseException<azure.cognitiveservices.knowledge.qnamaker.preview.models.ErrorResponseException>`
        """
        # Construct URL
        url = self.generate_answer.metadata['url']
        path_format_arguments = {
            'Endpoint': self._serialize.url("self.config.endpoint", self.config.endpoint, 'str', skip_quote=True)
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        if string_index_type is not None:
            query_parameters['stringIndexType'] = self._serialize.query("string_index_type", string_index_type, 'str')

        # Construct headers
        header_parameters = {}
        header_parameters['Accept'] = 'application/json'
        header_parameters['Content-Type'] = 'application/json; charset=utf-8'
        if custom_headers:
            header_parameters.update(custom_headers)

        # Construct body
        body_content = self._serialize.body(prebuilt_generate_answer_payload, 'PrebuiltQuery')

        # Construct and send request
        request = self._client.post(url, query_parameters, header_parameters, body_content)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200]:
            raise models.ErrorResponseException(self._deserialize, response)

        deserialized = None
        if response.status_code == 200:
            deserialized = self._deserialize('object', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    generate_answer.metadata = {'url': '/generateAnswer'}
