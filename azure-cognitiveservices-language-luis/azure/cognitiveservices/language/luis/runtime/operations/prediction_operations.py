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


class PredictionOperations(object):
    """PredictionOperations operations.

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

    def resolve(
            self, app_id, query, timezone_offset=None, verbose=None, staging=None, spell_check=None, bing_spell_check_subscription_key=None, log=None, custom_headers=None, raw=False, **operation_config):
        """Gets predictions for a given utterance, in the form of intents and
        entities. The current maximum query size is 500 characters.

        :param app_id: The LUIS application ID (Guid).
        :type app_id: str
        :param query: The utterance to predict.
        :type query: str
        :param timezone_offset: The timezone offset for the location of the
         request.
        :type timezone_offset: float
        :param verbose: If true, return all intents instead of just the top
         scoring intent.
        :type verbose: bool
        :param staging: Use the staging endpoint slot.
        :type staging: bool
        :param spell_check: Enable spell checking.
        :type spell_check: bool
        :param bing_spell_check_subscription_key: The subscription key to use
         when enabling bing spell check
        :type bing_spell_check_subscription_key: str
        :param log: Log query (default is true)
        :type log: bool
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: LuisResult or ClientRawResponse if raw=true
        :rtype:
         ~azure.cognitiveservices.language.luis.runtime.models.LuisResult or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`APIErrorException<azure.cognitiveservices.language.luis.runtime.models.APIErrorException>`
        """
        # Construct URL
        url = self.resolve.metadata['url']
        path_format_arguments = {
            'appId': self._serialize.url("app_id", app_id, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        if timezone_offset is not None:
            query_parameters['timezoneOffset'] = self._serialize.query("timezone_offset", timezone_offset, 'float')
        if verbose is not None:
            query_parameters['verbose'] = self._serialize.query("verbose", verbose, 'bool')
        if staging is not None:
            query_parameters['staging'] = self._serialize.query("staging", staging, 'bool')
        if spell_check is not None:
            query_parameters['spellCheck'] = self._serialize.query("spell_check", spell_check, 'bool')
        if bing_spell_check_subscription_key is not None:
            query_parameters['bing-spell-check-subscription-key'] = self._serialize.query("bing_spell_check_subscription_key", bing_spell_check_subscription_key, 'str')
        if log is not None:
            query_parameters['log'] = self._serialize.query("log", log, 'bool')

        # Construct headers
        header_parameters = {}
        header_parameters['Content-Type'] = 'application/json; charset=utf-8'
        if custom_headers:
            header_parameters.update(custom_headers)

        # Construct body
        body_content = self._serialize.body(query, 'str')

        # Construct and send request
        request = self._client.post(url, query_parameters)
        response = self._client.send(
            request, header_parameters, body_content, stream=False, **operation_config)

        if response.status_code not in [200]:
            raise models.APIErrorException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('LuisResult', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    resolve.metadata = {'url': '/apps/{appId}'}
