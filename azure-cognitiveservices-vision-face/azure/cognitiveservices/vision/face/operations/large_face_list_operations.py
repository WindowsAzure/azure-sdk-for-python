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


class LargeFaceListOperations(object):
    """LargeFaceListOperations operations.

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

    def create(
            self, large_face_list_id, name=None, user_data=None, custom_headers=None, raw=False, **operation_config):
        """Create an empty large face list. Up to 64 large face lists are allowed
        to exist in one subscription.

        :param large_face_list_id: Id referencing a particular large face
         list.
        :type large_face_list_id: str
        :param name: User defined name, maximum length is 128.
        :type name: str
        :param user_data: User specified data. Length should not exceed 16KB.
        :type user_data: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: None or ClientRawResponse if raw=true
        :rtype: None or ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`APIErrorException<azure.cognitiveservices.vision.face.models.APIErrorException>`
        """
        body = models.NameAndUserDataContract(name=name, user_data=user_data)

        # Construct URL
        url = self.create.metadata['url']
        path_format_arguments = {
            'Endpoint': self._serialize.url("self.config.endpoint", self.config.endpoint, 'str', skip_quote=True),
            'largeFaceListId': self._serialize.url("large_face_list_id", large_face_list_id, 'str', max_length=64, pattern=r'^[a-z0-9-_]+$')
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
        body_content = self._serialize.body(body, 'NameAndUserDataContract')

        # Construct and send request
        request = self._client.put(url, query_parameters, header_parameters, body_content)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200]:
            raise models.APIErrorException(self._deserialize, response)

        if raw:
            client_raw_response = ClientRawResponse(None, response)
            return client_raw_response
    create.metadata = {'url': '/largefacelists/{largeFaceListId}'}

    def get(
            self, large_face_list_id, custom_headers=None, raw=False, **operation_config):
        """Retrieve a large face list's information.

        :param large_face_list_id: Id referencing a particular large face
         list.
        :type large_face_list_id: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: LargeFaceList or ClientRawResponse if raw=true
        :rtype: ~azure.cognitiveservices.vision.face.models.LargeFaceList or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`APIErrorException<azure.cognitiveservices.vision.face.models.APIErrorException>`
        """
        # Construct URL
        url = self.get.metadata['url']
        path_format_arguments = {
            'Endpoint': self._serialize.url("self.config.endpoint", self.config.endpoint, 'str', skip_quote=True),
            'largeFaceListId': self._serialize.url("large_face_list_id", large_face_list_id, 'str', max_length=64, pattern=r'^[a-z0-9-_]+$')
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
            raise models.APIErrorException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('LargeFaceList', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    get.metadata = {'url': '/largefacelists/{largeFaceListId}'}

    def update(
            self, large_face_list_id, name=None, user_data=None, custom_headers=None, raw=False, **operation_config):
        """Update information of a large face list.

        :param large_face_list_id: Id referencing a particular large face
         list.
        :type large_face_list_id: str
        :param name: User defined name, maximum length is 128.
        :type name: str
        :param user_data: User specified data. Length should not exceed 16KB.
        :type user_data: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: None or ClientRawResponse if raw=true
        :rtype: None or ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`APIErrorException<azure.cognitiveservices.vision.face.models.APIErrorException>`
        """
        body = models.NameAndUserDataContract(name=name, user_data=user_data)

        # Construct URL
        url = self.update.metadata['url']
        path_format_arguments = {
            'Endpoint': self._serialize.url("self.config.endpoint", self.config.endpoint, 'str', skip_quote=True),
            'largeFaceListId': self._serialize.url("large_face_list_id", large_face_list_id, 'str', max_length=64, pattern=r'^[a-z0-9-_]+$')
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
        body_content = self._serialize.body(body, 'NameAndUserDataContract')

        # Construct and send request
        request = self._client.patch(url, query_parameters, header_parameters, body_content)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200]:
            raise models.APIErrorException(self._deserialize, response)

        if raw:
            client_raw_response = ClientRawResponse(None, response)
            return client_raw_response
    update.metadata = {'url': '/largefacelists/{largeFaceListId}'}

    def delete(
            self, large_face_list_id, custom_headers=None, raw=False, **operation_config):
        """Delete an existing large face list according to faceListId. Persisted
        face images in the large face list will also be deleted.

        :param large_face_list_id: Id referencing a particular large face
         list.
        :type large_face_list_id: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: None or ClientRawResponse if raw=true
        :rtype: None or ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`APIErrorException<azure.cognitiveservices.vision.face.models.APIErrorException>`
        """
        # Construct URL
        url = self.delete.metadata['url']
        path_format_arguments = {
            'Endpoint': self._serialize.url("self.config.endpoint", self.config.endpoint, 'str', skip_quote=True),
            'largeFaceListId': self._serialize.url("large_face_list_id", large_face_list_id, 'str', max_length=64, pattern=r'^[a-z0-9-_]+$')
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

        if response.status_code not in [200]:
            raise models.APIErrorException(self._deserialize, response)

        if raw:
            client_raw_response = ClientRawResponse(None, response)
            return client_raw_response
    delete.metadata = {'url': '/largefacelists/{largeFaceListId}'}

    def get_training_status(
            self, large_face_list_id, custom_headers=None, raw=False, **operation_config):
        """Retrieve the training status of a large face list (completed or
        ongoing).

        :param large_face_list_id: Id referencing a particular large face
         list.
        :type large_face_list_id: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: TrainingStatus or ClientRawResponse if raw=true
        :rtype: ~azure.cognitiveservices.vision.face.models.TrainingStatus or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`APIErrorException<azure.cognitiveservices.vision.face.models.APIErrorException>`
        """
        # Construct URL
        url = self.get_training_status.metadata['url']
        path_format_arguments = {
            'Endpoint': self._serialize.url("self.config.endpoint", self.config.endpoint, 'str', skip_quote=True),
            'largeFaceListId': self._serialize.url("large_face_list_id", large_face_list_id, 'str', max_length=64, pattern=r'^[a-z0-9-_]+$')
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
            raise models.APIErrorException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('TrainingStatus', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    get_training_status.metadata = {'url': '/largefacelists/{largeFaceListId}/training'}

    def list(
            self, custom_headers=None, raw=False, **operation_config):
        """Retrieve information about all existing large face lists. Only
        largeFaceListId, name and userData will be returned.

        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: list or ClientRawResponse if raw=true
        :rtype:
         list[~azure.cognitiveservices.vision.face.models.LargeFaceList] or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`APIErrorException<azure.cognitiveservices.vision.face.models.APIErrorException>`
        """
        # Construct URL
        url = self.list.metadata['url']
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
            raise models.APIErrorException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('[LargeFaceList]', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    list.metadata = {'url': '/largefacelists'}

    def train(
            self, large_face_list_id, custom_headers=None, raw=False, **operation_config):
        """Queue a large face list training task, the training task may not be
        started immediately.

        :param large_face_list_id: Id referencing a particular large face
         list.
        :type large_face_list_id: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: None or ClientRawResponse if raw=true
        :rtype: None or ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`APIErrorException<azure.cognitiveservices.vision.face.models.APIErrorException>`
        """
        # Construct URL
        url = self.train.metadata['url']
        path_format_arguments = {
            'Endpoint': self._serialize.url("self.config.endpoint", self.config.endpoint, 'str', skip_quote=True),
            'largeFaceListId': self._serialize.url("large_face_list_id", large_face_list_id, 'str', max_length=64, pattern=r'^[a-z0-9-_]+$')
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

        if response.status_code not in [202]:
            raise models.APIErrorException(self._deserialize, response)

        if raw:
            client_raw_response = ClientRawResponse(None, response)
            return client_raw_response
    train.metadata = {'url': '/largefacelists/{largeFaceListId}/train'}

    def delete_face(
            self, large_face_list_id, persisted_face_id, custom_headers=None, raw=False, **operation_config):
        """Delete an existing face from a large face list (given by a
        persisitedFaceId and a largeFaceListId). Persisted image related to the
        face will also be deleted.

        :param large_face_list_id: Id referencing a particular large face
         list.
        :type large_face_list_id: str
        :param persisted_face_id: Id referencing a particular persistedFaceId
         of an existing face.
        :type persisted_face_id: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: None or ClientRawResponse if raw=true
        :rtype: None or ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`APIErrorException<azure.cognitiveservices.vision.face.models.APIErrorException>`
        """
        # Construct URL
        url = self.delete_face.metadata['url']
        path_format_arguments = {
            'Endpoint': self._serialize.url("self.config.endpoint", self.config.endpoint, 'str', skip_quote=True),
            'largeFaceListId': self._serialize.url("large_face_list_id", large_face_list_id, 'str', max_length=64, pattern=r'^[a-z0-9-_]+$'),
            'persistedFaceId': self._serialize.url("persisted_face_id", persisted_face_id, 'str')
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

        if response.status_code not in [200]:
            raise models.APIErrorException(self._deserialize, response)

        if raw:
            client_raw_response = ClientRawResponse(None, response)
            return client_raw_response
    delete_face.metadata = {'url': '/largefacelists/{largeFaceListId}/persistedfaces/{persistedFaceId}'}

    def get_face(
            self, large_face_list_id, persisted_face_id, custom_headers=None, raw=False, **operation_config):
        """Retrieve information about a persisted face (specified by
        persistedFaceId and its belonging largeFaceListId).

        :param large_face_list_id: Id referencing a particular large face
         list.
        :type large_face_list_id: str
        :param persisted_face_id: Id referencing a particular persistedFaceId
         of an existing face.
        :type persisted_face_id: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: PersistedFace or ClientRawResponse if raw=true
        :rtype: ~azure.cognitiveservices.vision.face.models.PersistedFace or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`APIErrorException<azure.cognitiveservices.vision.face.models.APIErrorException>`
        """
        # Construct URL
        url = self.get_face.metadata['url']
        path_format_arguments = {
            'Endpoint': self._serialize.url("self.config.endpoint", self.config.endpoint, 'str', skip_quote=True),
            'largeFaceListId': self._serialize.url("large_face_list_id", large_face_list_id, 'str', max_length=64, pattern=r'^[a-z0-9-_]+$'),
            'persistedFaceId': self._serialize.url("persisted_face_id", persisted_face_id, 'str')
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
            raise models.APIErrorException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('PersistedFace', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    get_face.metadata = {'url': '/largefacelists/{largeFaceListId}/persistedfaces/{persistedFaceId}'}

    def update_face(
            self, large_face_list_id, persisted_face_id, user_data=None, custom_headers=None, raw=False, **operation_config):
        """Update a persisted face's userData field.

        :param large_face_list_id: Id referencing a particular large face
         list.
        :type large_face_list_id: str
        :param persisted_face_id: Id referencing a particular persistedFaceId
         of an existing face.
        :type persisted_face_id: str
        :param user_data: User-provided data attached to the face. The size
         limit is 1KB.
        :type user_data: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: None or ClientRawResponse if raw=true
        :rtype: None or ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`APIErrorException<azure.cognitiveservices.vision.face.models.APIErrorException>`
        """
        body = models.UpdateFaceRequest(user_data=user_data)

        # Construct URL
        url = self.update_face.metadata['url']
        path_format_arguments = {
            'Endpoint': self._serialize.url("self.config.endpoint", self.config.endpoint, 'str', skip_quote=True),
            'largeFaceListId': self._serialize.url("large_face_list_id", large_face_list_id, 'str', max_length=64, pattern=r'^[a-z0-9-_]+$'),
            'persistedFaceId': self._serialize.url("persisted_face_id", persisted_face_id, 'str')
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
        body_content = self._serialize.body(body, 'UpdateFaceRequest')

        # Construct and send request
        request = self._client.patch(url, query_parameters, header_parameters, body_content)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200]:
            raise models.APIErrorException(self._deserialize, response)

        if raw:
            client_raw_response = ClientRawResponse(None, response)
            return client_raw_response
    update_face.metadata = {'url': '/largefacelists/{largeFaceListId}/persistedfaces/{persistedFaceId}'}

    def add_face_from_url(
            self, large_face_list_id, url, user_data=None, target_face=None, custom_headers=None, raw=False, **operation_config):
        """Add a face to a large face list. The input face is specified as an
        image with a targetFace rectangle. It returns a persistedFaceId
        representing the added face, and persistedFaceId will not expire.

        :param large_face_list_id: Id referencing a particular large face
         list.
        :type large_face_list_id: str
        :param url: Publicly reachable URL of an image
        :type url: str
        :param user_data: User-specified data about the face for any purpose.
         The maximum length is 1KB.
        :type user_data: str
        :param target_face: A face rectangle to specify the target face to be
         added to a person in the format of "targetFace=left,top,width,height".
         E.g. "targetFace=10,10,100,100". If there is more than one face in the
         image, targetFace is required to specify which face to add. No
         targetFace means there is only one face detected in the entire image.
        :type target_face: list[int]
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: PersistedFace or ClientRawResponse if raw=true
        :rtype: ~azure.cognitiveservices.vision.face.models.PersistedFace or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`APIErrorException<azure.cognitiveservices.vision.face.models.APIErrorException>`
        """
        image_url = models.ImageUrl(url=url)

        # Construct URL
        url = self.add_face_from_url.metadata['url']
        path_format_arguments = {
            'Endpoint': self._serialize.url("self.config.endpoint", self.config.endpoint, 'str', skip_quote=True),
            'largeFaceListId': self._serialize.url("large_face_list_id", large_face_list_id, 'str', max_length=64, pattern=r'^[a-z0-9-_]+$')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        if user_data is not None:
            query_parameters['userData'] = self._serialize.query("user_data", user_data, 'str', max_length=1024)
        if target_face is not None:
            query_parameters['targetFace'] = self._serialize.query("target_face", target_face, '[int]', div=',')

        # Construct headers
        header_parameters = {}
        header_parameters['Accept'] = 'application/json'
        header_parameters['Content-Type'] = 'application/json; charset=utf-8'
        if custom_headers:
            header_parameters.update(custom_headers)

        # Construct body
        body_content = self._serialize.body(image_url, 'ImageUrl')

        # Construct and send request
        request = self._client.post(url, query_parameters, header_parameters, body_content)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200]:
            raise models.APIErrorException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('PersistedFace', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    add_face_from_url.metadata = {'url': '/largefacelists/{largeFaceListId}/persistedfaces'}

    def list_faces(
            self, large_face_list_id, start=None, top=None, custom_headers=None, raw=False, **operation_config):
        """List all faces in a large face list, and retrieve face information
        (including userData and persistedFaceIds of registered faces of the
        face).

        :param large_face_list_id: Id referencing a particular large face
         list.
        :type large_face_list_id: str
        :param start: Starting face id to return (used to list a range of
         faces).
        :type start: str
        :param top: Number of faces to return starting with the face id
         indicated by the 'start' parameter.
        :type top: int
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: list or ClientRawResponse if raw=true
        :rtype:
         list[~azure.cognitiveservices.vision.face.models.PersistedFace] or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`APIErrorException<azure.cognitiveservices.vision.face.models.APIErrorException>`
        """
        # Construct URL
        url = self.list_faces.metadata['url']
        path_format_arguments = {
            'Endpoint': self._serialize.url("self.config.endpoint", self.config.endpoint, 'str', skip_quote=True),
            'largeFaceListId': self._serialize.url("large_face_list_id", large_face_list_id, 'str', max_length=64, pattern=r'^[a-z0-9-_]+$')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        if start is not None:
            query_parameters['start'] = self._serialize.query("start", start, 'str')
        if top is not None:
            query_parameters['top'] = self._serialize.query("top", top, 'int', maximum=1000, minimum=1)

        # Construct headers
        header_parameters = {}
        header_parameters['Accept'] = 'application/json'
        if custom_headers:
            header_parameters.update(custom_headers)

        # Construct and send request
        request = self._client.get(url, query_parameters, header_parameters)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200]:
            raise models.APIErrorException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('[PersistedFace]', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    list_faces.metadata = {'url': '/largefacelists/{largeFaceListId}/persistedfaces'}

    def add_face_from_stream(
            self, large_face_list_id, image, user_data=None, target_face=None, custom_headers=None, raw=False, callback=None, **operation_config):
        """Add a face to a large face list. The input face is specified as an
        image with a targetFace rectangle. It returns a persistedFaceId
        representing the added face, and persistedFaceId will not expire.

        :param large_face_list_id: Id referencing a particular large face
         list.
        :type large_face_list_id: str
        :param image: An image stream.
        :type image: Generator
        :param user_data: User-specified data about the face for any purpose.
         The maximum length is 1KB.
        :type user_data: str
        :param target_face: A face rectangle to specify the target face to be
         added to a person in the format of "targetFace=left,top,width,height".
         E.g. "targetFace=10,10,100,100". If there is more than one face in the
         image, targetFace is required to specify which face to add. No
         targetFace means there is only one face detected in the entire image.
        :type target_face: list[int]
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param callback: When specified, will be called with each chunk of
         data that is streamed. The callback should take two arguments, the
         bytes of the current chunk of data and the response object. If the
         data is uploading, response will be None.
        :type callback: Callable[Bytes, response=None]
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: PersistedFace or ClientRawResponse if raw=true
        :rtype: ~azure.cognitiveservices.vision.face.models.PersistedFace or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`APIErrorException<azure.cognitiveservices.vision.face.models.APIErrorException>`
        """
        # Construct URL
        url = self.add_face_from_stream.metadata['url']
        path_format_arguments = {
            'Endpoint': self._serialize.url("self.config.endpoint", self.config.endpoint, 'str', skip_quote=True),
            'largeFaceListId': self._serialize.url("large_face_list_id", large_face_list_id, 'str', max_length=64, pattern=r'^[a-z0-9-_]+$')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        if user_data is not None:
            query_parameters['userData'] = self._serialize.query("user_data", user_data, 'str', max_length=1024)
        if target_face is not None:
            query_parameters['targetFace'] = self._serialize.query("target_face", target_face, '[int]', div=',')

        # Construct headers
        header_parameters = {}
        header_parameters['Accept'] = 'application/json'
        header_parameters['Content-Type'] = 'application/octet-stream'
        if custom_headers:
            header_parameters.update(custom_headers)

        # Construct body
        body_content = self._client.stream_upload(image, callback)

        # Construct and send request
        request = self._client.post(url, query_parameters, header_parameters, body_content)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200]:
            raise models.APIErrorException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('PersistedFace', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    add_face_from_stream.metadata = {'url': '/largefacelists/{largeFaceListId}/persistedfaces'}
