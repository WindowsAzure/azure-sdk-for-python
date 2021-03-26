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


class FaceListOperations(object):
    """FaceListOperations operations.

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

    def create(
            self, face_list_id, name=None, user_data=None, recognition_model="recognition_01", custom_headers=None, raw=False, **operation_config):
        """Create an empty face list with user-specified faceListId, name, an
        optional userData and recognitionModel. Up to 64 face lists are allowed
        in one subscription.
        <br /> Face list is a list of faces, up to 1,000 faces, and used by
        [Face - Find
        Similar](https://docs.microsoft.com/rest/api/faceapi/face/findsimilar).
        <br /> After creation, user should use [FaceList - Add
        Face](https://docs.microsoft.com/rest/api/faceapi/facelist/addfacefromurl)
        to import the faces. No image will be stored. Only the extracted face
        features are stored on server until [FaceList -
        Delete](https://docs.microsoft.com/rest/api/faceapi/facelist/delete) is
        called.
        <br /> Find Similar is used for scenario like finding celebrity-like
        faces, similar face filtering, or as a light way face identification.
        But if the actual use is to identify person, please use
        [PersonGroup](https://docs.microsoft.com/rest/api/faceapi/persongroup)
        /
        [LargePersonGroup](https://docs.microsoft.com/rest/api/faceapi/largepersongroup)
        and [Face -
        Identify](https://docs.microsoft.com/rest/api/faceapi/face/identify).
        <br /> Please consider
        [LargeFaceList](https://docs.microsoft.com/rest/api/faceapi/largefacelist)
        when the face number is large. It can support up to 1,000,000 faces.
        <br />'recognitionModel' should be specified to associate with this
        face list. The default value for 'recognitionModel' is
        'recognition_01', if the latest model needed, please explicitly specify
        the model you need in this parameter. New faces that are added to an
        existing face list will use the recognition model that's already
        associated with the collection. Existing face features in a face list
        can't be updated to features extracted by another version of
        recognition model.
        Please Refer to [Specify a face recognition
        model](https://docs.microsoft.com/azure/cognitive-services/face/face-api-how-to-topics/specify-recognition-model).

        :param face_list_id: Id referencing a particular face list.
        :type face_list_id: str
        :param name: User defined name, maximum length is 128.
        :type name: str
        :param user_data: User specified data. Length should not exceed 16KB.
        :type user_data: str
        :param recognition_model: Possible values include: 'recognition_01',
         'recognition_02', 'recognition_03', 'recognition_04'
        :type recognition_model: str or
         ~azure.cognitiveservices.vision.face.models.RecognitionModel
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
        body = models.MetaDataContract(name=name, user_data=user_data, recognition_model=recognition_model)

        # Construct URL
        url = self.create.metadata['url']
        path_format_arguments = {
            'Endpoint': self._serialize.url("self.config.endpoint", self.config.endpoint, 'str', skip_quote=True),
            'faceListId': self._serialize.url("face_list_id", face_list_id, 'str', max_length=64, pattern=r'^[a-z0-9-_]+$')
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
        body_content = self._serialize.body(body, 'MetaDataContract')

        # Construct and send request
        request = self._client.put(url, query_parameters, header_parameters, body_content)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200]:
            raise models.APIErrorException(self._deserialize, response)

        if raw:
            client_raw_response = ClientRawResponse(None, response)
            return client_raw_response
    create.metadata = {'url': '/facelists/{faceListId}'}

    def get(
            self, face_list_id, return_recognition_model=False, custom_headers=None, raw=False, **operation_config):
        """Retrieve a face list’s faceListId, name, userData, recognitionModel and
        faces in the face list.
        .

        :param face_list_id: Id referencing a particular face list.
        :type face_list_id: str
        :param return_recognition_model: A value indicating whether the
         operation should return 'recognitionModel' in response.
        :type return_recognition_model: bool
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: FaceList or ClientRawResponse if raw=true
        :rtype: ~azure.cognitiveservices.vision.face.models.FaceList or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`APIErrorException<azure.cognitiveservices.vision.face.models.APIErrorException>`
        """
        # Construct URL
        url = self.get.metadata['url']
        path_format_arguments = {
            'Endpoint': self._serialize.url("self.config.endpoint", self.config.endpoint, 'str', skip_quote=True),
            'faceListId': self._serialize.url("face_list_id", face_list_id, 'str', max_length=64, pattern=r'^[a-z0-9-_]+$')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        if return_recognition_model is not None:
            query_parameters['returnRecognitionModel'] = self._serialize.query("return_recognition_model", return_recognition_model, 'bool')

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
            deserialized = self._deserialize('FaceList', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    get.metadata = {'url': '/facelists/{faceListId}'}

    def update(
            self, face_list_id, name=None, user_data=None, custom_headers=None, raw=False, **operation_config):
        """Update information of a face list.

        :param face_list_id: Id referencing a particular face list.
        :type face_list_id: str
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
            'faceListId': self._serialize.url("face_list_id", face_list_id, 'str', max_length=64, pattern=r'^[a-z0-9-_]+$')
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
    update.metadata = {'url': '/facelists/{faceListId}'}

    def delete(
            self, face_list_id, custom_headers=None, raw=False, **operation_config):
        """Delete a specified face list.

        :param face_list_id: Id referencing a particular face list.
        :type face_list_id: str
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
            'faceListId': self._serialize.url("face_list_id", face_list_id, 'str', max_length=64, pattern=r'^[a-z0-9-_]+$')
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
    delete.metadata = {'url': '/facelists/{faceListId}'}

    def list(
            self, return_recognition_model=False, custom_headers=None, raw=False, **operation_config):
        """List face lists’ faceListId, name, userData and recognitionModel. <br
        />
        To get face information inside faceList use [FaceList -
        Get](https://docs.microsoft.com/rest/api/faceapi/facelist/get)
        .

        :param return_recognition_model: A value indicating whether the
         operation should return 'recognitionModel' in response.
        :type return_recognition_model: bool
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: list or ClientRawResponse if raw=true
        :rtype: list[~azure.cognitiveservices.vision.face.models.FaceList] or
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
        if return_recognition_model is not None:
            query_parameters['returnRecognitionModel'] = self._serialize.query("return_recognition_model", return_recognition_model, 'bool')

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
            deserialized = self._deserialize('[FaceList]', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    list.metadata = {'url': '/facelists'}

    def delete_face(
            self, face_list_id, persisted_face_id, custom_headers=None, raw=False, **operation_config):
        """Delete a face from a face list by specified faceListId and
        persistedFaceId.
        <br /> Adding/deleting faces to/from a same face list are processed
        sequentially and to/from different face lists are in parallel.

        :param face_list_id: Id referencing a particular face list.
        :type face_list_id: str
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
            'faceListId': self._serialize.url("face_list_id", face_list_id, 'str', max_length=64, pattern=r'^[a-z0-9-_]+$'),
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
    delete_face.metadata = {'url': '/facelists/{faceListId}/persistedfaces/{persistedFaceId}'}

    def add_face_from_url(
            self, face_list_id, url, user_data=None, target_face=None, detection_model="detection_01", custom_headers=None, raw=False, **operation_config):
        """Add a face to a specified face list, up to 1,000 faces.
        <br /> To deal with an image contains multiple faces, input face can be
        specified as an image with a targetFace rectangle. It returns a
        persistedFaceId representing the added face. No image will be stored.
        Only the extracted face feature will be stored on server until
        [FaceList - Delete
        Face](https://docs.microsoft.com/rest/api/faceapi/facelist/deleteface)
        or [FaceList -
        Delete](https://docs.microsoft.com/rest/api/faceapi/facelist/delete) is
        called.
        <br /> Note persistedFaceId is different from faceId generated by [Face
        -
        Detect](https://docs.microsoft.com/rest/api/faceapi/face/detectwithurl).
        * Higher face image quality means better detection and recognition
        precision. Please consider high-quality faces: frontal, clear, and face
        size is 200x200 pixels (100 pixels between eyes) or bigger.
        * JPEG, PNG, GIF (the first frame), and BMP format are supported. The
        allowed image file size is from 1KB to 6MB.
        * "targetFace" rectangle should contain one face. Zero or multiple
        faces will be regarded as an error. If the provided "targetFace"
        rectangle is not returned from [Face -
        Detect](https://docs.microsoft.com/rest/api/faceapi/face/detectwithurl),
        there’s no guarantee to detect and add the face successfully.
        * Out of detectable face size (36x36 - 4096x4096 pixels), large
        head-pose, or large occlusions will cause failures.
        * Adding/deleting faces to/from a same face list are processed
        sequentially and to/from different face lists are in parallel.
        * The minimum detectable face size is 36x36 pixels in an image no
        larger than 1920x1080 pixels. Images with dimensions higher than
        1920x1080 pixels will need a proportionally larger minimum face size.
        * Different 'detectionModel' values can be provided. To use and compare
        different detection models, please refer to [How to specify a detection
        model](https://docs.microsoft.com/azure/cognitive-services/face/face-api-how-to-topics/specify-detection-model).

        :param face_list_id: Id referencing a particular face list.
        :type face_list_id: str
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
        :param detection_model: Name of detection model. Detection model is
         used to detect faces in the submitted image. A detection model name
         can be provided when performing Face - Detect or (Large)FaceList - Add
         Face or (Large)PersonGroup - Add Face. The default value is
         'detection_01', if another model is needed, please explicitly specify
         it. Possible values include: 'detection_01', 'detection_02',
         'detection_03'
        :type detection_model: str or
         ~azure.cognitiveservices.vision.face.models.DetectionModel
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
            'faceListId': self._serialize.url("face_list_id", face_list_id, 'str', max_length=64, pattern=r'^[a-z0-9-_]+$')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        if user_data is not None:
            query_parameters['userData'] = self._serialize.query("user_data", user_data, 'str', max_length=1024)
        if target_face is not None:
            query_parameters['targetFace'] = self._serialize.query("target_face", target_face, '[int]', div=',')
        if detection_model is not None:
            query_parameters['detectionModel'] = self._serialize.query("detection_model", detection_model, 'str')

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
    add_face_from_url.metadata = {'url': '/facelists/{faceListId}/persistedfaces'}

    def add_face_from_stream(
            self, face_list_id, image, user_data=None, target_face=None, detection_model="detection_01", custom_headers=None, raw=False, callback=None, **operation_config):
        """Add a face to a specified face list, up to 1,000 faces.
        <br /> To deal with an image contains multiple faces, input face can be
        specified as an image with a targetFace rectangle. It returns a
        persistedFaceId representing the added face. No image will be stored.
        Only the extracted face feature will be stored on server until
        [FaceList - Delete
        Face](https://docs.microsoft.com/rest/api/faceapi/facelist/deleteface)
        or [FaceList -
        Delete](https://docs.microsoft.com/rest/api/faceapi/facelist/delete) is
        called.
        <br /> Note persistedFaceId is different from faceId generated by [Face
        -
        Detect](https://docs.microsoft.com/rest/api/faceapi/face/detectwithurl).
        * Higher face image quality means better detection and recognition
        precision. Please consider high-quality faces: frontal, clear, and face
        size is 200x200 pixels (100 pixels between eyes) or bigger.
        * JPEG, PNG, GIF (the first frame), and BMP format are supported. The
        allowed image file size is from 1KB to 6MB.
        * "targetFace" rectangle should contain one face. Zero or multiple
        faces will be regarded as an error. If the provided "targetFace"
        rectangle is not returned from [Face -
        Detect](https://docs.microsoft.com/rest/api/faceapi/face/detectwithurl),
        there’s no guarantee to detect and add the face successfully.
        * Out of detectable face size (36x36 - 4096x4096 pixels), large
        head-pose, or large occlusions will cause failures.
        * Adding/deleting faces to/from a same face list are processed
        sequentially and to/from different face lists are in parallel.
        * The minimum detectable face size is 36x36 pixels in an image no
        larger than 1920x1080 pixels. Images with dimensions higher than
        1920x1080 pixels will need a proportionally larger minimum face size.
        * Different 'detectionModel' values can be provided. To use and compare
        different detection models, please refer to [How to specify a detection
        model](https://docs.microsoft.com/azure/cognitive-services/face/face-api-how-to-topics/specify-detection-model).

        :param face_list_id: Id referencing a particular face list.
        :type face_list_id: str
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
        :param detection_model: Name of detection model. Detection model is
         used to detect faces in the submitted image. A detection model name
         can be provided when performing Face - Detect or (Large)FaceList - Add
         Face or (Large)PersonGroup - Add Face. The default value is
         'detection_01', if another model is needed, please explicitly specify
         it. Possible values include: 'detection_01', 'detection_02',
         'detection_03'
        :type detection_model: str or
         ~azure.cognitiveservices.vision.face.models.DetectionModel
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
            'faceListId': self._serialize.url("face_list_id", face_list_id, 'str', max_length=64, pattern=r'^[a-z0-9-_]+$')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        if user_data is not None:
            query_parameters['userData'] = self._serialize.query("user_data", user_data, 'str', max_length=1024)
        if target_face is not None:
            query_parameters['targetFace'] = self._serialize.query("target_face", target_face, '[int]', div=',')
        if detection_model is not None:
            query_parameters['detectionModel'] = self._serialize.query("detection_model", detection_model, 'str')

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
    add_face_from_stream.metadata = {'url': '/facelists/{faceListId}/persistedfaces'}
