# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator (autorest: 3.0.6246, generator: {generator})
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------
from typing import Any, Callable, Dict, Generic, Optional, TypeVar, Union
import warnings

from azure.core.async_paging import AsyncItemPaged, AsyncList
from azure.core.exceptions import HttpResponseError, ResourceExistsError, ResourceNotFoundError, map_error
from azure.core.pipeline import PipelineResponse
from azure.core.pipeline.transport import AsyncHttpResponse, HttpRequest
from azure.core.polling import AsyncNoPolling, AsyncPollingMethod, async_poller

from ... import models

T = TypeVar('T')
ClsType = Optional[Callable[[PipelineResponse[HttpRequest, AsyncHttpResponse], T, Dict[str, Any]], Any]]

class FormRecognizerClientOperationsMixin:

    async def train_custom_model_async(
        self,
        train_request: "models.TrainRequest",
        **kwargs
    ) -> None:
        """Create and train a custom model. The request must include a source parameter that is either an externally accessible Azure storage blob container Uri (preferably a Shared Access Signature Uri) or valid path to a data folder in a locally mounted drive. When local paths are specified, they must follow the Linux/Unix path format and be an absolute path rooted to the input mount configuration setting value e.g., if '{Mounts:Input}' configuration setting value is '/input' then a valid source path would be '/input/contosodataset'. All data to be trained is expected to be under the source folder or sub folders under it. Models are trained using documents that are of the following content type - 'application/pdf', 'image/jpeg', 'image/png', 'image/tiff'. Other type of content is ignored.

        Train Custom Model.

        :param train_request: Training request parameters.
        :type train_request: ~azure.ai.formrecognizer.models.TrainRequest
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: None or the result of cls(response)
        :rtype: None
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType[None]
        error_map = kwargs.pop('error_map', {404: ResourceNotFoundError, 409: ResourceExistsError})

        # Construct URL
        url = self.train_custom_model_async.metadata['url']
        path_format_arguments = {
            'endpoint': self._serialize.url("self._config.endpoint", self._config.endpoint, 'str', skip_quote=True),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Content-Type'] = kwargs.pop('content_type', 'application/json')

        # Construct and send request
        body_content_kwargs = {}  # type: Dict[str, Any]
        body_content = self._serialize.body(train_request, 'TrainRequest')
        body_content_kwargs['content'] = body_content
        request = self._client.post(url, query_parameters, header_parameters, **body_content_kwargs)

        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [201]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize(models.ErrorResponse, response)
            raise HttpResponseError(response=response, model=error)

        response_headers = {}
        response_headers['Location']=self._deserialize('str', response.headers.get('Location'))

        if cls:
          return cls(pipeline_response, None, response_headers)

    train_custom_model_async.metadata = {'url': '/custom/models'}

    async def get_custom_model(
        self,
        model_id: str,
        include_keys: Optional[bool] = False,
        **kwargs
    ) -> "models.Model":
        """Get detailed information about a custom model.

        Get Custom Model.

        :param model_id: Model identifier.
        :type model_id: str
        :param include_keys: Include list of extracted keys in model information.
        :type include_keys: bool
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: Model or the result of cls(response)
        :rtype: ~azure.ai.formrecognizer.models.Model
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["models.Model"]
        error_map = kwargs.pop('error_map', {404: ResourceNotFoundError, 409: ResourceExistsError})

        # Construct URL
        url = self.get_custom_model.metadata['url']
        path_format_arguments = {
            'endpoint': self._serialize.url("self._config.endpoint", self._config.endpoint, 'str', skip_quote=True),
            'modelId': self._serialize.url("model_id", model_id, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        if include_keys is not None:
            query_parameters['includeKeys'] = self._serialize.query("include_keys", include_keys, 'bool')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Accept'] = 'application/json'

        # Construct and send request
        request = self._client.get(url, query_parameters, header_parameters)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize(models.ErrorResponse, response)
            raise HttpResponseError(response=response, model=error)

        deserialized = self._deserialize('Model', pipeline_response)

        if cls:
          return cls(pipeline_response, deserialized, {})

        return deserialized
    get_custom_model.metadata = {'url': '/custom/models/{modelId}'}

    async def delete_custom_model(
        self,
        model_id: str,
        **kwargs
    ) -> None:
        """Mark model for deletion. Model artifacts will be permanently removed within a predetermined period.

        Delete Custom Model.

        :param model_id: Model identifier.
        :type model_id: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: None or the result of cls(response)
        :rtype: None
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType[None]
        error_map = kwargs.pop('error_map', {404: ResourceNotFoundError, 409: ResourceExistsError})

        # Construct URL
        url = self.delete_custom_model.metadata['url']
        path_format_arguments = {
            'endpoint': self._serialize.url("self._config.endpoint", self._config.endpoint, 'str', skip_quote=True),
            'modelId': self._serialize.url("model_id", model_id, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]

        # Construct and send request
        request = self._client.delete(url, query_parameters, header_parameters)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [204]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize(models.ErrorResponse, response)
            raise HttpResponseError(response=response, model=error)

        if cls:
          return cls(pipeline_response, None, {})

    delete_custom_model.metadata = {'url': '/custom/models/{modelId}'}

    async def _analyze_with_custom_model_initial(
        self,
        model_id: str,
        include_text_details: Optional[bool] = False,
        file_stream: Optional[Union[str, "models.SourcePath"]] = None,
        **kwargs
    ) -> None:
        cls = kwargs.pop('cls', None)  # type: ClsType[None]
        error_map = kwargs.pop('error_map', {404: ResourceNotFoundError, 409: ResourceExistsError})

        # Construct URL
        url = self._analyze_with_custom_model_initial.metadata['url']
        path_format_arguments = {
            'endpoint': self._serialize.url("self._config.endpoint", self._config.endpoint, 'str', skip_quote=True),
            'modelId': self._serialize.url("model_id", model_id, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        if include_text_details is not None:
            query_parameters['includeTextDetails'] = self._serialize.query("include_text_details", include_text_details, 'bool')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Content-Type'] = kwargs.pop('content_type', 'application/json')

        # Construct and send request
        body_content_kwargs = {}  # type: Dict[str, Any]
        if header_parameters['Content-Type'] in ['application/pdf', 'image/jpeg', 'image/png', 'image/tiff']:
            body_content_kwargs['stream_content'] = file_stream
        elif header_parameters['Content-Type'] in ['application/json']:
            if file_stream is not None:
                body_content = self._serialize.body(file_stream, 'SourcePath')
            else:
                body_content = None
            body_content_kwargs['content'] = body_content
        else:
            raise ValueError(
                "Content type {} is not valid for this operation".format(header_parameters['Content-Type'])
            )
        request = self._client.post(url, query_parameters, header_parameters, **body_content_kwargs)

        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [202]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize(models.ErrorResponse, response)
            raise HttpResponseError(response=response, model=error)

        response_headers = {}
        response_headers['Operation-Location']=self._deserialize('str', response.headers.get('Operation-Location'))

        if cls:
          return cls(pipeline_response, None, response_headers)

    _analyze_with_custom_model_initial.metadata = {'url': '/custom/models/{modelId}/analyze'}

    async def analyze_with_custom_model(
        self,
        model_id: str,
        include_text_details: Optional[bool] = False,
        file_stream: Optional[Union[str, "models.SourcePath"]] = None,
        **kwargs
    ) -> None:
        """Extract key-value pairs, tables, and semantic values from a given document. The input document must be of one of the supported content types - 'application/pdf', 'image/jpeg', 'image/png' or 'image/tiff'. Alternatively, use 'application/json' type to specify the location (Uri or local path) of the document to be analyzed.

        Analyze Form.

        :param model_id: Model identifier.
        :type model_id: str
        :param include_text_details: Include text lines and element references in the result.
        :type include_text_details: bool
        :param file_stream: .json, .pdf, .jpg, .png or .tiff type file stream.
        :type file_stream: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :keyword polling: True for ARMPolling, False for no polling, or a
         polling object for personal polling strategy
        :paramtype polling: bool or ~azure.core.polling.AsyncPollingMethod
        :return: An instance of LROPoller that returns None
        :rtype: ~azure.core.polling.LROPoller[None]

        :raises ~azure.core.exceptions.HttpResponseError:
        """
        polling = kwargs.pop('polling', False)  # type: Union[bool, AsyncPollingMethod]
        cls = kwargs.pop('cls', None)  # type: ClsType[None]
        raw_result = await self._analyze_with_custom_model_initial(
            model_id=model_id,
            include_text_details=include_text_details,
            file_stream=file_stream,
            cls=lambda x,y,z: x,
            **kwargs
        )

        def get_long_running_output(pipeline_response):
            if cls:
                return cls(pipeline_response, None, {})

        lro_delay = kwargs.get(
            'polling_interval',
            self._config.polling_interval
        )
        if polling is True: raise ValueError("polling being True is not valid because no default polling implemetation has been defined.")
        elif polling is False: polling_method = AsyncNoPolling()
        else: polling_method = polling
        return await async_poller(self._client, raw_result, get_long_running_output, polling_method)
    analyze_with_custom_model.metadata = {'url': '/custom/models/{modelId}/analyze'}

    async def get_analyze_form_result(
        self,
        model_id: str,
        result_id: str,
        **kwargs
    ) -> "models.AnalyzeOperationResult":
        """Obtain current status and the result of the analyze form operation.

        Get Analyze Form Result.

        :param model_id: Model identifier.
        :type model_id: str
        :param result_id: Analyze operation result identifier.
        :type result_id: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: AnalyzeOperationResult or the result of cls(response)
        :rtype: ~azure.ai.formrecognizer.models.AnalyzeOperationResult
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["models.AnalyzeOperationResult"]
        error_map = kwargs.pop('error_map', {404: ResourceNotFoundError, 409: ResourceExistsError})

        # Construct URL
        url = self.get_analyze_form_result.metadata['url']
        path_format_arguments = {
            'endpoint': self._serialize.url("self._config.endpoint", self._config.endpoint, 'str', skip_quote=True),
            'modelId': self._serialize.url("model_id", model_id, 'str'),
            'resultId': self._serialize.url("result_id", result_id, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Accept'] = 'application/json'

        # Construct and send request
        request = self._client.get(url, query_parameters, header_parameters)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize(models.ErrorResponse, response)
            raise HttpResponseError(response=response, model=error)

        deserialized = self._deserialize('AnalyzeOperationResult', pipeline_response)

        if cls:
          return cls(pipeline_response, deserialized, {})

        return deserialized
    get_analyze_form_result.metadata = {'url': '/custom/models/{modelId}/analyzeResults/{resultId}'}

    async def _analyze_receipt_async_initial(
        self,
        include_text_details: Optional[bool] = False,
        file_stream: Optional[Union[str, "models.SourcePath"]] = None,
        **kwargs
    ) -> None:
        cls = kwargs.pop('cls', None)  # type: ClsType[None]
        error_map = kwargs.pop('error_map', {404: ResourceNotFoundError, 409: ResourceExistsError})

        # Construct URL
        url = self._analyze_receipt_async_initial.metadata['url']
        path_format_arguments = {
            'endpoint': self._serialize.url("self._config.endpoint", self._config.endpoint, 'str', skip_quote=True),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        if include_text_details is not None:
            query_parameters['includeTextDetails'] = self._serialize.query("include_text_details", include_text_details, 'bool')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Content-Type'] = kwargs.pop('content_type', 'application/json')

        # Construct and send request
        body_content_kwargs = {}  # type: Dict[str, Any]
        if header_parameters['Content-Type'] in ['application/pdf', 'image/jpeg', 'image/png', 'image/tiff']:
            body_content_kwargs['stream_content'] = file_stream
        elif header_parameters['Content-Type'] in ['application/json']:
            if file_stream is not None:
                body_content = self._serialize.body(file_stream, 'SourcePath')
            else:
                body_content = None
            body_content_kwargs['content'] = body_content
        else:
            raise ValueError(
                "Content type {} is not valid for this operation".format(header_parameters['Content-Type'])
            )
        request = self._client.post(url, query_parameters, header_parameters, **body_content_kwargs)

        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [202]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize(models.ErrorResponse, response)
            raise HttpResponseError(response=response, model=error)

        response_headers = {}
        response_headers['Operation-Location']=self._deserialize('str', response.headers.get('Operation-Location'))

        if cls:
          return cls(pipeline_response, None, response_headers)

    _analyze_receipt_async_initial.metadata = {'url': '/prebuilt/receipt/analyze'}

    async def analyze_receipt_async(
        self,
        include_text_details: Optional[bool] = False,
        file_stream: Optional[Union[str, "models.SourcePath"]] = None,
        **kwargs
    ) -> None:
        """Extract field text and semantic values from a given receipt document. The input document must be of one of the supported content types - 'application/pdf', 'image/jpeg', 'image/png' or 'image/tiff'. Alternatively, use 'application/json' type to specify the location (Uri or local path) of the document to be analyzed.

        Analyze Receipt.

        :param include_text_details: Include text lines and element references in the result.
        :type include_text_details: bool
        :param file_stream: .json, .pdf, .jpg, .png or .tiff type file stream.
        :type file_stream: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :keyword polling: True for ARMPolling, False for no polling, or a
         polling object for personal polling strategy
        :paramtype polling: bool or ~azure.core.polling.AsyncPollingMethod
        :return: An instance of LROPoller that returns None
        :rtype: ~azure.core.polling.LROPoller[None]

        :raises ~azure.core.exceptions.HttpResponseError:
        """
        polling = kwargs.pop('polling', False)  # type: Union[bool, AsyncPollingMethod]
        cls = kwargs.pop('cls', None)  # type: ClsType[None]
        raw_result = await self._analyze_receipt_async_initial(
            include_text_details=include_text_details,
            file_stream=file_stream,
            cls=lambda x,y,z: x,
            **kwargs
        )

        def get_long_running_output(pipeline_response):
            if cls:
                return cls(pipeline_response, None, {})

        lro_delay = kwargs.get(
            'polling_interval',
            self._config.polling_interval
        )
        if polling is True: raise ValueError("polling being True is not valid because no default polling implemetation has been defined.")
        elif polling is False: polling_method = AsyncNoPolling()
        else: polling_method = polling
        return await async_poller(self._client, raw_result, get_long_running_output, polling_method)
    analyze_receipt_async.metadata = {'url': '/prebuilt/receipt/analyze'}

    async def get_analyze_receipt_result(
        self,
        result_id: str,
        **kwargs
    ) -> "models.AnalyzeOperationResult":
        """Track the progress and obtain the result of the analyze receipt operation.

        Get Analyze Receipt Result.

        :param result_id: Analyze operation result identifier.
        :type result_id: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: AnalyzeOperationResult or the result of cls(response)
        :rtype: ~azure.ai.formrecognizer.models.AnalyzeOperationResult
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["models.AnalyzeOperationResult"]
        error_map = kwargs.pop('error_map', {404: ResourceNotFoundError, 409: ResourceExistsError})

        # Construct URL
        url = self.get_analyze_receipt_result.metadata['url']
        path_format_arguments = {
            'endpoint': self._serialize.url("self._config.endpoint", self._config.endpoint, 'str', skip_quote=True),
            'resultId': self._serialize.url("result_id", result_id, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Accept'] = 'application/json'

        # Construct and send request
        request = self._client.get(url, query_parameters, header_parameters)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize(models.ErrorResponse, response)
            raise HttpResponseError(response=response, model=error)

        deserialized = self._deserialize('AnalyzeOperationResult', pipeline_response)

        if cls:
          return cls(pipeline_response, deserialized, {})

        return deserialized
    get_analyze_receipt_result.metadata = {'url': '/prebuilt/receipt/analyzeResults/{resultId}'}

    async def _analyze_layout_async_initial(
        self,
        file_stream: Optional[Union[str, "models.SourcePath"]] = None,
        **kwargs
    ) -> None:
        cls = kwargs.pop('cls', None)  # type: ClsType[None]
        error_map = kwargs.pop('error_map', {404: ResourceNotFoundError, 409: ResourceExistsError})

        # Construct URL
        url = self._analyze_layout_async_initial.metadata['url']
        path_format_arguments = {
            'endpoint': self._serialize.url("self._config.endpoint", self._config.endpoint, 'str', skip_quote=True),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Content-Type'] = kwargs.pop('content_type', 'application/json')

        # Construct and send request
        body_content_kwargs = {}  # type: Dict[str, Any]
        if header_parameters['Content-Type'] in ['application/pdf', 'image/jpeg', 'image/png', 'image/tiff']:
            body_content_kwargs['stream_content'] = file_stream
        elif header_parameters['Content-Type'] in ['application/json']:
            if file_stream is not None:
                body_content = self._serialize.body(file_stream, 'SourcePath')
            else:
                body_content = None
            body_content_kwargs['content'] = body_content
        else:
            raise ValueError(
                "Content type {} is not valid for this operation".format(header_parameters['Content-Type'])
            )
        request = self._client.post(url, query_parameters, header_parameters, **body_content_kwargs)

        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [202]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize(models.ErrorResponse, response)
            raise HttpResponseError(response=response, model=error)

        response_headers = {}
        response_headers['Operation-Location']=self._deserialize('str', response.headers.get('Operation-Location'))

        if cls:
          return cls(pipeline_response, None, response_headers)

    _analyze_layout_async_initial.metadata = {'url': '/layout/analyze'}

    async def analyze_layout_async(
        self,
        file_stream: Optional[Union[str, "models.SourcePath"]] = None,
        **kwargs
    ) -> None:
        """Extract text and layout information from a given document. The input document must be of one of the supported content types - 'application/pdf', 'image/jpeg', 'image/png' or 'image/tiff'. Alternatively, use 'application/json' type to specify the location (Uri or local path) of the document to be analyzed.

        Analyze Layout.

        :param file_stream: .json, .pdf, .jpg, .png or .tiff type file stream.
        :type file_stream: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :keyword polling: True for ARMPolling, False for no polling, or a
         polling object for personal polling strategy
        :paramtype polling: bool or ~azure.core.polling.AsyncPollingMethod
        :return: An instance of LROPoller that returns None
        :rtype: ~azure.core.polling.LROPoller[None]

        :raises ~azure.core.exceptions.HttpResponseError:
        """
        polling = kwargs.pop('polling', False)  # type: Union[bool, AsyncPollingMethod]
        cls = kwargs.pop('cls', None)  # type: ClsType[None]
        raw_result = await self._analyze_layout_async_initial(
            file_stream=file_stream,
            cls=lambda x,y,z: x,
            **kwargs
        )

        def get_long_running_output(pipeline_response):
            if cls:
                return cls(pipeline_response, None, {})

        lro_delay = kwargs.get(
            'polling_interval',
            self._config.polling_interval
        )
        if polling is True: raise ValueError("polling being True is not valid because no default polling implemetation has been defined.")
        elif polling is False: polling_method = AsyncNoPolling()
        else: polling_method = polling
        return await async_poller(self._client, raw_result, get_long_running_output, polling_method)
    analyze_layout_async.metadata = {'url': '/layout/analyze'}

    async def get_analyze_layout_result(
        self,
        result_id: str,
        **kwargs
    ) -> "models.AnalyzeOperationResult":
        """Track the progress and obtain the result of the analyze layout operation.

        Get Analyze Layout Result.

        :param result_id: Analyze operation result identifier.
        :type result_id: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: AnalyzeOperationResult or the result of cls(response)
        :rtype: ~azure.ai.formrecognizer.models.AnalyzeOperationResult
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["models.AnalyzeOperationResult"]
        error_map = kwargs.pop('error_map', {404: ResourceNotFoundError, 409: ResourceExistsError})

        # Construct URL
        url = self.get_analyze_layout_result.metadata['url']
        path_format_arguments = {
            'endpoint': self._serialize.url("self._config.endpoint", self._config.endpoint, 'str', skip_quote=True),
            'resultId': self._serialize.url("result_id", result_id, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Accept'] = 'application/json'

        # Construct and send request
        request = self._client.get(url, query_parameters, header_parameters)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize(models.ErrorResponse, response)
            raise HttpResponseError(response=response, model=error)

        deserialized = self._deserialize('AnalyzeOperationResult', pipeline_response)

        if cls:
          return cls(pipeline_response, deserialized, {})

        return deserialized
    get_analyze_layout_result.metadata = {'url': '/layout/analyzeResults/{resultId}'}

    def list_custom_models(
        self,
        **kwargs
    ) -> "models.Models":
        """Get information about all custom models.

        List Custom Models.

        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: Models or the result of cls(response)
        :rtype: ~azure.ai.formrecognizer.models.Models
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["models.Models"]
        error_map = kwargs.pop('error_map', {404: ResourceNotFoundError, 409: ResourceExistsError})
        op = "full"

        def prepare_request(next_link=None):
            if not next_link:
                # Construct URL
                url = self.list_custom_models.metadata['url']
                path_format_arguments = {
                    'endpoint': self._serialize.url("self._config.endpoint", self._config.endpoint, 'str', skip_quote=True),
                }
                url = self._client.format_url(url, **path_format_arguments)
            else:
                url = next_link
                path_format_arguments = {
                    'endpoint': self._serialize.url("self._config.endpoint", self._config.endpoint, 'str', skip_quote=True),
                }
                url = self._client.format_url(url, **path_format_arguments)

            # Construct parameters
            query_parameters = {}  # type: Dict[str, Any]
            query_parameters['op'] = self._serialize.query("op", op, 'str')

            # Construct headers
            header_parameters = {}  # type: Dict[str, Any]
            header_parameters['Accept'] = 'application/json'

            # Construct and send request
            request = self._client.get(url, query_parameters, header_parameters)
            return request

        async def extract_data(pipeline_response):
            deserialized = self._deserialize('Models', pipeline_response)
            list_of_elem = deserialized.model_list
            if cls:
                list_of_elem = cls(list_of_elem)
            return deserialized.next_link or None, AsyncList(list_of_elem)

        async def get_next(next_link=None):
            request = prepare_request(next_link)

            pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
            response = pipeline_response.http_response

            if response.status_code not in [200]:
                error = self._deserialize(models.ErrorResponse, response)
                map_error(status_code=response.status_code, response=response, error_map=error_map)
                raise HttpResponseError(response=response, model=error)

            return pipeline_response

        return AsyncItemPaged(
            get_next, extract_data
        )
    list_custom_models.metadata = {'url': '/custom/models'}

    async def get_custom_models(
        self,
        **kwargs
    ) -> "models.Models":
        """Get information about all custom models.

        Get Custom Models.

        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: Models or the result of cls(response)
        :rtype: ~azure.ai.formrecognizer.models.Models
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["models.Models"]
        error_map = kwargs.pop('error_map', {404: ResourceNotFoundError, 409: ResourceExistsError})
        op = "summary"

        # Construct URL
        url = self.get_custom_models.metadata['url']
        path_format_arguments = {
            'endpoint': self._serialize.url("self._config.endpoint", self._config.endpoint, 'str', skip_quote=True),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['op'] = self._serialize.query("op", op, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Accept'] = 'application/json'

        # Construct and send request
        request = self._client.get(url, query_parameters, header_parameters)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize(models.ErrorResponse, response)
            raise HttpResponseError(response=response, model=error)

        deserialized = self._deserialize('Models', pipeline_response)

        if cls:
          return cls(pipeline_response, deserialized, {})

        return deserialized
    get_custom_models.metadata = {'url': '/custom/models'}
