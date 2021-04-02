# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator (autorest: 3.2.1, generator: {generator})
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------
from typing import TYPE_CHECKING
import warnings

from azure.core.exceptions import ClientAuthenticationError, HttpResponseError, ResourceExistsError, ResourceNotFoundError, map_error
from azure.core.paging import ItemPaged
from azure.core.pipeline import PipelineResponse
from azure.core.pipeline.transport import HttpRequest, HttpResponse

from .. import models as _models

if TYPE_CHECKING:
    # pylint: disable=unused-import,ungrouped-imports
    from typing import Any, Callable, Dict, Generic, Iterable, Optional, TypeVar

    T = TypeVar('T')
    ClsType = Optional[Callable[[PipelineResponse[HttpRequest, HttpResponse], T, Dict[str, Any]], Any]]

class ContainerRegistryRepositoryOperations(object):
    """ContainerRegistryRepositoryOperations operations.

    You should not instantiate this class directly. Instead, you should create a Client instance that
    instantiates it for you and attaches it as an attribute.

    :ivar models: Alias to model classes used in this operation group.
    :type models: ~container_registry.models
    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An object model deserializer.
    """

    models = _models

    def __init__(self, client, config, serializer, deserializer):
        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer
        self._config = config

    def get_manifest(
        self,
        name,  # type: str
        reference,  # type: str
        accept=None,  # type: Optional[str]
        **kwargs  # type: Any
    ):
        # type: (...) -> "_models.Manifest"
        """Get the manifest identified by ``name`` and ``reference`` where ``reference`` can be a tag or
        digest.

        :param name: Name of the image (including the namespace).
        :type name: str
        :param reference: A tag or a digest, pointing to a specific image.
        :type reference: str
        :param accept: Accept header string delimited by comma. For example,
         application/vnd.docker.distribution.manifest.v2+json.
        :type accept: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: Manifest, or the result of cls(response)
        :rtype: ~container_registry.models.Manifest
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.Manifest"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        accept = "application/json"

        # Construct URL
        url = self.get_manifest.metadata['url']  # type: ignore
        path_format_arguments = {
            'url': self._serialize.url("self._config.url", self._config.url, 'str', skip_quote=True),
            'name': self._serialize.url("name", name, 'str'),
            'reference': self._serialize.url("reference", reference, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        if accept is not None:
            header_parameters['accept'] = self._serialize.header("accept", accept, 'str')
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        request = self._client.get(url, query_parameters, header_parameters)
        pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize.failsafe_deserialize(_models.AcrErrors, response)
            raise HttpResponseError(response=response, model=error)

        deserialized = self._deserialize('Manifest', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    get_manifest.metadata = {'url': '/v2/{name}/manifests/{reference}'}  # type: ignore

    def create_manifest(
        self,
        name,  # type: str
        reference,  # type: str
        payload,  # type: "_models.Manifest"
        **kwargs  # type: Any
    ):
        # type: (...) -> object
        """Put the manifest identified by ``name`` and ``reference`` where ``reference`` can be a tag or
        digest.

        :param name: Name of the image (including the namespace).
        :type name: str
        :param reference: A tag or a digest, pointing to a specific image.
        :type reference: str
        :param payload: Manifest body, can take v1 or v2 values depending on accept header.
        :type payload: ~container_registry.models.Manifest
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: object, or the result of cls(response)
        :rtype: object
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType[object]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        content_type = kwargs.pop("content_type", "application/vnd.docker.distribution.manifest.v2+json")
        accept = "application/json"

        # Construct URL
        url = self.create_manifest.metadata['url']  # type: ignore
        path_format_arguments = {
            'url': self._serialize.url("self._config.url", self._config.url, 'str', skip_quote=True),
            'name': self._serialize.url("name", name, 'str'),
            'reference': self._serialize.url("reference", reference, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Content-Type'] = self._serialize.header("content_type", content_type, 'str')
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        body_content_kwargs = {}  # type: Dict[str, Any]
        body_content = self._serialize.body(payload, 'Manifest')
        body_content_kwargs['content'] = body_content
        request = self._client.put(url, query_parameters, header_parameters, **body_content_kwargs)
        pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [201]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize.failsafe_deserialize(_models.AcrErrors, response)
            raise HttpResponseError(response=response, model=error)

        response_headers = {}
        response_headers['Docker-Content-Digest']=self._deserialize('str', response.headers.get('Docker-Content-Digest'))
        response_headers['Location']=self._deserialize('str', response.headers.get('Location'))
        response_headers['Content-Length']=self._deserialize('long', response.headers.get('Content-Length'))
        deserialized = self._deserialize('object', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, response_headers)

        return deserialized
    create_manifest.metadata = {'url': '/v2/{name}/manifests/{reference}'}  # type: ignore

    def delete_manifest(
        self,
        name,  # type: str
        reference,  # type: str
        **kwargs  # type: Any
    ):
        # type: (...) -> None
        """Delete the manifest identified by ``name`` and ``reference``. Note that a manifest can *only*
        be deleted by ``digest``.

        :param name: Name of the image (including the namespace).
        :type name: str
        :param reference: Digest of a BLOB.
        :type reference: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: None, or the result of cls(response)
        :rtype: None
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType[None]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        accept = "application/json"

        # Construct URL
        url = self.delete_manifest.metadata['url']  # type: ignore
        path_format_arguments = {
            'url': self._serialize.url("self._config.url", self._config.url, 'str', skip_quote=True),
            'name': self._serialize.url("name", name, 'str'),
            'reference': self._serialize.url("reference", reference, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        request = self._client.delete(url, query_parameters, header_parameters)
        pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [202]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize.failsafe_deserialize(_models.AcrErrors, response)
            raise HttpResponseError(response=response, model=error)

        if cls:
            return cls(pipeline_response, None, {})

    delete_manifest.metadata = {'url': '/v2/{name}/manifests/{reference}'}  # type: ignore

    def get_properties(
        self,
        name,  # type: str
        **kwargs  # type: Any
    ):
        # type: (...) -> "_models.RepositoryProperties"
        """Get repository attributes.

        :param name: Name of the image (including the namespace).
        :type name: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: RepositoryProperties, or the result of cls(response)
        :rtype: ~container_registry.models.RepositoryProperties
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.RepositoryProperties"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        accept = "application/json"

        # Construct URL
        url = self.get_properties.metadata['url']  # type: ignore
        path_format_arguments = {
            'url': self._serialize.url("self._config.url", self._config.url, 'str', skip_quote=True),
            'name': self._serialize.url("name", name, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        request = self._client.get(url, query_parameters, header_parameters)
        pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize.failsafe_deserialize(_models.AcrErrors, response)
            raise HttpResponseError(response=response, model=error)

        deserialized = self._deserialize('RepositoryProperties', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    get_properties.metadata = {'url': '/acr/v1/{name}'}  # type: ignore

    def set_properties(
        self,
        name,  # type: str
        value=None,  # type: Optional["_models.ContentProperties"]
        **kwargs  # type: Any
    ):
        # type: (...) -> None
        """Update the attribute identified by ``name`` where ``reference`` is the name of the repository.

        :param name: Name of the image (including the namespace).
        :type name: str
        :param value: Repository attribute value.
        :type value: ~container_registry.models.ContentProperties
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: None, or the result of cls(response)
        :rtype: None
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType[None]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        content_type = kwargs.pop("content_type", "application/json")
        accept = "application/json"

        # Construct URL
        url = self.set_properties.metadata['url']  # type: ignore
        path_format_arguments = {
            'url': self._serialize.url("self._config.url", self._config.url, 'str', skip_quote=True),
            'name': self._serialize.url("name", name, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Content-Type'] = self._serialize.header("content_type", content_type, 'str')
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        body_content_kwargs = {}  # type: Dict[str, Any]
        if value is not None:
            body_content = self._serialize.body(value, 'ContentProperties')
        else:
            body_content = None
        body_content_kwargs['content'] = body_content
        request = self._client.patch(url, query_parameters, header_parameters, **body_content_kwargs)
        pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize.failsafe_deserialize(_models.AcrErrors, response)
            raise HttpResponseError(response=response, model=error)

        if cls:
            return cls(pipeline_response, None, {})

    set_properties.metadata = {'url': '/acr/v1/{name}'}  # type: ignore

    def get_tags(
        self,
        name,  # type: str
        last=None,  # type: Optional[str]
        n=None,  # type: Optional[int]
        orderby=None,  # type: Optional[str]
        digest=None,  # type: Optional[str]
        **kwargs  # type: Any
    ):
        # type: (...) -> Iterable["_models.TagList"]
        """List tags of a repository.

        :param name: Name of the image (including the namespace).
        :type name: str
        :param last: Query parameter for the last item in previous query. Result set will include
         values lexically after last.
        :type last: str
        :param n: query parameter for max number of items.
        :type n: int
        :param orderby: orderby query parameter.
        :type orderby: str
        :param digest: filter by digest.
        :type digest: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: An iterator like instance of either TagList or the result of cls(response)
        :rtype: ~azure.core.paging.ItemPaged[~container_registry.models.TagList]
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.TagList"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        accept = "application/json"

        def prepare_request(next_link=None):
            # Construct headers
            header_parameters = {}  # type: Dict[str, Any]
            header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

            if not next_link:
                # Construct URL
                url = self.get_tags.metadata['url']  # type: ignore
                path_format_arguments = {
                    'url': self._serialize.url("self._config.url", self._config.url, 'str', skip_quote=True),
                    'name': self._serialize.url("name", name, 'str'),
                }
                url = self._client.format_url(url, **path_format_arguments)
                # Construct parameters
                query_parameters = {}  # type: Dict[str, Any]
                if last is not None:
                    query_parameters['last'] = self._serialize.query("last", last, 'str')
                if n is not None:
                    query_parameters['n'] = self._serialize.query("n", n, 'int')
                if orderby is not None:
                    query_parameters['orderby'] = self._serialize.query("orderby", orderby, 'str')
                if digest is not None:
                    query_parameters['digest'] = self._serialize.query("digest", digest, 'str')

                request = self._client.get(url, query_parameters, header_parameters)
            else:
                url = next_link
                query_parameters = {}  # type: Dict[str, Any]
                path_format_arguments = {
                    'url': self._serialize.url("self._config.url", self._config.url, 'str', skip_quote=True),
                    'name': self._serialize.url("name", name, 'str'),
                }
                url = self._client.format_url(url, **path_format_arguments)
                request = self._client.get(url, query_parameters, header_parameters)
            return request

        def extract_data(pipeline_response):
            deserialized = self._deserialize('TagList', pipeline_response)
            list_of_elem = deserialized.tags
            if cls:
                list_of_elem = cls(list_of_elem)
            return deserialized.link or None, iter(list_of_elem)

        def get_next(next_link=None):
            request = prepare_request(next_link)

            pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
            response = pipeline_response.http_response

            if response.status_code not in [200]:
                error = self._deserialize.failsafe_deserialize(_models.AcrErrors, response)
                map_error(status_code=response.status_code, response=response, error_map=error_map)
                raise HttpResponseError(response=response, model=error)

            return pipeline_response

        return ItemPaged(
            get_next, extract_data
        )
    get_tags.metadata = {'url': '/acr/v1/{name}/_tags'}  # type: ignore

    def get_tag_properties(
        self,
        name,  # type: str
        reference,  # type: str
        **kwargs  # type: Any
    ):
        # type: (...) -> "_models.TagProperties"
        """Get tag attributes by tag.

        :param name: Name of the image (including the namespace).
        :type name: str
        :param reference: Tag name.
        :type reference: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: TagProperties, or the result of cls(response)
        :rtype: ~container_registry.models.TagProperties
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.TagProperties"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        accept = "application/json"

        # Construct URL
        url = self.get_tag_properties.metadata['url']  # type: ignore
        path_format_arguments = {
            'url': self._serialize.url("self._config.url", self._config.url, 'str', skip_quote=True),
            'name': self._serialize.url("name", name, 'str'),
            'reference': self._serialize.url("reference", reference, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        request = self._client.get(url, query_parameters, header_parameters)
        pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize.failsafe_deserialize(_models.AcrErrors, response)
            raise HttpResponseError(response=response, model=error)

        deserialized = self._deserialize('TagProperties', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    get_tag_properties.metadata = {'url': '/acr/v1/{name}/_tags/{reference}'}  # type: ignore

    def update_tag_attributes(
        self,
        name,  # type: str
        reference,  # type: str
        value=None,  # type: Optional["_models.ContentProperties"]
        **kwargs  # type: Any
    ):
        # type: (...) -> None
        """Update tag attributes.

        :param name: Name of the image (including the namespace).
        :type name: str
        :param reference: Tag name.
        :type reference: str
        :param value: Repository attribute value.
        :type value: ~container_registry.models.ContentProperties
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: None, or the result of cls(response)
        :rtype: None
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType[None]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        content_type = kwargs.pop("content_type", "application/json")
        accept = "application/json"

        # Construct URL
        url = self.update_tag_attributes.metadata['url']  # type: ignore
        path_format_arguments = {
            'url': self._serialize.url("self._config.url", self._config.url, 'str', skip_quote=True),
            'name': self._serialize.url("name", name, 'str'),
            'reference': self._serialize.url("reference", reference, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Content-Type'] = self._serialize.header("content_type", content_type, 'str')
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        body_content_kwargs = {}  # type: Dict[str, Any]
        if value is not None:
            body_content = self._serialize.body(value, 'ContentProperties')
        else:
            body_content = None
        body_content_kwargs['content'] = body_content
        request = self._client.patch(url, query_parameters, header_parameters, **body_content_kwargs)
        pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize.failsafe_deserialize(_models.AcrErrors, response)
            raise HttpResponseError(response=response, model=error)

        if cls:
            return cls(pipeline_response, None, {})

    update_tag_attributes.metadata = {'url': '/acr/v1/{name}/_tags/{reference}'}  # type: ignore

    def delete_tag(
        self,
        name,  # type: str
        reference,  # type: str
        **kwargs  # type: Any
    ):
        # type: (...) -> None
        """Delete tag.

        :param name: Name of the image (including the namespace).
        :type name: str
        :param reference: Tag name.
        :type reference: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: None, or the result of cls(response)
        :rtype: None
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType[None]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        accept = "application/json"

        # Construct URL
        url = self.delete_tag.metadata['url']  # type: ignore
        path_format_arguments = {
            'url': self._serialize.url("self._config.url", self._config.url, 'str', skip_quote=True),
            'name': self._serialize.url("name", name, 'str'),
            'reference': self._serialize.url("reference", reference, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        request = self._client.delete(url, query_parameters, header_parameters)
        pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [202]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize.failsafe_deserialize(_models.AcrErrors, response)
            raise HttpResponseError(response=response, model=error)

        if cls:
            return cls(pipeline_response, None, {})

    delete_tag.metadata = {'url': '/acr/v1/{name}/_tags/{reference}'}  # type: ignore

    def get_manifests(
        self,
        name,  # type: str
        last=None,  # type: Optional[str]
        n=None,  # type: Optional[int]
        orderby=None,  # type: Optional[str]
        **kwargs  # type: Any
    ):
        # type: (...) -> Iterable["_models.AcrManifests"]
        """List manifests of a repository.

        :param name: Name of the image (including the namespace).
        :type name: str
        :param last: Query parameter for the last item in previous query. Result set will include
         values lexically after last.
        :type last: str
        :param n: query parameter for max number of items.
        :type n: int
        :param orderby: orderby query parameter.
        :type orderby: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: An iterator like instance of either AcrManifests or the result of cls(response)
        :rtype: ~azure.core.paging.ItemPaged[~container_registry.models.AcrManifests]
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.AcrManifests"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        accept = "application/json"

        def prepare_request(next_link=None):
            # Construct headers
            header_parameters = {}  # type: Dict[str, Any]
            header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

            if not next_link:
                # Construct URL
                url = self.get_manifests.metadata['url']  # type: ignore
                path_format_arguments = {
                    'url': self._serialize.url("self._config.url", self._config.url, 'str', skip_quote=True),
                    'name': self._serialize.url("name", name, 'str'),
                }
                url = self._client.format_url(url, **path_format_arguments)
                # Construct parameters
                query_parameters = {}  # type: Dict[str, Any]
                if last is not None:
                    query_parameters['last'] = self._serialize.query("last", last, 'str')
                if n is not None:
                    query_parameters['n'] = self._serialize.query("n", n, 'int')
                if orderby is not None:
                    query_parameters['orderby'] = self._serialize.query("orderby", orderby, 'str')

                request = self._client.get(url, query_parameters, header_parameters)
            else:
                url = next_link
                query_parameters = {}  # type: Dict[str, Any]
                path_format_arguments = {
                    'url': self._serialize.url("self._config.url", self._config.url, 'str', skip_quote=True),
                    'name': self._serialize.url("name", name, 'str'),
                }
                url = self._client.format_url(url, **path_format_arguments)
                request = self._client.get(url, query_parameters, header_parameters)
            return request

        def extract_data(pipeline_response):
            deserialized = self._deserialize('AcrManifests', pipeline_response)
            list_of_elem = deserialized.manifests
            if cls:
                list_of_elem = cls(list_of_elem)
            return deserialized.link or None, iter(list_of_elem)

        def get_next(next_link=None):
            request = prepare_request(next_link)

            pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
            response = pipeline_response.http_response

            if response.status_code not in [200]:
                error = self._deserialize.failsafe_deserialize(_models.AcrErrors, response)
                map_error(status_code=response.status_code, response=response, error_map=error_map)
                raise HttpResponseError(response=response, model=error)

            return pipeline_response

        return ItemPaged(
            get_next, extract_data
        )
    get_manifests.metadata = {'url': '/acr/v1/{name}/_manifests'}  # type: ignore

    def get_registry_artifact_properties(
        self,
        name,  # type: str
        digest,  # type: str
        **kwargs  # type: Any
    ):
        # type: (...) -> "_models.RegistryArtifactProperties"
        """Get manifest attributes.

        :param name: Name of the image (including the namespace).
        :type name: str
        :param digest: Digest of a BLOB.
        :type digest: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: RegistryArtifactProperties, or the result of cls(response)
        :rtype: ~container_registry.models.RegistryArtifactProperties
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.RegistryArtifactProperties"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        accept = "application/json"

        # Construct URL
        url = self.get_registry_artifact_properties.metadata['url']  # type: ignore
        path_format_arguments = {
            'url': self._serialize.url("self._config.url", self._config.url, 'str', skip_quote=True),
            'name': self._serialize.url("name", name, 'str'),
            'digest': self._serialize.url("digest", digest, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        request = self._client.get(url, query_parameters, header_parameters)
        pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize.failsafe_deserialize(_models.AcrErrors, response)
            raise HttpResponseError(response=response, model=error)

        deserialized = self._deserialize('RegistryArtifactProperties', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    get_registry_artifact_properties.metadata = {'url': '/acr/v1/{name}/_manifests/{digest}'}  # type: ignore

    def update_manifest_attributes(
        self,
        name,  # type: str
        digest,  # type: str
        value=None,  # type: Optional["_models.ContentProperties"]
        **kwargs  # type: Any
    ):
        # type: (...) -> None
        """Update attributes of a manifest.

        :param name: Name of the image (including the namespace).
        :type name: str
        :param digest: Digest of a BLOB.
        :type digest: str
        :param value: Repository attribute value.
        :type value: ~container_registry.models.ContentProperties
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: None, or the result of cls(response)
        :rtype: None
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType[None]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        content_type = kwargs.pop("content_type", "application/json")
        accept = "application/json"

        # Construct URL
        url = self.update_manifest_attributes.metadata['url']  # type: ignore
        path_format_arguments = {
            'url': self._serialize.url("self._config.url", self._config.url, 'str', skip_quote=True),
            'name': self._serialize.url("name", name, 'str'),
            'digest': self._serialize.url("digest", digest, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Content-Type'] = self._serialize.header("content_type", content_type, 'str')
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        body_content_kwargs = {}  # type: Dict[str, Any]
        if value is not None:
            body_content = self._serialize.body(value, 'ContentProperties')
        else:
            body_content = None
        body_content_kwargs['content'] = body_content
        request = self._client.patch(url, query_parameters, header_parameters, **body_content_kwargs)
        pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize.failsafe_deserialize(_models.AcrErrors, response)
            raise HttpResponseError(response=response, model=error)

        if cls:
            return cls(pipeline_response, None, {})

    update_manifest_attributes.metadata = {'url': '/acr/v1/{name}/_manifests/{digest}'}  # type: ignore
