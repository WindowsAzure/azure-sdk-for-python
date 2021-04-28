# coding=utf-8
# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------
from typing import TYPE_CHECKING, Dict, Any

from azure.core.exceptions import (
    ClientAuthenticationError,
    ResourceNotFoundError,
    ResourceExistsError,
    HttpResponseError,
    map_error,
)
from azure.core.async_paging import AsyncItemPaged, AsyncList
from azure.core.tracing.decorator import distributed_trace
from azure.core.tracing.decorator_async import distributed_trace_async

from ._async_base_client import ContainerRegistryBaseClient
from .._generated.models import AcrErrors
from .._helpers import _is_tag, _parse_next_link
from .._models import (
    ContentPermissions,
    ArtifactManifestProperties,
    TagProperties,
)

if TYPE_CHECKING:
    from azure.core.credentials_async import AsyncTokenCredential


class RegistryArtifact(ContainerRegistryBaseClient):
    def __init__(
        self,
        endpoint: str,
        repository: str,
        tag_or_digest: str,
        credential: "AsyncTokenCredential",
        **kwargs: Dict[str, Any]
    ) -> None:
        """Create a RegistryArtifact from an endpoint, repository, a tag or digest, and a credential

        :param endpoint: An ACR endpoint
        :type endpoint: str
        :param repository: The name of a repository
        :type repository: str
        :param tag_or_digest: Tag or digest of the artifact
        :type tag_or_digest: str
        :param credential: The credential with which to authenticate
        :type credential: :class:`~azure.core.credentials.TokenCredential`
        :returns: None
        :raises: None
        """
        if not endpoint.startswith("https://") and not endpoint.startswith("http://"):
            endpoint = "https://" + endpoint
        self._endpoint = endpoint
        self._credential = credential
        self.repository = repository
        self.tag_or_digest = tag_or_digest
        self.fully_qualified_name = self._endpoint + self.repository + self.tag_or_digest
        self._digest = None
        self._tag = None
        super(RegistryArtifact, self).__init__(endpoint=self._endpoint, credential=credential, **kwargs)

    async def _get_digest_from_tag(self):
        # type: () -> str
        tag_props = await self.get_tag_properties(self.tag_or_digest)
        return tag_props.digest

    @distributed_trace_async
    async def delete(self, **kwargs: Dict[str, Any]) -> None:
        """Delete a registry artifact

        :returns: None
        :raises: :class:`~azure.core.exceptions.ResourceNotFoundError`
        """
        if not self._digest:
            self._digest = self.tag_or_digest if not _is_tag(self.tag_or_digest) else await self._get_digest_from_tag()
        await self._client.container_registry.delete_manifest(self.repository, self._digest, **kwargs)

    @distributed_trace_async
    async def delete_tag(self, tag: str, **kwargs: Dict[str, Any]) -> None:
        """Delete a tag from a repository

        :param str tag: The tag to be deleted
        :returns: None
        :raises: :class:`~azure.core.exceptions.ResourceNotFoundError`
        """
        await self._client.container_registry.delete_tag(self.repository, tag, **kwargs)

    @distributed_trace_async
    async def get_manifest_properties(self, **kwargs: Dict[str, Any]) -> ArtifactManifestProperties:
        """Get the properties of a registry artifact

        :returns: :class:`~azure.containerregistry.ArtifactManifestProperties`
        :raises: :class:`~azure.core.exceptions.ResourceNotFoundError`
        """
        if not self._digest:
            self._digest = self.tag_or_digest if not _is_tag(self.tag_or_digest) else await self._get_digest_from_tag()

        return ArtifactManifestProperties._from_generated(  # pylint: disable=protected-access
            await self._client.container_registry.get_manifest_properties(self.repository, self._digest, **kwargs)
        )

    @distributed_trace_async
    async def get_tag_properties(self, tag: str, **kwargs: Dict[str, Any]) -> TagProperties:
        """Get the properties for a tag

        :param tag: The tag to get properties for
        :type tag: str
        :returns: :class:`~azure.containerregistry.TagProperties`
        :raises: :class:`~azure.core.exceptions.ResourceNotFoundError`
        """
        return TagProperties._from_generated(  # pylint: disable=protected-access
            await self._client.container_registry.get_tag_properties(self.repository, tag, **kwargs)
        )

    @distributed_trace
    def list_tags(self, **kwargs: Dict[str, Any]) -> AsyncItemPaged[TagProperties]:
        """List the tags for a repository

        :keyword last: Query parameter for the last item in the previous call. Ensuing
            call will return values after last lexically
        :paramtype last: str
        :keyword order_by: Query parameter for ordering by time ascending or descending
        :paramtype order_by: :class:`~azure.containerregistry.TagOrderBy`
        :keyword results_per_page: Number of repositories to return per page
        :paramtype results_per_page: int
        :return: ItemPaged[:class:`~azure.containerregistry.TagProperties`]
        :rtype: :class:`~azure.core.async_paging.AsyncItemPaged`
        :raises: :class:`~azure.core.exceptions.ResourceNotFoundError`
        """
        name = self.repository
        last = kwargs.pop("last", None)
        n = kwargs.pop("results_per_page", None)
        orderby = kwargs.pop("order_by", None)
        digest = kwargs.pop("digest", None)
        cls = kwargs.pop(
            "cls", lambda objs: [TagProperties._from_generated(o) for o in objs]  # pylint: disable=protected-access
        )

        error_map = {401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError}
        error_map.update(kwargs.pop("error_map", {}))
        accept = "application/json"

        def prepare_request(next_link=None):
            # Construct headers
            header_parameters = {}  # type: Dict[str, Any]
            header_parameters["Accept"] = self._client._serialize.header(  # pylint: disable=protected-access
                "accept", accept, "str"
            )

            if not next_link:
                # Construct URL
                url = "/acr/v1/{name}/_tags"
                path_format_arguments = {
                    "url": self._client._serialize.url(  # pylint: disable=protected-access
                        "self._client._config.url",
                        self._client._config.url,  # pylint: disable=protected-access
                        "str",
                        skip_quote=True,
                    ),
                    "name": self._client._serialize.url("name", name, "str"),  # pylint: disable=protected-access
                }
                url = self._client._client.format_url(url, **path_format_arguments)  # pylint: disable=protected-access
                # Construct parameters
                query_parameters = {}  # type: Dict[str, Any]
                if last is not None:
                    query_parameters["last"] = self._client._serialize.query(  # pylint: disable=protected-access
                        "last", last, "str"
                    )
                if n is not None:
                    query_parameters["n"] = self._client._serialize.query(  # pylint: disable=protected-access
                        "n", n, "int"
                    )
                if orderby is not None:
                    query_parameters["orderby"] = self._client._serialize.query(  # pylint: disable=protected-access
                        "orderby", orderby, "str"
                    )
                if digest is not None:
                    query_parameters["digest"] = self._client._serialize.query(  # pylint: disable=protected-access
                        "digest", digest, "str"
                    )

                request = self._client._client.get(  # pylint: disable=protected-access
                    url, query_parameters, header_parameters
                )
            else:
                url = next_link
                query_parameters = {}  # type: Dict[str, Any]
                path_format_arguments = {
                    "url": self._client._serialize.url(  # pylint: disable=protected-access
                        "self._client._config.url",
                        self._client._config.url,  # pylint: disable=protected-access
                        "str",
                        skip_quote=True,
                    ),
                    "name": self._client._serialize.url("name", name, "str"),  # pylint: disable=protected-access
                }
                url = self._client._client.format_url(url, **path_format_arguments)  # pylint: disable=protected-access
                request = self._client._client.get(  # pylint: disable=protected-access
                    url, query_parameters, header_parameters
                )
            return request

        async def extract_data(pipeline_response):
            deserialized = self._client._deserialize("TagList", pipeline_response)  # pylint: disable=protected-access
            list_of_elem = deserialized.tag_attribute_bases
            if cls:
                list_of_elem = cls(list_of_elem)
            link = None
            if "Link" in pipeline_response.http_response.headers.keys():
                link = _parse_next_link(pipeline_response.http_response.headers["Link"])
            return link, AsyncList(list_of_elem)

        async def get_next(next_link=None):
            request = prepare_request(next_link)

            pipeline_response = await self._client._client._pipeline.run(  # pylint: disable=protected-access
                request, stream=False, **kwargs
            )
            response = pipeline_response.http_response

            if response.status_code not in [200]:
                error = self._client._deserialize.failsafe_deserialize(  # pylint: disable=protected-access
                    AcrErrors, response
                )
                map_error(status_code=response.status_code, response=response, error_map=error_map)
                raise HttpResponseError(response=response, model=error)

            return pipeline_response

        return AsyncItemPaged(get_next, extract_data)

    @distributed_trace_async
    async def set_manifest_properties(
        self, permissions: ContentPermissions, **kwargs: Dict[str, Any]
    ) -> ArtifactManifestProperties:
        """Set the properties for a manifest

        :param permissions: The property's values to be set
        :type permissions: ContentPermissions
        :returns: :class:`~azure.containerregistry.ArtifactManifestProperties`
        :raises: :class:`~azure.core.exceptions.ResourceNotFoundError`
        """
        if not self._digest:
            self._digest = self.tag_or_digest if _is_tag(self.tag_or_digest) else self._get_digest_from_tag()

        return ArtifactManifestProperties._from_generated(  # pylint: disable=protected-access
            await self._client.container_registry.update_manifest_properties(
                self.repository,
                self._digest,
                value=permissions._to_generated(),  # pylint: disable=protected-access
                **kwargs
            )
        )

    @distributed_trace_async
    async def set_tag_properties(
        self, tag: str, permissions: ContentPermissions, **kwargs: Dict[str, Any]
    ) -> TagProperties:
        """Set the properties for a tag

        :param tag: Tag to set properties for
        :type tag: str
        :param permissions: The property's values to be set
        :type permissions: ContentPermissions
        :returns: :class:`~azure.containerregistry.TagProperties`
        :raises: :class:`~azure.core.exceptions.ResourceNotFoundError`
        """
        return TagProperties._from_generated(  # pylint: disable=protected-access
            await self._client.container_registry.update_tag_attributes(
                self.repository, tag, value=permissions._to_generated(), **kwargs  # pylint: disable=protected-access
            )
        )
