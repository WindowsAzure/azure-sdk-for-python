# -------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# --------------------------------------------------------------------------
# pylint: disable=too-few-public-methods, too-many-instance-attributes
# pylint: disable=super-init-not-called, too-many-lines
from azure.core.async_paging import AsyncPageIterator, AsyncItemPaged

from .._deserialize import process_storage_error, get_deleted_path_properties_from_generated_code
from .._generated.models import StorageErrorException, BlobItemInternal, BlobPrefix as GenBlobPrefix

from .._shared.models import DictMixin
from .._shared.response_handlers import return_context_and_deserialized


class DeletedPathPropertiesPaged(AsyncPageIterator):
    """An Iterable of deleted path properties.

    :ivar str service_endpoint: The service URL.
    :ivar str prefix: A path name prefix being used to filter the list.
    :ivar str marker: The continuation token of the current page of results.
    :ivar int results_per_page: The maximum number of results retrieved per API call.
    :ivar str continuation_token: The continuation token to retrieve the next page of results.
    :ivar str location_mode: The location mode being used to list results. The available
        options include "primary" and "secondary".
    :ivar current_page: The current page of listed results.
    :vartype current_page: list(~azure.storage.filedatalake.DeletedPathProperties)
    :ivar str container: The container that the paths are listed from.
    :ivar str delimiter: A delimiting character used for hierarchy listing.

    :param callable command: Function to retrieve the next page of items.
    """
    def __init__(
            self, command,
            container=None,
            prefix=None,
            results_per_page=None,
            continuation_token=None,
            delimiter=None,
            location_mode=None):
        super(DeletedPathPropertiesPaged, self).__init__(
            get_next=self._get_next_cb,
            extract_data=self._extract_data_cb,
            continuation_token=continuation_token or ""
        )
        self._command = command
        self.service_endpoint = None
        self.prefix = prefix
        self.marker = None
        self.results_per_page = results_per_page
        self.container = container
        self.delimiter = delimiter
        self.current_page = None
        self.location_mode = location_mode

    async def _get_next_cb(self, continuation_token):
        try:
            return await self._command(
                prefix=self.prefix,
                marker=continuation_token or None,
                max_results=self.results_per_page,
                cls=return_context_and_deserialized,
                use_location=self.location_mode)
        except StorageErrorException as error:
            process_storage_error(error)

    async def _extract_data_cb(self, get_next_return):
        self.location_mode, self._response = get_next_return
        self.service_endpoint = self._response.service_endpoint
        self.prefix = self._response.prefix
        self.marker = self._response.marker
        self.results_per_page = self._response.max_results
        self.container = self._response.container_name
        self.current_page = self._response.segment.blob_prefixes + self._response.segment.blob_items
        self.current_page = [self._build_item(item) for item in self.current_page]
        self.delimiter = self._response.delimiter

        return self._response.next_marker or None, self.current_page

    def _build_item(self, item):
        if isinstance(item, BlobItemInternal):
            file_props = get_deleted_path_properties_from_generated_code(item)
            file_props.file_system = self.container
            return file_props
        if isinstance(item, GenBlobPrefix):
            return DirectoryPrefix(
                container=self.container,
                prefix=item.name,
                results_per_page=self.results_per_page,
                location_mode=self.location_mode)
        return item


class DirectoryPrefix(DictMixin):
    """Directory prefix.

    :ivar str name: Name of the deleted directory.
    :ivar int results_per_page: The maximum number of results retrieved per API call.
    :ivar str location_mode: The location mode being used to list results. The available
        options include "primary" and "secondary".
    :ivar str file_system: The file system that the deleted paths are listed from.
    :ivar str delimiter: A delimiting character used for hierarchy listing.
    """
    def __init__(self, **kwargs):
        self.name = kwargs.get('prefix')
        self.results_per_page = kwargs.get('results_per_page')
        self.file_system = kwargs.get('container')
        self.delimiter = kwargs.get('delimiter')
        self.location_mode = kwargs.get('location_mode')
