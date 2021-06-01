# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from typing import TYPE_CHECKING

from azure.mgmt.core import ARMPipelineClient
from msrest import Deserializer, Serializer

if TYPE_CHECKING:
    # pylint: disable=unused-import,ungrouped-imports
    from typing import Any, Optional

    from azure.core.credentials import TokenCredential
    from azure.core.pipeline.transport import HttpRequest, HttpResponse

from ._configuration import ComputeManagementClientConfiguration
from .operations import DisksOperations
from .operations import SnapshotsOperations
from .operations import DiskEncryptionSetsOperations
from .operations import DiskAccessesOperations
from .operations import DiskRestorePointOperations
from .operations import GalleriesOperations
from .operations import GalleryImagesOperations
from .operations import GalleryImageVersionsOperations
from .operations import GalleryApplicationsOperations
from .operations import GalleryApplicationVersionsOperations
from .operations import GallerySharingProfileOperations
from .operations import SharedGalleriesOperations
from .operations import SharedGalleryImagesOperations
from .operations import SharedGalleryImageVersionsOperations
from . import models


class ComputeManagementClient(object):
    """Compute Client.

    :ivar disks: DisksOperations operations
    :vartype disks: azure.mgmt.compute.v2020_09_30.operations.DisksOperations
    :ivar snapshots: SnapshotsOperations operations
    :vartype snapshots: azure.mgmt.compute.v2020_09_30.operations.SnapshotsOperations
    :ivar disk_encryption_sets: DiskEncryptionSetsOperations operations
    :vartype disk_encryption_sets: azure.mgmt.compute.v2020_09_30.operations.DiskEncryptionSetsOperations
    :ivar disk_accesses: DiskAccessesOperations operations
    :vartype disk_accesses: azure.mgmt.compute.v2020_09_30.operations.DiskAccessesOperations
    :ivar disk_restore_point: DiskRestorePointOperations operations
    :vartype disk_restore_point: azure.mgmt.compute.v2020_09_30.operations.DiskRestorePointOperations
    :ivar galleries: GalleriesOperations operations
    :vartype galleries: azure.mgmt.compute.v2020_09_30.operations.GalleriesOperations
    :ivar gallery_images: GalleryImagesOperations operations
    :vartype gallery_images: azure.mgmt.compute.v2020_09_30.operations.GalleryImagesOperations
    :ivar gallery_image_versions: GalleryImageVersionsOperations operations
    :vartype gallery_image_versions: azure.mgmt.compute.v2020_09_30.operations.GalleryImageVersionsOperations
    :ivar gallery_applications: GalleryApplicationsOperations operations
    :vartype gallery_applications: azure.mgmt.compute.v2020_09_30.operations.GalleryApplicationsOperations
    :ivar gallery_application_versions: GalleryApplicationVersionsOperations operations
    :vartype gallery_application_versions: azure.mgmt.compute.v2020_09_30.operations.GalleryApplicationVersionsOperations
    :ivar gallery_sharing_profile: GallerySharingProfileOperations operations
    :vartype gallery_sharing_profile: azure.mgmt.compute.v2020_09_30.operations.GallerySharingProfileOperations
    :ivar shared_galleries: SharedGalleriesOperations operations
    :vartype shared_galleries: azure.mgmt.compute.v2020_09_30.operations.SharedGalleriesOperations
    :ivar shared_gallery_images: SharedGalleryImagesOperations operations
    :vartype shared_gallery_images: azure.mgmt.compute.v2020_09_30.operations.SharedGalleryImagesOperations
    :ivar shared_gallery_image_versions: SharedGalleryImageVersionsOperations operations
    :vartype shared_gallery_image_versions: azure.mgmt.compute.v2020_09_30.operations.SharedGalleryImageVersionsOperations
    :param credential: Credential needed for the client to connect to Azure.
    :type credential: ~azure.core.credentials.TokenCredential
    :param subscription_id: Subscription credentials which uniquely identify Microsoft Azure subscription. The subscription ID forms part of the URI for every service call.
    :type subscription_id: str
    :param str base_url: Service URL
    :keyword int polling_interval: Default waiting time between two polls for LRO operations if no Retry-After header is present.
    """

    def __init__(
        self,
        credential,  # type: "TokenCredential"
        subscription_id,  # type: str
        base_url=None,  # type: Optional[str]
        **kwargs  # type: Any
    ):
        # type: (...) -> None
        if not base_url:
            base_url = 'https://management.azure.com'
        self._config = ComputeManagementClientConfiguration(credential, subscription_id, **kwargs)
        self._client = ARMPipelineClient(base_url=base_url, config=self._config, **kwargs)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self._serialize = Serializer(client_models)
        self._serialize.client_side_validation = False
        self._deserialize = Deserializer(client_models)

        self.disks = DisksOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.snapshots = SnapshotsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.disk_encryption_sets = DiskEncryptionSetsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.disk_accesses = DiskAccessesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.disk_restore_point = DiskRestorePointOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.galleries = GalleriesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.gallery_images = GalleryImagesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.gallery_image_versions = GalleryImageVersionsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.gallery_applications = GalleryApplicationsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.gallery_application_versions = GalleryApplicationVersionsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.gallery_sharing_profile = GallerySharingProfileOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.shared_galleries = SharedGalleriesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.shared_gallery_images = SharedGalleryImagesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.shared_gallery_image_versions = SharedGalleryImageVersionsOperations(
            self._client, self._config, self._serialize, self._deserialize)

    def _send_request(self, http_request, **kwargs):
        # type: (HttpRequest, Any) -> HttpResponse
        """Runs the network request through the client's chained policies.

        :param http_request: The network request you want to make. Required.
        :type http_request: ~azure.core.pipeline.transport.HttpRequest
        :keyword bool stream: Whether the response payload will be streamed. Defaults to True.
        :return: The response of your network call. Does not do error handling on your response.
        :rtype: ~azure.core.pipeline.transport.HttpResponse
        """
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
        }
        http_request.url = self._client.format_url(http_request.url, **path_format_arguments)
        stream = kwargs.pop("stream", True)
        pipeline_response = self._client._pipeline.run(http_request, stream=stream, **kwargs)
        return pipeline_response.http_response

    def close(self):
        # type: () -> None
        self._client.close()

    def __enter__(self):
        # type: () -> ComputeManagementClient
        self._client.__enter__()
        return self

    def __exit__(self, *exc_details):
        # type: (Any) -> None
        self._client.__exit__(*exc_details)
