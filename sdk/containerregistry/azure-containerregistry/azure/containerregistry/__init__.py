# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from ._artifact_storage_client import ArtifactClient
from ._container_registry_authentication import ContainerRegistryStsClient
from ._container_registry_client import ContainerRegistryClient
from ._container_repository_client import ContainerRepositoryClient
from ._models import (
    AzureAdminUserCredential,
    ContentPermissions,
    DeletedRepositoryResult,
    GetManifestOptions,
    GetTagOptions,
    ArtifactAttributes,
    ManifestOrderBy,
    RepositoryAttributes,
    TagAttributes,
    TagOrderBy
)
from ._storage_models import (
    ArtifactManifest,
    CompleteUploadResult,
    ConfigMediaType,
    ContentDescriptor,
    CreateManifestResult,
    CreateUploadResult,
    DockerManifestList,
    DockerManifestV1,
    DockerManifestV1FsLayer,
    DockerManifestV1History,
    DockerManifestV1ImageHistory,
    DockerManifestV1Jwk,
    DockerManifestV1JwkHeader,
    DockerManifestV2,
    ManifestListAttributes,
    ManifestMediaType,
    OCIIndex,
    OCIManifest,
    OCIManifestAnnotations,
    RuntimePlatform,
    UploadStatus
)
from ._version import VERSION

__version__ = VERSION

__all__ = [
    "ArtifactClient",
    "ContainerRegistryStsClient",
    "ContainerRegistryClient",
    "ContainerRepositoryClient",
    "AzureAdminUserCredential",
    "ContentPermissions",
    "DeletedRepositoryResult",
    "GetManifestOptions",
    "GetTagOptions",
    "ArtifactAttributes",
    "ManifestOrderBy",
    "RepositoryAttributes",
    "TagAttributes",
    "TagOrderBy",
    "ArtifactManifest",
    "CompleteUploadResult",
    "ConfigMediaType",
    "ContentDescriptor",
    "CreateManifestResult",
    "CreateUploadResult",
    "DockerManifestList",
    "DockerManifestV1",
    "DockerManifestV1FsLayer",
    "DockerManifestV1History",
    "DockerManifestV1ImageHistory",
    "DockerManifestV1Jwk",
    "DockerManifestV1JwkHeader",
    "DockerManifestV2",
    "ManifestListAttributes",
    "ManifestMediaType",
    "OCIIndex",
    "OCIManifest",
    "OCIManifestAnnotations",
    "RuntimePlatform",
    "UploadStatus",
]
