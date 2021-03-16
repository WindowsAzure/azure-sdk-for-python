# coding=utf-8
# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------

from enum import Enum

from azure.core.paging import PageIterator

from ._generated.models import (
    DeletedRepository,
)

class ContentPermissions(object):
    def __init__(self, **kwargs):
        self.can_delete = kwargs.get("can_delete")
        self.can_list = kwargs.get("can_list")
        self.can_read = kwargs.get("can_read")
        self.can_write = kwargs.get("can_write")

    @classmethod
    def from_generated(cls, generated):
        # type: (azure.containerregistry._generated.models.ChangeableAttributes) -> ContentPermissions
        return cls(
            delete=generated.can_delete,
            list=generated.can_list,
            read=generated.can_read,
            write=generated.can_write
        )


class DeletedRepositoryResult(DeletedRepository):
    def __init__(self, **kwargs):
        super(DeletedRepositoryResult, self).__init__(**kwargs)
        self.deleted_registry_artifact_digests = kwargs.get(
            "deleted_registry_artifact_digests", None
        )
        self.deleted_tags = kwargs.get("deleted_tags", None)
        pass


class RegistryArtifactProperties(object):
    def __init__(self, **kwargs):
        self.created_on = kwargs.get("created_on", None)
        self.image_name = kwargs.get("image_name", None)
        self.registry = kwargs.get("registry", None)
        self.manifest_properties = ManifestProperties.from_generated(kwargs.get("manifest_attributes"))

        # self.cpu_arch = kwargs.get("arch", None)
        # self.digest = kwargs.get("digest", None)
        # self.last_updated = kwargs.get("last_updated", None)
        # self.manifest_properties = kwargs.get("manifest_properties", None)
        # self.operating_system = kwargs.get("operating_system", None)
        # self.registry = kwargs.get("registry", None)
        # self.registry_artifacts = kwargs.get("registry_artifacts", None)
        # self.repository = kwargs.get("repository", None)
        # self.size = kwargs.get("size", None)
        # self.tags = kwargs.get("tags", None)

    @classmethod
    def from_generated(cls, generated):
        # type: (azure.containerregistry._generated.models.ManfiestAttributestBase) -> RegistryArtifactProperties
        cls(
            created_on=generated.created_on,
            image_name=generated.image_name,
            registry=generated.registry,
            manifest_attributes=generated.manifest_attributes,
        )


class RepositoryProperties(object):
    """Model for storing properties of a single repository

    :ivar created_on: Time the repository was created
    :vartype created_on: str
    :ivar last_updated_on: Time the repository was last updated
    :vartype last_updated_on: str
    :ivar modifiable_properties: Read/Write/Update/Delete permissions for the repository
    :vartype modifiable_properties: ContentPermissions
    :ivar name: Name of the repository
    :vartype name: str
    :ivar registry: Registry the repository belongs to
    :vartype registry: str
    :ivar digest: The digest of the repository
    :vartype digest: str
    :ivar tag_count: Number of tags associated with the repository
    :vartype tag_count: int
    :ivar manifest_count: Number of manifest in the repository
    :vartype manifest_count: int
    """

    def __init__(self, **kwargs):
        self.created_on = kwargs.get("created_on", None)
        self.last_updated_on = kwargs.get("last_updated_on", None)
        self.modifiable_properties = kwargs.get("modifiable_properties", None)
        self.name = kwargs.get("name", None)
        self.registry = kwargs.get("registry", None)
        self.tag_count = kwargs.get("tag_count", None)
        self.manifest_count = kwargs.get("manifest_count", None)
        self.content_permissions = kwargs.get('content_permissions', None)
        if self.content_permissions:
            self.content_permissions = ContentPermissions.from_generated(self.content_permissions)

    @classmethod
    def from_generated(cls, generated):
        # type: (azure.containerregistry._generated.models.RepositoryAttributes) -> RepositoryProperties
        return cls(
            created_on=generated.created_on,
            last_updated_on=generated.last_updated_on,
            name=generated.name,
            registry=generated.registry,
            manifest_count=generated.registry_artifact_count,
            tag_count=generated.tag_count,
            content_permissions=generated.writeable_properties
        )
        return cls(generated)


class RegistryArtifactOrderBy(int, Enum):

    LastUpdateTimeDescending = 0
    LastUpdateTimeAscending = 1


class TagOrderBy(int, Enum):

    LastUpdateTimeDescending = 0
    LastUpdateTimeAscending = 1
