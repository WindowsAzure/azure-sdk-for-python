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

from msrest.serialization import Model
from msrest.exceptions import HttpOperationError


class BoundingBox(Model):
    """Bounding box that defines a region of an image.

    All required parameters must be populated in order to send to Azure.

    :param left: Required. Coordinate of the left boundary.
    :type left: float
    :param top: Required. Coordinate of the top boundary.
    :type top: float
    :param width: Required. Width.
    :type width: float
    :param height: Required. Height.
    :type height: float
    """

    _validation = {
        'left': {'required': True},
        'top': {'required': True},
        'width': {'required': True},
        'height': {'required': True},
    }

    _attribute_map = {
        'left': {'key': 'left', 'type': 'float'},
        'top': {'key': 'top', 'type': 'float'},
        'width': {'key': 'width', 'type': 'float'},
        'height': {'key': 'height', 'type': 'float'},
    }

    def __init__(self, *, left: float, top: float, width: float, height: float, **kwargs) -> None:
        super(BoundingBox, self).__init__(**kwargs)
        self.left = left
        self.top = top
        self.width = width
        self.height = height


class CustomVisionError(Model):
    """CustomVisionError.

    All required parameters must be populated in order to send to Azure.

    :param code: Required. The error code. Possible values include: 'NoError',
     'BadRequest', 'BadRequestExceededBatchSize', 'BadRequestNotSupported',
     'BadRequestInvalidIds', 'BadRequestProjectName',
     'BadRequestProjectNameNotUnique', 'BadRequestProjectDescription',
     'BadRequestProjectUnknownDomain',
     'BadRequestProjectUnknownClassification',
     'BadRequestProjectUnsupportedDomainTypeChange',
     'BadRequestProjectUnsupportedExportPlatform',
     'BadRequestProjectImagePreprocessingSettings',
     'BadRequestProjectDuplicated', 'BadRequestIterationName',
     'BadRequestIterationNameNotUnique', 'BadRequestIterationDescription',
     'BadRequestIterationIsNotTrained', 'BadRequestIterationValidationFailed',
     'BadRequestWorkspaceCannotBeModified', 'BadRequestWorkspaceNotDeletable',
     'BadRequestTagName', 'BadRequestTagNameNotUnique',
     'BadRequestTagDescription', 'BadRequestTagType',
     'BadRequestMultipleNegativeTag', 'BadRequestMultipleGeneralProductTag',
     'BadRequestImageTags', 'BadRequestImageRegions',
     'BadRequestNegativeAndRegularTagOnSameImage',
     'BadRequestUnsupportedDomain', 'BadRequestRequiredParamIsNull',
     'BadRequestIterationIsPublished', 'BadRequestInvalidPublishName',
     'BadRequestInvalidPublishTarget', 'BadRequestUnpublishFailed',
     'BadRequestIterationNotPublished', 'BadRequestSubscriptionApi',
     'BadRequestExceedProjectLimit',
     'BadRequestExceedIterationPerProjectLimit',
     'BadRequestExceedTagPerProjectLimit', 'BadRequestExceedTagPerImageLimit',
     'BadRequestExceededQuota', 'BadRequestCannotMigrateProjectWithName',
     'BadRequestNotLimitedTrial', 'BadRequestImageBatch',
     'BadRequestImageStream', 'BadRequestImageUrl', 'BadRequestImageFormat',
     'BadRequestImageSizeBytes', 'BadRequestImageDimensions',
     'BadRequestImageExceededCount', 'BadRequestTrainingNotNeeded',
     'BadRequestTrainingNotNeededButTrainingPipelineUpdated',
     'BadRequestTrainingValidationFailed',
     'BadRequestClassificationTrainingValidationFailed',
     'BadRequestMultiClassClassificationTrainingValidationFailed',
     'BadRequestMultiLabelClassificationTrainingValidationFailed',
     'BadRequestDetectionTrainingValidationFailed',
     'BadRequestTrainingAlreadyInProgress',
     'BadRequestDetectionTrainingNotAllowNegativeTag',
     'BadRequestInvalidEmailAddress',
     'BadRequestDomainNotSupportedForAdvancedTraining',
     'BadRequestExportPlatformNotSupportedForAdvancedTraining',
     'BadRequestReservedBudgetInHoursNotEnoughForAdvancedTraining',
     'BadRequestExportValidationFailed', 'BadRequestExportAlreadyInProgress',
     'BadRequestPredictionIdsMissing', 'BadRequestPredictionIdsExceededCount',
     'BadRequestPredictionTagsExceededCount',
     'BadRequestPredictionResultsExceededCount',
     'BadRequestPredictionInvalidApplicationName',
     'BadRequestPredictionInvalidQueryParameters',
     'BadRequestInvalidImportToken', 'BadRequestExportWhileTraining',
     'BadRequestImageMetadataKey', 'BadRequestImageMetadataValue',
     'BadRequestOperationNotSupported', 'BadRequestInvalidArtifactUri',
     'BadRequestCustomerManagedKeyRevoked', 'BadRequestInvalid',
     'UnsupportedMediaType', 'Forbidden', 'ForbiddenUser',
     'ForbiddenUserResource', 'ForbiddenUserSignupDisabled',
     'ForbiddenUserSignupAllowanceExceeded', 'ForbiddenUserDoesNotExist',
     'ForbiddenUserDisabled', 'ForbiddenUserInsufficientCapability',
     'ForbiddenDRModeEnabled', 'ForbiddenInvalid', 'NotFound',
     'NotFoundProject', 'NotFoundProjectDefaultIteration', 'NotFoundIteration',
     'NotFoundIterationPerformance', 'NotFoundTag', 'NotFoundImage',
     'NotFoundDomain', 'NotFoundApimSubscription', 'NotFoundInvalid',
     'Conflict', 'ConflictInvalid', 'ErrorUnknown', 'ErrorIterationCopyFailed',
     'ErrorPreparePerformanceMigrationFailed', 'ErrorProjectInvalidWorkspace',
     'ErrorProjectInvalidPipelineConfiguration', 'ErrorProjectInvalidDomain',
     'ErrorProjectTrainingRequestFailed', 'ErrorProjectImportRequestFailed',
     'ErrorProjectExportRequestFailed', 'ErrorFeaturizationServiceUnavailable',
     'ErrorFeaturizationQueueTimeout', 'ErrorFeaturizationInvalidFeaturizer',
     'ErrorFeaturizationAugmentationUnavailable',
     'ErrorFeaturizationUnrecognizedJob',
     'ErrorFeaturizationAugmentationError', 'ErrorExporterInvalidPlatform',
     'ErrorExporterInvalidFeaturizer', 'ErrorExporterInvalidClassifier',
     'ErrorPredictionServiceUnavailable', 'ErrorPredictionModelNotFound',
     'ErrorPredictionModelNotCached', 'ErrorPrediction',
     'ErrorPredictionStorage', 'ErrorRegionProposal', 'ErrorUnknownBaseModel',
     'ErrorInvalid'
    :type code: str or
     ~azure.cognitiveservices.vision.customvision.prediction.models.CustomVisionErrorCodes
    :param message: Required. A message explaining the error reported by the
     service.
    :type message: str
    """

    _validation = {
        'code': {'required': True},
        'message': {'required': True},
    }

    _attribute_map = {
        'code': {'key': 'code', 'type': 'str'},
        'message': {'key': 'message', 'type': 'str'},
    }

    def __init__(self, *, code, message: str, **kwargs) -> None:
        super(CustomVisionError, self).__init__(**kwargs)
        self.code = code
        self.message = message


class CustomVisionErrorException(HttpOperationError):
    """Server responded with exception of type: 'CustomVisionError'.

    :param deserialize: A deserializer
    :param response: Server response to be deserialized.
    """

    def __init__(self, deserialize, response, *args):

        super(CustomVisionErrorException, self).__init__(deserialize, response, 'CustomVisionError', *args)


class ImagePrediction(Model):
    """Result of an image prediction request.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Prediction Id.
    :vartype id: str
    :ivar project: Project Id.
    :vartype project: str
    :ivar iteration: Iteration Id.
    :vartype iteration: str
    :ivar created: Date this prediction was created.
    :vartype created: datetime
    :ivar predictions: List of predictions.
    :vartype predictions:
     list[~azure.cognitiveservices.vision.customvision.prediction.models.Prediction]
    """

    _validation = {
        'id': {'readonly': True},
        'project': {'readonly': True},
        'iteration': {'readonly': True},
        'created': {'readonly': True},
        'predictions': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'project': {'key': 'project', 'type': 'str'},
        'iteration': {'key': 'iteration', 'type': 'str'},
        'created': {'key': 'created', 'type': 'iso-8601'},
        'predictions': {'key': 'predictions', 'type': '[Prediction]'},
    }

    def __init__(self, **kwargs) -> None:
        super(ImagePrediction, self).__init__(**kwargs)
        self.id = None
        self.project = None
        self.iteration = None
        self.created = None
        self.predictions = None


class ImageUrl(Model):
    """Image url.

    All required parameters must be populated in order to send to Azure.

    :param url: Required. Url of the image.
    :type url: str
    """

    _validation = {
        'url': {'required': True},
    }

    _attribute_map = {
        'url': {'key': 'url', 'type': 'str'},
    }

    def __init__(self, *, url: str, **kwargs) -> None:
        super(ImageUrl, self).__init__(**kwargs)
        self.url = url


class Prediction(Model):
    """Prediction result.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar probability: Probability of the tag.
    :vartype probability: float
    :ivar tag_id: Id of the predicted tag.
    :vartype tag_id: str
    :ivar tag_name: Name of the predicted tag.
    :vartype tag_name: str
    :ivar bounding_box: Bounding box of the prediction.
    :vartype bounding_box:
     ~azure.cognitiveservices.vision.customvision.prediction.models.BoundingBox
    :ivar tag_type: Type of the predicted tag. Possible values include:
     'Regular', 'Negative', 'GeneralProduct'
    :vartype tag_type: str or
     ~azure.cognitiveservices.vision.customvision.prediction.models.TagType
    """

    _validation = {
        'probability': {'readonly': True},
        'tag_id': {'readonly': True},
        'tag_name': {'readonly': True},
        'bounding_box': {'readonly': True},
        'tag_type': {'readonly': True},
    }

    _attribute_map = {
        'probability': {'key': 'probability', 'type': 'float'},
        'tag_id': {'key': 'tagId', 'type': 'str'},
        'tag_name': {'key': 'tagName', 'type': 'str'},
        'bounding_box': {'key': 'boundingBox', 'type': 'BoundingBox'},
        'tag_type': {'key': 'tagType', 'type': 'str'},
    }

    def __init__(self, **kwargs) -> None:
        super(Prediction, self).__init__(**kwargs)
        self.probability = None
        self.tag_id = None
        self.tag_name = None
        self.bounding_box = None
        self.tag_type = None
