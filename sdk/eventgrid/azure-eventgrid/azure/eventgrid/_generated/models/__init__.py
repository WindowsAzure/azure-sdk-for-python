# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

try:
    from ._models_py3 import ACSChatEventBaseProperties
    from ._models_py3 import ACSChatMemberAddedToThreadWithUserEventData
    from ._models_py3 import ACSChatMemberRemovedFromThreadWithUserEventData
    from ._models_py3 import ACSChatMessageDeletedEventData
    from ._models_py3 import ACSChatMessageEditedEventData
    from ._models_py3 import ACSChatMessageEventBaseProperties
    from ._models_py3 import ACSChatMessageReceivedEventData
    from ._models_py3 import ACSChatThreadCreatedWithUserEventData
    from ._models_py3 import ACSChatThreadEventBaseProperties
    from ._models_py3 import ACSChatThreadMemberProperties
    from ._models_py3 import ACSChatThreadPropertiesUpdatedPerUserEventData
    from ._models_py3 import ACSChatThreadWithUserDeletedEventData
    from ._models_py3 import ACSSMSDeliveryAttemptProperties
    from ._models_py3 import ACSSMSDeliveryReportReceivedEventData
    from ._models_py3 import ACSSMSEventBaseProperties
    from ._models_py3 import ACSSMSReceivedEventData
    from ._models_py3 import AppConfigurationKeyValueDeletedEventData
    from ._models_py3 import AppConfigurationKeyValueModifiedEventData
    from ._models_py3 import AppEventTypeDetail
    from ._models_py3 import AppServicePlanEventTypeDetail
    from ._models_py3 import CloudEvent
    from ._models_py3 import ContainerRegistryArtifactEventData
    from ._models_py3 import ContainerRegistryArtifactEventTarget
    from ._models_py3 import ContainerRegistryChartDeletedEventData
    from ._models_py3 import ContainerRegistryChartPushedEventData
    from ._models_py3 import ContainerRegistryEventActor
    from ._models_py3 import ContainerRegistryEventData
    from ._models_py3 import ContainerRegistryEventRequest
    from ._models_py3 import ContainerRegistryEventSource
    from ._models_py3 import ContainerRegistryEventTarget
    from ._models_py3 import ContainerRegistryImageDeletedEventData
    from ._models_py3 import ContainerRegistryImagePushedEventData
    from ._models_py3 import DeviceConnectionStateEventInfo
    from ._models_py3 import DeviceConnectionStateEventProperties
    from ._models_py3 import DeviceLifeCycleEventProperties
    from ._models_py3 import DeviceTelemetryEventProperties
    from ._models_py3 import DeviceTwinInfo
    from ._models_py3 import DeviceTwinInfoProperties
    from ._models_py3 import DeviceTwinInfoX509Thumbprint
    from ._models_py3 import DeviceTwinMetadata
    from ._models_py3 import DeviceTwinProperties
    from ._models_py3 import EventGridEvent
    from ._models_py3 import EventHubCaptureFileCreatedEventData
    from ._models_py3 import IotHubDeviceConnectedEventData
    from ._models_py3 import IotHubDeviceCreatedEventData
    from ._models_py3 import IotHubDeviceDeletedEventData
    from ._models_py3 import IotHubDeviceDisconnectedEventData
    from ._models_py3 import IotHubDeviceTelemetryEventData
    from ._models_py3 import KeyVaultAccessPolicyChangedEventData
    from ._models_py3 import KeyVaultCertificateExpiredEventData
    from ._models_py3 import KeyVaultCertificateNearExpiryEventData
    from ._models_py3 import KeyVaultCertificateNewVersionCreatedEventData
    from ._models_py3 import KeyVaultKeyExpiredEventData
    from ._models_py3 import KeyVaultKeyNearExpiryEventData
    from ._models_py3 import KeyVaultKeyNewVersionCreatedEventData
    from ._models_py3 import KeyVaultSecretExpiredEventData
    from ._models_py3 import KeyVaultSecretNearExpiryEventData
    from ._models_py3 import KeyVaultSecretNewVersionCreatedEventData
    from ._models_py3 import MachineLearningServicesDatasetDriftDetectedEventData
    from ._models_py3 import MachineLearningServicesModelDeployedEventData
    from ._models_py3 import MachineLearningServicesModelRegisteredEventData
    from ._models_py3 import MachineLearningServicesRunCompletedEventData
    from ._models_py3 import MachineLearningServicesRunStatusChangedEventData
    from ._models_py3 import MapsGeofenceEnteredEventData
    from ._models_py3 import MapsGeofenceEventProperties
    from ._models_py3 import MapsGeofenceExitedEventData
    from ._models_py3 import MapsGeofenceGeometry
    from ._models_py3 import MapsGeofenceResultEventData
    from ._models_py3 import MediaJobCanceledEventData
    from ._models_py3 import MediaJobCancelingEventData
    from ._models_py3 import MediaJobError
    from ._models_py3 import MediaJobErrorDetail
    from ._models_py3 import MediaJobErroredEventData
    from ._models_py3 import MediaJobFinishedEventData
    from ._models_py3 import MediaJobOutput
    from ._models_py3 import MediaJobOutputAsset
    from ._models_py3 import MediaJobOutputCanceledEventData
    from ._models_py3 import MediaJobOutputCancelingEventData
    from ._models_py3 import MediaJobOutputErroredEventData
    from ._models_py3 import MediaJobOutputFinishedEventData
    from ._models_py3 import MediaJobOutputProcessingEventData
    from ._models_py3 import MediaJobOutputProgressEventData
    from ._models_py3 import MediaJobOutputScheduledEventData
    from ._models_py3 import MediaJobOutputStateChangeEventData
    from ._models_py3 import MediaJobProcessingEventData
    from ._models_py3 import MediaJobScheduledEventData
    from ._models_py3 import MediaJobStateChangeEventData
    from ._models_py3 import MediaLiveEventConnectionRejectedEventData
    from ._models_py3 import MediaLiveEventEncoderConnectedEventData
    from ._models_py3 import MediaLiveEventEncoderDisconnectedEventData
    from ._models_py3 import MediaLiveEventIncomingDataChunkDroppedEventData
    from ._models_py3 import MediaLiveEventIncomingStreamReceivedEventData
    from ._models_py3 import MediaLiveEventIncomingStreamsOutOfSyncEventData
    from ._models_py3 import MediaLiveEventIncomingVideoStreamsOutOfSyncEventData
    from ._models_py3 import MediaLiveEventIngestHeartbeatEventData
    from ._models_py3 import MediaLiveEventTrackDiscontinuityDetectedEventData
    from ._models_py3 import RedisExportRDBCompletedEventData
    from ._models_py3 import RedisImportRDBCompletedEventData
    from ._models_py3 import RedisPatchingCompletedEventData
    from ._models_py3 import RedisScalingCompletedEventData
    from ._models_py3 import ResourceActionCancelData
    from ._models_py3 import ResourceActionFailureData
    from ._models_py3 import ResourceActionSuccessData
    from ._models_py3 import ResourceDeleteCancelData
    from ._models_py3 import ResourceDeleteFailureData
    from ._models_py3 import ResourceDeleteSuccessData
    from ._models_py3 import ResourceWriteCancelData
    from ._models_py3 import ResourceWriteFailureData
    from ._models_py3 import ResourceWriteSuccessData
    from ._models_py3 import ServiceBusActiveMessagesAvailableWithNoListenersEventData
    from ._models_py3 import ServiceBusDeadletterMessagesAvailableWithNoListenersEventData
    from ._models_py3 import SignalRServiceClientConnectionConnectedEventData
    from ._models_py3 import SignalRServiceClientConnectionDisconnectedEventData
    from ._models_py3 import StorageBlobCreatedEventData
    from ._models_py3 import StorageBlobDeletedEventData
    from ._models_py3 import StorageBlobRenamedEventData
    from ._models_py3 import StorageDirectoryCreatedEventData
    from ._models_py3 import StorageDirectoryDeletedEventData
    from ._models_py3 import StorageDirectoryRenamedEventData
    from ._models_py3 import StorageLifecyclePolicyActionSummaryDetail
    from ._models_py3 import StorageLifecyclePolicyCompletedEventData
    from ._models_py3 import SubscriptionDeletedEventData
    from ._models_py3 import SubscriptionValidationEventData
    from ._models_py3 import SubscriptionValidationResponse
    from ._models_py3 import WebAppServicePlanUpdatedEventData
    from ._models_py3 import WebAppServicePlanUpdatedEventDataSku
    from ._models_py3 import WebAppUpdatedEventData
    from ._models_py3 import WebBackupOperationCompletedEventData
    from ._models_py3 import WebBackupOperationFailedEventData
    from ._models_py3 import WebBackupOperationStartedEventData
    from ._models_py3 import WebRestoreOperationCompletedEventData
    from ._models_py3 import WebRestoreOperationFailedEventData
    from ._models_py3 import WebRestoreOperationStartedEventData
    from ._models_py3 import WebSlotSwapCompletedEventData
    from ._models_py3 import WebSlotSwapFailedEventData
    from ._models_py3 import WebSlotSwapStartedEventData
    from ._models_py3 import WebSlotSwapWithPreviewCancelledEventData
    from ._models_py3 import WebSlotSwapWithPreviewStartedEventData
except (SyntaxError, ImportError):
    from ._models import ACSChatEventBaseProperties  # type: ignore
    from ._models import ACSChatMemberAddedToThreadWithUserEventData  # type: ignore
    from ._models import ACSChatMemberRemovedFromThreadWithUserEventData  # type: ignore
    from ._models import ACSChatMessageDeletedEventData  # type: ignore
    from ._models import ACSChatMessageEditedEventData  # type: ignore
    from ._models import ACSChatMessageEventBaseProperties  # type: ignore
    from ._models import ACSChatMessageReceivedEventData  # type: ignore
    from ._models import ACSChatThreadCreatedWithUserEventData  # type: ignore
    from ._models import ACSChatThreadEventBaseProperties  # type: ignore
    from ._models import ACSChatThreadMemberProperties  # type: ignore
    from ._models import ACSChatThreadPropertiesUpdatedPerUserEventData  # type: ignore
    from ._models import ACSChatThreadWithUserDeletedEventData  # type: ignore
    from ._models import ACSSMSDeliveryAttemptProperties  # type: ignore
    from ._models import ACSSMSDeliveryReportReceivedEventData  # type: ignore
    from ._models import ACSSMSEventBaseProperties  # type: ignore
    from ._models import ACSSMSReceivedEventData  # type: ignore
    from ._models import AppConfigurationKeyValueDeletedEventData  # type: ignore
    from ._models import AppConfigurationKeyValueModifiedEventData  # type: ignore
    from ._models import AppEventTypeDetail  # type: ignore
    from ._models import AppServicePlanEventTypeDetail  # type: ignore
    from ._models import CloudEvent  # type: ignore
    from ._models import ContainerRegistryArtifactEventData  # type: ignore
    from ._models import ContainerRegistryArtifactEventTarget  # type: ignore
    from ._models import ContainerRegistryChartDeletedEventData  # type: ignore
    from ._models import ContainerRegistryChartPushedEventData  # type: ignore
    from ._models import ContainerRegistryEventActor  # type: ignore
    from ._models import ContainerRegistryEventData  # type: ignore
    from ._models import ContainerRegistryEventRequest  # type: ignore
    from ._models import ContainerRegistryEventSource  # type: ignore
    from ._models import ContainerRegistryEventTarget  # type: ignore
    from ._models import ContainerRegistryImageDeletedEventData  # type: ignore
    from ._models import ContainerRegistryImagePushedEventData  # type: ignore
    from ._models import DeviceConnectionStateEventInfo  # type: ignore
    from ._models import DeviceConnectionStateEventProperties  # type: ignore
    from ._models import DeviceLifeCycleEventProperties  # type: ignore
    from ._models import DeviceTelemetryEventProperties  # type: ignore
    from ._models import DeviceTwinInfo  # type: ignore
    from ._models import DeviceTwinInfoProperties  # type: ignore
    from ._models import DeviceTwinInfoX509Thumbprint  # type: ignore
    from ._models import DeviceTwinMetadata  # type: ignore
    from ._models import DeviceTwinProperties  # type: ignore
    from ._models import EventGridEvent  # type: ignore
    from ._models import EventHubCaptureFileCreatedEventData  # type: ignore
    from ._models import IotHubDeviceConnectedEventData  # type: ignore
    from ._models import IotHubDeviceCreatedEventData  # type: ignore
    from ._models import IotHubDeviceDeletedEventData  # type: ignore
    from ._models import IotHubDeviceDisconnectedEventData  # type: ignore
    from ._models import IotHubDeviceTelemetryEventData  # type: ignore
    from ._models import KeyVaultAccessPolicyChangedEventData  # type: ignore
    from ._models import KeyVaultCertificateExpiredEventData  # type: ignore
    from ._models import KeyVaultCertificateNearExpiryEventData  # type: ignore
    from ._models import KeyVaultCertificateNewVersionCreatedEventData  # type: ignore
    from ._models import KeyVaultKeyExpiredEventData  # type: ignore
    from ._models import KeyVaultKeyNearExpiryEventData  # type: ignore
    from ._models import KeyVaultKeyNewVersionCreatedEventData  # type: ignore
    from ._models import KeyVaultSecretExpiredEventData  # type: ignore
    from ._models import KeyVaultSecretNearExpiryEventData  # type: ignore
    from ._models import KeyVaultSecretNewVersionCreatedEventData  # type: ignore
    from ._models import MachineLearningServicesDatasetDriftDetectedEventData  # type: ignore
    from ._models import MachineLearningServicesModelDeployedEventData  # type: ignore
    from ._models import MachineLearningServicesModelRegisteredEventData  # type: ignore
    from ._models import MachineLearningServicesRunCompletedEventData  # type: ignore
    from ._models import MachineLearningServicesRunStatusChangedEventData  # type: ignore
    from ._models import MapsGeofenceEnteredEventData  # type: ignore
    from ._models import MapsGeofenceEventProperties  # type: ignore
    from ._models import MapsGeofenceExitedEventData  # type: ignore
    from ._models import MapsGeofenceGeometry  # type: ignore
    from ._models import MapsGeofenceResultEventData  # type: ignore
    from ._models import MediaJobCanceledEventData  # type: ignore
    from ._models import MediaJobCancelingEventData  # type: ignore
    from ._models import MediaJobError  # type: ignore
    from ._models import MediaJobErrorDetail  # type: ignore
    from ._models import MediaJobErroredEventData  # type: ignore
    from ._models import MediaJobFinishedEventData  # type: ignore
    from ._models import MediaJobOutput  # type: ignore
    from ._models import MediaJobOutputAsset  # type: ignore
    from ._models import MediaJobOutputCanceledEventData  # type: ignore
    from ._models import MediaJobOutputCancelingEventData  # type: ignore
    from ._models import MediaJobOutputErroredEventData  # type: ignore
    from ._models import MediaJobOutputFinishedEventData  # type: ignore
    from ._models import MediaJobOutputProcessingEventData  # type: ignore
    from ._models import MediaJobOutputProgressEventData  # type: ignore
    from ._models import MediaJobOutputScheduledEventData  # type: ignore
    from ._models import MediaJobOutputStateChangeEventData  # type: ignore
    from ._models import MediaJobProcessingEventData  # type: ignore
    from ._models import MediaJobScheduledEventData  # type: ignore
    from ._models import MediaJobStateChangeEventData  # type: ignore
    from ._models import MediaLiveEventConnectionRejectedEventData  # type: ignore
    from ._models import MediaLiveEventEncoderConnectedEventData  # type: ignore
    from ._models import MediaLiveEventEncoderDisconnectedEventData  # type: ignore
    from ._models import MediaLiveEventIncomingDataChunkDroppedEventData  # type: ignore
    from ._models import MediaLiveEventIncomingStreamReceivedEventData  # type: ignore
    from ._models import MediaLiveEventIncomingStreamsOutOfSyncEventData  # type: ignore
    from ._models import MediaLiveEventIncomingVideoStreamsOutOfSyncEventData  # type: ignore
    from ._models import MediaLiveEventIngestHeartbeatEventData  # type: ignore
    from ._models import MediaLiveEventTrackDiscontinuityDetectedEventData  # type: ignore
    from ._models import RedisExportRDBCompletedEventData  # type: ignore
    from ._models import RedisImportRDBCompletedEventData  # type: ignore
    from ._models import RedisPatchingCompletedEventData  # type: ignore
    from ._models import RedisScalingCompletedEventData  # type: ignore
    from ._models import ResourceActionCancelData  # type: ignore
    from ._models import ResourceActionFailureData  # type: ignore
    from ._models import ResourceActionSuccessData  # type: ignore
    from ._models import ResourceDeleteCancelData  # type: ignore
    from ._models import ResourceDeleteFailureData  # type: ignore
    from ._models import ResourceDeleteSuccessData  # type: ignore
    from ._models import ResourceWriteCancelData  # type: ignore
    from ._models import ResourceWriteFailureData  # type: ignore
    from ._models import ResourceWriteSuccessData  # type: ignore
    from ._models import ServiceBusActiveMessagesAvailableWithNoListenersEventData  # type: ignore
    from ._models import ServiceBusDeadletterMessagesAvailableWithNoListenersEventData  # type: ignore
    from ._models import SignalRServiceClientConnectionConnectedEventData  # type: ignore
    from ._models import SignalRServiceClientConnectionDisconnectedEventData  # type: ignore
    from ._models import StorageBlobCreatedEventData  # type: ignore
    from ._models import StorageBlobDeletedEventData  # type: ignore
    from ._models import StorageBlobRenamedEventData  # type: ignore
    from ._models import StorageDirectoryCreatedEventData  # type: ignore
    from ._models import StorageDirectoryDeletedEventData  # type: ignore
    from ._models import StorageDirectoryRenamedEventData  # type: ignore
    from ._models import StorageLifecyclePolicyActionSummaryDetail  # type: ignore
    from ._models import StorageLifecyclePolicyCompletedEventData  # type: ignore
    from ._models import SubscriptionDeletedEventData  # type: ignore
    from ._models import SubscriptionValidationEventData  # type: ignore
    from ._models import SubscriptionValidationResponse  # type: ignore
    from ._models import WebAppServicePlanUpdatedEventData  # type: ignore
    from ._models import WebAppServicePlanUpdatedEventDataSku  # type: ignore
    from ._models import WebAppUpdatedEventData  # type: ignore
    from ._models import WebBackupOperationCompletedEventData  # type: ignore
    from ._models import WebBackupOperationFailedEventData  # type: ignore
    from ._models import WebBackupOperationStartedEventData  # type: ignore
    from ._models import WebRestoreOperationCompletedEventData  # type: ignore
    from ._models import WebRestoreOperationFailedEventData  # type: ignore
    from ._models import WebRestoreOperationStartedEventData  # type: ignore
    from ._models import WebSlotSwapCompletedEventData  # type: ignore
    from ._models import WebSlotSwapFailedEventData  # type: ignore
    from ._models import WebSlotSwapStartedEventData  # type: ignore
    from ._models import WebSlotSwapWithPreviewCancelledEventData  # type: ignore
    from ._models import WebSlotSwapWithPreviewStartedEventData  # type: ignore

from ._event_grid_publisher_client_enums import (
    AppAction,
    AppServicePlanAction,
    AsyncStatus,
    MediaJobErrorCategory,
    MediaJobErrorCode,
    MediaJobRetry,
    MediaJobState,
    StampKind,
)

__all__ = [
    'ACSChatEventBaseProperties',
    'ACSChatMemberAddedToThreadWithUserEventData',
    'ACSChatMemberRemovedFromThreadWithUserEventData',
    'ACSChatMessageDeletedEventData',
    'ACSChatMessageEditedEventData',
    'ACSChatMessageEventBaseProperties',
    'ACSChatMessageReceivedEventData',
    'ACSChatThreadCreatedWithUserEventData',
    'ACSChatThreadEventBaseProperties',
    'ACSChatThreadMemberProperties',
    'ACSChatThreadPropertiesUpdatedPerUserEventData',
    'ACSChatThreadWithUserDeletedEventData',
    'ACSSMSDeliveryAttemptProperties',
    'ACSSMSDeliveryReportReceivedEventData',
    'ACSSMSEventBaseProperties',
    'ACSSMSReceivedEventData',
    'AppConfigurationKeyValueDeletedEventData',
    'AppConfigurationKeyValueModifiedEventData',
    'AppEventTypeDetail',
    'AppServicePlanEventTypeDetail',
    'CloudEvent',
    'ContainerRegistryArtifactEventData',
    'ContainerRegistryArtifactEventTarget',
    'ContainerRegistryChartDeletedEventData',
    'ContainerRegistryChartPushedEventData',
    'ContainerRegistryEventActor',
    'ContainerRegistryEventData',
    'ContainerRegistryEventRequest',
    'ContainerRegistryEventSource',
    'ContainerRegistryEventTarget',
    'ContainerRegistryImageDeletedEventData',
    'ContainerRegistryImagePushedEventData',
    'DeviceConnectionStateEventInfo',
    'DeviceConnectionStateEventProperties',
    'DeviceLifeCycleEventProperties',
    'DeviceTelemetryEventProperties',
    'DeviceTwinInfo',
    'DeviceTwinInfoProperties',
    'DeviceTwinInfoX509Thumbprint',
    'DeviceTwinMetadata',
    'DeviceTwinProperties',
    'EventGridEvent',
    'EventHubCaptureFileCreatedEventData',
    'IotHubDeviceConnectedEventData',
    'IotHubDeviceCreatedEventData',
    'IotHubDeviceDeletedEventData',
    'IotHubDeviceDisconnectedEventData',
    'IotHubDeviceTelemetryEventData',
    'KeyVaultAccessPolicyChangedEventData',
    'KeyVaultCertificateExpiredEventData',
    'KeyVaultCertificateNearExpiryEventData',
    'KeyVaultCertificateNewVersionCreatedEventData',
    'KeyVaultKeyExpiredEventData',
    'KeyVaultKeyNearExpiryEventData',
    'KeyVaultKeyNewVersionCreatedEventData',
    'KeyVaultSecretExpiredEventData',
    'KeyVaultSecretNearExpiryEventData',
    'KeyVaultSecretNewVersionCreatedEventData',
    'MachineLearningServicesDatasetDriftDetectedEventData',
    'MachineLearningServicesModelDeployedEventData',
    'MachineLearningServicesModelRegisteredEventData',
    'MachineLearningServicesRunCompletedEventData',
    'MachineLearningServicesRunStatusChangedEventData',
    'MapsGeofenceEnteredEventData',
    'MapsGeofenceEventProperties',
    'MapsGeofenceExitedEventData',
    'MapsGeofenceGeometry',
    'MapsGeofenceResultEventData',
    'MediaJobCanceledEventData',
    'MediaJobCancelingEventData',
    'MediaJobError',
    'MediaJobErrorDetail',
    'MediaJobErroredEventData',
    'MediaJobFinishedEventData',
    'MediaJobOutput',
    'MediaJobOutputAsset',
    'MediaJobOutputCanceledEventData',
    'MediaJobOutputCancelingEventData',
    'MediaJobOutputErroredEventData',
    'MediaJobOutputFinishedEventData',
    'MediaJobOutputProcessingEventData',
    'MediaJobOutputProgressEventData',
    'MediaJobOutputScheduledEventData',
    'MediaJobOutputStateChangeEventData',
    'MediaJobProcessingEventData',
    'MediaJobScheduledEventData',
    'MediaJobStateChangeEventData',
    'MediaLiveEventConnectionRejectedEventData',
    'MediaLiveEventEncoderConnectedEventData',
    'MediaLiveEventEncoderDisconnectedEventData',
    'MediaLiveEventIncomingDataChunkDroppedEventData',
    'MediaLiveEventIncomingStreamReceivedEventData',
    'MediaLiveEventIncomingStreamsOutOfSyncEventData',
    'MediaLiveEventIncomingVideoStreamsOutOfSyncEventData',
    'MediaLiveEventIngestHeartbeatEventData',
    'MediaLiveEventTrackDiscontinuityDetectedEventData',
    'RedisExportRDBCompletedEventData',
    'RedisImportRDBCompletedEventData',
    'RedisPatchingCompletedEventData',
    'RedisScalingCompletedEventData',
    'ResourceActionCancelData',
    'ResourceActionFailureData',
    'ResourceActionSuccessData',
    'ResourceDeleteCancelData',
    'ResourceDeleteFailureData',
    'ResourceDeleteSuccessData',
    'ResourceWriteCancelData',
    'ResourceWriteFailureData',
    'ResourceWriteSuccessData',
    'ServiceBusActiveMessagesAvailableWithNoListenersEventData',
    'ServiceBusDeadletterMessagesAvailableWithNoListenersEventData',
    'SignalRServiceClientConnectionConnectedEventData',
    'SignalRServiceClientConnectionDisconnectedEventData',
    'StorageBlobCreatedEventData',
    'StorageBlobDeletedEventData',
    'StorageBlobRenamedEventData',
    'StorageDirectoryCreatedEventData',
    'StorageDirectoryDeletedEventData',
    'StorageDirectoryRenamedEventData',
    'StorageLifecyclePolicyActionSummaryDetail',
    'StorageLifecyclePolicyCompletedEventData',
    'SubscriptionDeletedEventData',
    'SubscriptionValidationEventData',
    'SubscriptionValidationResponse',
    'WebAppServicePlanUpdatedEventData',
    'WebAppServicePlanUpdatedEventDataSku',
    'WebAppUpdatedEventData',
    'WebBackupOperationCompletedEventData',
    'WebBackupOperationFailedEventData',
    'WebBackupOperationStartedEventData',
    'WebRestoreOperationCompletedEventData',
    'WebRestoreOperationFailedEventData',
    'WebRestoreOperationStartedEventData',
    'WebSlotSwapCompletedEventData',
    'WebSlotSwapFailedEventData',
    'WebSlotSwapStartedEventData',
    'WebSlotSwapWithPreviewCancelledEventData',
    'WebSlotSwapWithPreviewStartedEventData',
    'AppAction',
    'AppServicePlanAction',
    'AsyncStatus',
    'MediaJobErrorCategory',
    'MediaJobErrorCode',
    'MediaJobRetry',
    'MediaJobState',
    'StampKind',
]
