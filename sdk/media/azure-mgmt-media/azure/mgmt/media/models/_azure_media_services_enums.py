# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from enum import Enum, EnumMeta
from six import with_metaclass

class _CaseInsensitiveEnumMeta(EnumMeta):
    def __getitem__(self, name):
        return super().__getitem__(name.upper())

    def __getattr__(cls, name):
        """Return the enum member matching `name`
        We use __getattr__ instead of descriptors or inserting into the enum
        class' __dict__ in order to support `name` and `value` being both
        properties for enum members (which live in the class' __dict__) and
        enum members themselves.
        """
        try:
            return cls._member_map_[name.upper()]
        except KeyError:
            raise AttributeError(name)


class AacAudioProfile(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The encoding profile to be used when encoding audio with AAC.
    """

    AAC_LC = "AacLc"  #: Specifies that the output audio is to be encoded into AAC Low Complexity profile (AAC-LC).
    HE_AAC_V1 = "HeAacV1"  #: Specifies that the output audio is to be encoded into HE-AAC v1 profile.
    HE_AAC_V2 = "HeAacV2"  #: Specifies that the output audio is to be encoded into HE-AAC v2 profile.

class AccountEncryptionKeyType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The type of key used to encrypt the Account Key.
    """

    SYSTEM_KEY = "SystemKey"  #: The Account Key is encrypted with a System Key.
    CUSTOMER_KEY = "CustomerKey"  #: The Account Key is encrypted with a Customer Key.

class AnalysisResolution(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Specifies the maximum resolution at which your video is analyzed. The default behavior is
    "SourceResolution," which will keep the input video at its original resolution when analyzed.
    Using "StandardDefinition" will resize input videos to standard definition while preserving the
    appropriate aspect ratio. It will only resize if the video is of higher resolution. For
    example, a 1920x1080 input would be scaled to 640x360 before processing. Switching to
    "StandardDefinition" will reduce the time it takes to process high resolution video. It may
    also reduce the cost of using this component (see https://azure.microsoft.com/en-
    us/pricing/details/media-services/#analytics for details). However, faces that end up being too
    small in the resized video may not be detected.
    """

    SOURCE_RESOLUTION = "SourceResolution"
    STANDARD_DEFINITION = "StandardDefinition"

class AssetContainerPermission(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The permissions to set on the SAS URL.
    """

    READ = "Read"  #: The SAS URL will allow read access to the container.
    READ_WRITE = "ReadWrite"  #: The SAS URL will allow read and write access to the container.
    READ_WRITE_DELETE = "ReadWriteDelete"  #: The SAS URL will allow read, write and delete access to the container.

class AssetStorageEncryptionFormat(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The Asset encryption format. One of None or MediaStorageEncryption.
    """

    NONE = "None"  #: The Asset does not use client-side storage encryption (this is the only allowed value for new Assets).
    MEDIA_STORAGE_CLIENT_ENCRYPTION = "MediaStorageClientEncryption"  #: The Asset is encrypted with Media Services client-side encryption.

class AudioAnalysisMode(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Determines the set of audio analysis operations to be performed. If unspecified, the Standard
    AudioAnalysisMode would be chosen.
    """

    STANDARD = "Standard"  #: Performs all operations included in the Basic mode, additionally performing language detection and speaker diarization.
    BASIC = "Basic"  #: This mode performs speech-to-text transcription and generation of a VTT subtitle/caption file. The output of this mode includes an Insights JSON file including only the keywords, transcription,and timing information. Automatic language detection and speaker diarization are not included in this mode.

class ContentKeyPolicyFairPlayRentalAndLeaseKeyType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The rental and lease key type.
    """

    UNKNOWN = "Unknown"  #: Represents a ContentKeyPolicyFairPlayRentalAndLeaseKeyType that is unavailable in current API version.
    UNDEFINED = "Undefined"  #: Key duration is not specified.
    DUAL_EXPIRY = "DualExpiry"  #: Dual expiry for offline rental.
    PERSISTENT_UNLIMITED = "PersistentUnlimited"  #: Content key can be persisted with an unlimited duration.
    PERSISTENT_LIMITED = "PersistentLimited"  #: Content key can be persisted and the valid duration is limited by the Rental Duration value.

class ContentKeyPolicyPlayReadyContentType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The PlayReady content type.
    """

    UNKNOWN = "Unknown"  #: Represents a ContentKeyPolicyPlayReadyContentType that is unavailable in current API version.
    UNSPECIFIED = "Unspecified"  #: Unspecified content type.
    ULTRA_VIOLET_DOWNLOAD = "UltraVioletDownload"  #: Ultraviolet download content type.
    ULTRA_VIOLET_STREAMING = "UltraVioletStreaming"  #: Ultraviolet streaming content type.

class ContentKeyPolicyPlayReadyLicenseType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The license type.
    """

    UNKNOWN = "Unknown"  #: Represents a ContentKeyPolicyPlayReadyLicenseType that is unavailable in current API version.
    NON_PERSISTENT = "NonPersistent"  #: Non persistent license.
    PERSISTENT = "Persistent"  #: Persistent license. Allows offline playback.

class ContentKeyPolicyPlayReadyUnknownOutputPassingOption(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Configures Unknown output handling settings of the license.
    """

    UNKNOWN = "Unknown"  #: Represents a ContentKeyPolicyPlayReadyUnknownOutputPassingOption that is unavailable in current API version.
    NOT_ALLOWED = "NotAllowed"  #: Passing the video portion of protected content to an Unknown Output is not allowed.
    ALLOWED = "Allowed"  #: Passing the video portion of protected content to an Unknown Output is allowed.
    ALLOWED_WITH_VIDEO_CONSTRICTION = "AllowedWithVideoConstriction"  #: Passing the video portion of protected content to an Unknown Output is allowed but with constrained resolution.

class ContentKeyPolicyRestrictionTokenType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The type of token.
    """

    UNKNOWN = "Unknown"  #: Represents a ContentKeyPolicyRestrictionTokenType that is unavailable in current API version.
    SWT = "Swt"  #: Simple Web Token.
    JWT = "Jwt"  #: JSON Web Token.

class DeinterlaceMode(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The deinterlacing mode. Defaults to AutoPixelAdaptive.
    """

    OFF = "Off"  #: Disables de-interlacing of the source video.
    AUTO_PIXEL_ADAPTIVE = "AutoPixelAdaptive"  #: Apply automatic pixel adaptive de-interlacing on each frame in the input video.

class DeinterlaceParity(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The field parity for de-interlacing, defaults to Auto.
    """

    AUTO = "Auto"  #: Automatically detect the order of fields.
    TOP_FIELD_FIRST = "TopFieldFirst"  #: Apply top field first processing of input video.
    BOTTOM_FIELD_FIRST = "BottomFieldFirst"  #: Apply bottom field first processing of input video.

class EncoderNamedPreset(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The built-in preset to be used for encoding videos.
    """

    H264_SINGLE_BITRATE_SD = "H264SingleBitrateSD"  #: Produces an MP4 file where the video is encoded with H.264 codec at 2200 kbps and a picture height of 480 pixels, and the stereo audio is encoded with AAC-LC codec at 128 kbps.
    H264_SINGLE_BITRATE720_P = "H264SingleBitrate720p"  #: Produces an MP4 file where the video is encoded with H.264 codec at 4500 kbps and a picture height of 720 pixels, and the stereo audio is encoded with AAC-LC codec at 128 kbps.
    H264_SINGLE_BITRATE1080_P = "H264SingleBitrate1080p"  #: Produces an MP4 file where the video is encoded with H.264 codec at 6750 kbps and a picture height of 1080 pixels, and the stereo audio is encoded with AAC-LC codec at 128 kbps.
    ADAPTIVE_STREAMING = "AdaptiveStreaming"  #: Produces a set of GOP aligned MP4 files with H.264 video and stereo AAC audio. Auto-generates a bitrate ladder based on the input resolution, bitrate and frame rate. The auto-generated preset will never exceed the input resolution. For example, if the input is 720p, output will remain 720p at best.
    AAC_GOOD_QUALITY_AUDIO = "AACGoodQualityAudio"  #: Produces a single MP4 file containing only stereo audio encoded at 192 kbps.
    CONTENT_AWARE_ENCODING_EXPERIMENTAL = "ContentAwareEncodingExperimental"  #: Exposes an experimental preset for content-aware encoding. Given any input content, the service attempts to automatically determine the optimal number of layers, appropriate bitrate and resolution settings for delivery by adaptive streaming. The underlying algorithms will continue to evolve over time. The output will contain MP4 files with video and audio interleaved.
    CONTENT_AWARE_ENCODING = "ContentAwareEncoding"  #: Produces a set of GOP-aligned MP4s by using content-aware encoding. Given any input content, the service performs an initial lightweight analysis of the input content, and uses the results to determine the optimal number of layers, appropriate bitrate and resolution settings for delivery by adaptive streaming. This preset is particularly effective for low and medium complexity videos, where the output files will be at lower bitrates but at a quality that still delivers a good experience to viewers. The output will contain MP4 files with video and audio interleaved.
    COPY_ALL_BITRATE_NON_INTERLEAVED = "CopyAllBitrateNonInterleaved"  #: Copy all video and audio streams from the input asset as non-interleaved video and audio output files. This preset can be used to clip an existing asset or convert a group of key frame (GOP) aligned MP4 files as an asset that can be streamed.
    H264_MULTIPLE_BITRATE1080_P = "H264MultipleBitrate1080p"  #: Produces a set of 8 GOP-aligned MP4 files, ranging from 6000 kbps to 400 kbps, and stereo AAC audio. Resolution starts at 1080p and goes down to 180p.
    H264_MULTIPLE_BITRATE720_P = "H264MultipleBitrate720p"  #: Produces a set of 6 GOP-aligned MP4 files, ranging from 3400 kbps to 400 kbps, and stereo AAC audio. Resolution starts at 720p and goes down to 180p.
    H264_MULTIPLE_BITRATE_SD = "H264MultipleBitrateSD"  #: Produces a set of 5 GOP-aligned MP4 files, ranging from 1900kbps to 400 kbps, and stereo AAC audio. Resolution starts at 480p and goes down to 240p.

class EncryptionScheme(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Encryption scheme
    """

    NO_ENCRYPTION = "NoEncryption"  #: NoEncryption scheme.
    ENVELOPE_ENCRYPTION = "EnvelopeEncryption"  #: EnvelopeEncryption scheme.
    COMMON_ENCRYPTION_CENC = "CommonEncryptionCenc"  #: CommonEncryptionCenc scheme.
    COMMON_ENCRYPTION_CBCS = "CommonEncryptionCbcs"  #: CommonEncryptionCbcs scheme.

class EntropyMode(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The entropy mode to be used for this layer. If not specified, the encoder chooses the mode that
    is appropriate for the profile and level.
    """

    CABAC = "Cabac"  #: Context Adaptive Binary Arithmetic Coder (CABAC) entropy encoding.
    CAVLC = "Cavlc"  #: Context Adaptive Variable Length Coder (CAVLC) entropy encoding.

class FilterTrackPropertyCompareOperation(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The track property condition operation.
    """

    EQUAL = "Equal"  #: The equal operation.
    NOT_EQUAL = "NotEqual"  #: The not equal operation.

class FilterTrackPropertyType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The track property type.
    """

    UNKNOWN = "Unknown"  #: The unknown track property type.
    TYPE = "Type"  #: The type.
    NAME = "Name"  #: The name.
    LANGUAGE = "Language"  #: The language.
    FOUR_CC = "FourCC"  #: The fourCC.
    BITRATE = "Bitrate"  #: The bitrate.

class H264Complexity(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Tells the encoder how to choose its encoding settings. The default value is Balanced.
    """

    SPEED = "Speed"  #: Tells the encoder to use settings that are optimized for faster encoding. Quality is sacrificed to decrease encoding time.
    BALANCED = "Balanced"  #: Tells the encoder to use settings that achieve a balance between speed and quality.
    QUALITY = "Quality"  #: Tells the encoder to use settings that are optimized to produce higher quality output at the expense of slower overall encode time.

class H264VideoProfile(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """We currently support Baseline, Main, High, High422, High444. Default is Auto.
    """

    AUTO = "Auto"  #: Tells the encoder to automatically determine the appropriate H.264 profile.
    BASELINE = "Baseline"  #: Baseline profile.
    MAIN = "Main"  #: Main profile.
    HIGH = "High"  #: High profile.
    HIGH422 = "High422"  #: High 4:2:2 profile.
    HIGH444 = "High444"  #: High 4:4:4 predictive profile.

class InsightsType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Defines the type of insights that you want the service to generate. The allowed values are
    'AudioInsightsOnly', 'VideoInsightsOnly', and 'AllInsights'. The default is AllInsights. If you
    set this to AllInsights and the input is audio only, then only audio insights are generated.
    Similarly if the input is video only, then only video insights are generated. It is recommended
    that you not use AudioInsightsOnly if you expect some of your inputs to be video only; or use
    VideoInsightsOnly if you expect some of your inputs to be audio only. Your Jobs in such
    conditions would error out.
    """

    AUDIO_INSIGHTS_ONLY = "AudioInsightsOnly"  #: Generate audio only insights. Ignore video even if present. Fails if no audio is present.
    VIDEO_INSIGHTS_ONLY = "VideoInsightsOnly"  #: Generate video only insights. Ignore audio if present. Fails if no video is present.
    ALL_INSIGHTS = "AllInsights"  #: Generate both audio and video insights. Fails if either audio or video Insights fail.

class JobErrorCategory(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Helps with categorization of errors.
    """

    SERVICE = "Service"  #: The error is service related.
    DOWNLOAD = "Download"  #: The error is download related.
    UPLOAD = "Upload"  #: The error is upload related.
    CONFIGURATION = "Configuration"  #: The error is configuration related.
    CONTENT = "Content"  #: The error is related to data in the input files.

class JobErrorCode(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Error code describing the error.
    """

    SERVICE_ERROR = "ServiceError"  #: Fatal service error, please contact support.
    SERVICE_TRANSIENT_ERROR = "ServiceTransientError"  #: Transient error, please retry, if retry is unsuccessful, please contact support.
    DOWNLOAD_NOT_ACCESSIBLE = "DownloadNotAccessible"  #: While trying to download the input files, the files were not accessible, please check the availability of the source.
    DOWNLOAD_TRANSIENT_ERROR = "DownloadTransientError"  #: While trying to download the input files, there was an issue during transfer (storage service, network errors), see details and check your source.
    UPLOAD_NOT_ACCESSIBLE = "UploadNotAccessible"  #: While trying to upload the output files, the destination was not reachable, please check the availability of the destination.
    UPLOAD_TRANSIENT_ERROR = "UploadTransientError"  #: While trying to upload the output files, there was an issue during transfer (storage service, network errors), see details and check your destination.
    CONFIGURATION_UNSUPPORTED = "ConfigurationUnsupported"  #: There was a problem with the combination of input files and the configuration settings applied, fix the configuration settings and retry with the same input, or change input to match the configuration.
    CONTENT_MALFORMED = "ContentMalformed"  #: There was a problem with the input content (for example: zero byte files, or corrupt/non-decodable files), check the input files.
    CONTENT_UNSUPPORTED = "ContentUnsupported"  #: There was a problem with the format of the input (not valid media file, or an unsupported file/codec), check the validity of the input files.

class JobRetry(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Indicates that it may be possible to retry the Job. If retry is unsuccessful, please contact
    Azure support via Azure Portal.
    """

    DO_NOT_RETRY = "DoNotRetry"  #: Issue needs to be investigated and then the job resubmitted with corrections or retried once the underlying issue has been corrected.
    MAY_RETRY = "MayRetry"  #: Issue may be resolved after waiting for a period of time and resubmitting the same Job.

class JobState(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Describes the state of the JobOutput.
    """

    CANCELED = "Canceled"  #: The job was canceled. This is a final state for the job.
    CANCELING = "Canceling"  #: The job is in the process of being canceled. This is a transient state for the job.
    ERROR = "Error"  #: The job has encountered an error. This is a final state for the job.
    FINISHED = "Finished"  #: The job is finished. This is a final state for the job.
    PROCESSING = "Processing"  #: The job is processing. This is a transient state for the job.
    QUEUED = "Queued"  #: The job is in a queued state, waiting for resources to become available. This is a transient state.
    SCHEDULED = "Scheduled"  #: The job is being scheduled to run on an available resource. This is a transient state, between queued and processing states.

class LiveEventEncodingType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Live event type. When encodingType is set to None, the service simply passes through the
    incoming video and audio layer(s) to the output. When encodingType is set to Standard or
    Premium1080p, a live encoder transcodes the incoming stream into multiple bitrates or layers.
    See https://go.microsoft.com/fwlink/?linkid=2095101 for more information. This property cannot
    be modified after the live event is created.
    """

    NONE = "None"  #: A contribution live encoder sends a multiple bitrate stream. The ingested stream passes through the live event without any further processing. It is also called the pass-through mode.
    STANDARD = "Standard"  #: A contribution live encoder sends a single bitrate stream to the live event and Media Services creates multiple bitrate streams. The output cannot exceed 720p in resolution.
    PREMIUM1080_P = "Premium1080p"  #: A contribution live encoder sends a single bitrate stream to the live event and Media Services creates multiple bitrate streams. The output cannot exceed 1080p in resolution.

class LiveEventInputProtocol(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The input protocol for the live event. This is specified at creation time and cannot be
    updated.
    """

    FRAGMENTED_MP4 = "FragmentedMP4"  #: Smooth Streaming input will be sent by the contribution encoder to the live event.
    RTMP = "RTMP"  #: RTMP input will be sent by the contribution encoder to the live event.

class LiveEventResourceState(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The resource state of the live event. See https://go.microsoft.com/fwlink/?linkid=2139012 for
    more information.
    """

    STOPPED = "Stopped"  #: This is the initial state of the live event after creation (unless autostart was set to true.) No billing occurs in this state. In this state, the live event properties can be updated but streaming is not allowed.
    ALLOCATING = "Allocating"  #: Allocate action was called on the live event and resources are being provisioned for this live event. Once allocation completes successfully, the live event will transition to StandBy state.
    STAND_BY = "StandBy"  #: Live event resources have been provisioned and is ready to start. Billing occurs in this state. Most properties can still be updated, however ingest or streaming is not allowed during this state.
    STARTING = "Starting"  #: The live event is being started and resources are being allocated. No billing occurs in this state. Updates or streaming are not allowed during this state. If an error occurs, the live event returns to the Stopped state.
    RUNNING = "Running"  #: The live event resources have been allocated, ingest and preview URLs have been generated, and it is capable of receiving live streams. At this point, billing is active. You must explicitly call Stop on the live event resource to halt further billing.
    STOPPING = "Stopping"  #: The live event is being stopped and resources are being de-provisioned. No billing occurs in this transient state. Updates or streaming are not allowed during this state.
    DELETING = "Deleting"  #: The live event is being deleted. No billing occurs in this transient state. Updates or streaming are not allowed during this state.

class LiveOutputResourceState(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The resource state of the live output.
    """

    CREATING = "Creating"  #: Live output is being created. No content is archived in the asset until the live output is in running state.
    RUNNING = "Running"  #: Live output is running and archiving live streaming content to the asset if there is valid input from a contribution encoder.
    DELETING = "Deleting"  #: Live output is being deleted. The live asset is being converted from live to on-demand asset. Any streaming URLs created on the live output asset continue to work.

class ManagedIdentityType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The identity type.
    """

    SYSTEM_ASSIGNED = "SystemAssigned"  #: A system-assigned managed identity.
    NONE = "None"  #: No managed identity.

class MetricAggregationType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The metric aggregation type
    """

    AVERAGE = "Average"  #: The average.
    COUNT = "Count"  #: The count of a number of items, usually requests.
    TOTAL = "Total"  #: The sum.

class MetricUnit(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The metric unit
    """

    BYTES = "Bytes"  #: The number of bytes.
    COUNT = "Count"  #: The count.
    MILLISECONDS = "Milliseconds"  #: The number of milliseconds.

class OnErrorType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """A Transform can define more than one outputs. This property defines what the service should do
    when one output fails - either continue to produce other outputs, or, stop the other outputs.
    The overall Job state will not reflect failures of outputs that are specified with
    'ContinueJob'. The default is 'StopProcessingJob'.
    """

    STOP_PROCESSING_JOB = "StopProcessingJob"  #: Tells the service that if this TransformOutput fails, then any other incomplete TransformOutputs can be stopped.
    CONTINUE_JOB = "ContinueJob"  #: Tells the service that if this TransformOutput fails, then allow any other TransformOutput to continue.

class Priority(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Sets the relative priority of the TransformOutputs within a Transform. This sets the priority
    that the service uses for processing TransformOutputs. The default priority is Normal.
    """

    LOW = "Low"  #: Used for TransformOutputs that can be generated after Normal and High priority TransformOutputs.
    NORMAL = "Normal"  #: Used for TransformOutputs that can be generated at Normal priority.
    HIGH = "High"  #: Used for TransformOutputs that should take precedence over others.

class PrivateEndpointConnectionProvisioningState(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The current provisioning state.
    """

    SUCCEEDED = "Succeeded"
    CREATING = "Creating"
    DELETING = "Deleting"
    FAILED = "Failed"

class PrivateEndpointServiceConnectionStatus(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The private endpoint connection status.
    """

    PENDING = "Pending"
    APPROVED = "Approved"
    REJECTED = "Rejected"

class Rotation(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The rotation, if any, to be applied to the input video, before it is encoded. Default is Auto
    """

    AUTO = "Auto"  #: Automatically detect and rotate as needed.
    NONE = "None"  #: Do not rotate the video.  If the output format supports it, any metadata about rotation is kept intact.
    ROTATE0 = "Rotate0"  #: Do not rotate the video but remove any metadata about the rotation.
    ROTATE90 = "Rotate90"  #: Rotate 90 degrees clockwise.
    ROTATE180 = "Rotate180"  #: Rotate 180 degrees clockwise.
    ROTATE270 = "Rotate270"  #: Rotate 270 degrees clockwise.

class StorageAccountType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The type of the storage account.
    """

    PRIMARY = "Primary"  #: The primary storage account for the Media Services account.
    SECONDARY = "Secondary"  #: A secondary storage account for the Media Services account.

class StorageAuthentication(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):

    SYSTEM = "System"  #: System authentication.
    MANAGED_IDENTITY = "ManagedIdentity"  #: Managed Identity authentication.

class StreamingEndpointResourceState(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The resource state of the streaming endpoint.
    """

    STOPPED = "Stopped"  #: The initial state of a streaming endpoint after creation. Content is not ready to be streamed from this endpoint.
    STARTING = "Starting"  #: The streaming endpoint is transitioning to the running state.
    RUNNING = "Running"  #: The streaming endpoint is running. It is able to stream content to clients.
    STOPPING = "Stopping"  #: The streaming endpoint is transitioning to the stopped state.
    DELETING = "Deleting"  #: The streaming endpoint is being deleted.
    SCALING = "Scaling"  #: The streaming endpoint is increasing or decreasing scale units.

class StreamingLocatorContentKeyType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Encryption type of Content Key
    """

    COMMON_ENCRYPTION_CENC = "CommonEncryptionCenc"  #: Common Encryption using CENC.
    COMMON_ENCRYPTION_CBCS = "CommonEncryptionCbcs"  #: Common Encryption using CBCS.
    ENVELOPE_ENCRYPTION = "EnvelopeEncryption"  #: Envelope Encryption.

class StreamingPolicyStreamingProtocol(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Streaming protocol
    """

    HLS = "Hls"  #: HLS protocol.
    DASH = "Dash"  #: DASH protocol.
    SMOOTH_STREAMING = "SmoothStreaming"  #: SmoothStreaming protocol.
    DOWNLOAD = "Download"  #: Download protocol.

class StreamOptionsFlag(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):

    DEFAULT = "Default"  #: Live streaming with no special latency optimizations.
    LOW_LATENCY = "LowLatency"  #: The live event provides lower end to end latency by reducing its internal buffers. This could result in more client buffering during playback if network bandwidth is low.

class StretchMode(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The resizing mode - how the input video will be resized to fit the desired output
    resolution(s). Default is AutoSize
    """

    NONE = "None"  #: Strictly respect the output resolution without considering the pixel aspect ratio or display aspect ratio of the input video.
    AUTO_SIZE = "AutoSize"  #: Override the output resolution, and change it to match the display aspect ratio of the input, without padding. For example, if the input is 1920x1080 and the encoding preset asks for 1280x1280, then the value in the preset is overridden, and the output will be at 1280x720, which maintains the input aspect ratio of 16:9.
    AUTO_FIT = "AutoFit"  #: Pad the output (with either letterbox or pillar box) to honor the output resolution, while ensuring that the active video region in the output has the same aspect ratio as the input. For example, if the input is 1920x1080 and the encoding preset asks for 1280x1280, then the output will be at 1280x1280, which contains an inner rectangle of 1280x720 at aspect ratio of 16:9, and pillar box regions 280 pixels wide at the left and right.

class TrackPropertyCompareOperation(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Track property condition operation
    """

    UNKNOWN = "Unknown"  #: Unknown track property compare operation.
    EQUAL = "Equal"  #: Equal operation.

class TrackPropertyType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Track property type
    """

    UNKNOWN = "Unknown"  #: Unknown track property.
    FOUR_CC = "FourCC"  #: Track FourCC.

class VideoSyncMode(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The Video Sync Mode
    """

    AUTO = "Auto"  #: This is the default method. Chooses between Cfr and Vfr depending on muxer capabilities. For output format MP4, the default mode is Cfr.
    PASSTHROUGH = "Passthrough"  #: The presentation timestamps on frames are passed through from the input file to the output file writer. Recommended when the input source has variable frame rate, and are attempting to produce multiple layers for adaptive streaming in the output which have aligned GOP boundaries. Note: if two or more frames in the input have duplicate timestamps, then the output will also have the same behavior.
    CFR = "Cfr"  #: Input frames will be repeated and/or dropped as needed to achieve exactly the requested constant frame rate. Recommended when the output frame rate is explicitly set at a specified value.
    VFR = "Vfr"  #: Similar to the Passthrough mode, but if the input has frames that have duplicate timestamps, then only one frame is passed through to the output, and others are dropped. Recommended when the number of output frames is expected to be equal to the number of input frames. For example, the output is used to calculate a quality metric like PSNR against the input.
