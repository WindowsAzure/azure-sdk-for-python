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


class AnalyzeResult(Model):
    """Analyze API call result.

    :param status: Status of the analyze operation. Possible values include:
     'success', 'partialSuccess', 'failure'
    :type status: str or ~azure.cognitiveservices.formrecognizer.models.enum
    :param pages: Page level information extracted in the analyzed
     document.
    :type pages:
     list[~azure.cognitiveservices.formrecognizer.models.ExtractedPage]
    :param errors: List of errors reported during the analyze
     operation.
    :type errors:
     list[~azure.cognitiveservices.formrecognizer.models.FormOperationError]
    """

    _attribute_map = {
        'status': {'key': 'status', 'type': 'str'},
        'pages': {'key': 'pages', 'type': '[ExtractedPage]'},
        'errors': {'key': 'errors', 'type': '[FormOperationError]'},
    }

    def __init__(self, *, status=None, pages=None, errors=None, **kwargs) -> None:
        super(AnalyzeResult, self).__init__(**kwargs)
        self.status = status
        self.pages = pages
        self.errors = errors


class ComputerVisionError(Model):
    """Details about the API request error.

    All required parameters must be populated in order to send to Azure.

    :param code: Required. The error code.
    :type code: object
    :param message: Required. A message explaining the error reported by the
     service.
    :type message: str
    :param request_id: A unique request identifier.
    :type request_id: str
    """

    _validation = {
        'code': {'required': True},
        'message': {'required': True},
    }

    _attribute_map = {
        'code': {'key': 'code', 'type': 'object'},
        'message': {'key': 'message', 'type': 'str'},
        'request_id': {'key': 'requestId', 'type': 'str'},
    }

    def __init__(self, *, code, message: str, request_id: str=None, **kwargs) -> None:
        super(ComputerVisionError, self).__init__(**kwargs)
        self.code = code
        self.message = message
        self.request_id = request_id


class ComputerVisionErrorException(HttpOperationError):
    """Server responsed with exception of type: 'ComputerVisionError'.

    :param deserialize: A deserializer
    :param response: Server response to be deserialized.
    """

    def __init__(self, deserialize, response, *args):

        super(ComputerVisionErrorException, self).__init__(deserialize, response, 'ComputerVisionError', *args)


class ElementReference(Model):
    """Reference to an OCR word.

    :param ref:
    :type ref: str
    """

    _attribute_map = {
        'ref': {'key': '$ref', 'type': 'str'},
    }

    def __init__(self, *, ref: str=None, **kwargs) -> None:
        super(ElementReference, self).__init__(**kwargs)
        self.ref = ref


class ErrorInformation(Model):
    """ErrorInformation.

    :param code:
    :type code: str
    :param inner_error:
    :type inner_error:
     ~azure.cognitiveservices.formrecognizer.models.InnerError
    :param message:
    :type message: str
    """

    _attribute_map = {
        'code': {'key': 'code', 'type': 'str'},
        'inner_error': {'key': 'innerError', 'type': 'InnerError'},
        'message': {'key': 'message', 'type': 'str'},
    }

    def __init__(self, *, code: str=None, inner_error=None, message: str=None, **kwargs) -> None:
        super(ErrorInformation, self).__init__(**kwargs)
        self.code = code
        self.inner_error = inner_error
        self.message = message


class ErrorResponse(Model):
    """ErrorResponse.

    :param error:
    :type error:
     ~azure.cognitiveservices.formrecognizer.models.ErrorInformation
    """

    _attribute_map = {
        'error': {'key': 'error', 'type': 'ErrorInformation'},
    }

    def __init__(self, *, error=None, **kwargs) -> None:
        super(ErrorResponse, self).__init__(**kwargs)
        self.error = error


class ErrorResponseException(HttpOperationError):
    """Server responsed with exception of type: 'ErrorResponse'.

    :param deserialize: A deserializer
    :param response: Server response to be deserialized.
    """

    def __init__(self, deserialize, response, *args):

        super(ErrorResponseException, self).__init__(deserialize, response, 'ErrorResponse', *args)


class ExtractedKeyValuePair(Model):
    """Representation of a key-value pair as a list
    of key and value tokens.

    :param key: List of tokens for the extracted key in a key-value pair.
    :type key:
     list[~azure.cognitiveservices.formrecognizer.models.ExtractedToken]
    :param value: List of tokens for the extracted value in a key-value pair.
    :type value:
     list[~azure.cognitiveservices.formrecognizer.models.ExtractedToken]
    """

    _attribute_map = {
        'key': {'key': 'key', 'type': '[ExtractedToken]'},
        'value': {'key': 'value', 'type': '[ExtractedToken]'},
    }

    def __init__(self, *, key=None, value=None, **kwargs) -> None:
        super(ExtractedKeyValuePair, self).__init__(**kwargs)
        self.key = key
        self.value = value


class ExtractedPage(Model):
    """Extraction information of a single page in a
    with a document.

    :param number: Page number.
    :type number: int
    :param height: Height of the page (in pixels).
    :type height: int
    :param width: Width of the page (in pixels).
    :type width: int
    :param cluster_id: Cluster identifier.
    :type cluster_id: int
    :param key_value_pairs: List of Key-Value pairs extracted from the page.
    :type key_value_pairs:
     list[~azure.cognitiveservices.formrecognizer.models.ExtractedKeyValuePair]
    :param tables: List of Tables and their information extracted from the
     page.
    :type tables:
     list[~azure.cognitiveservices.formrecognizer.models.ExtractedTable]
    """

    _attribute_map = {
        'number': {'key': 'number', 'type': 'int'},
        'height': {'key': 'height', 'type': 'int'},
        'width': {'key': 'width', 'type': 'int'},
        'cluster_id': {'key': 'clusterId', 'type': 'int'},
        'key_value_pairs': {'key': 'keyValuePairs', 'type': '[ExtractedKeyValuePair]'},
        'tables': {'key': 'tables', 'type': '[ExtractedTable]'},
    }

    def __init__(self, *, number: int=None, height: int=None, width: int=None, cluster_id: int=None, key_value_pairs=None, tables=None, **kwargs) -> None:
        super(ExtractedPage, self).__init__(**kwargs)
        self.number = number
        self.height = height
        self.width = width
        self.cluster_id = cluster_id
        self.key_value_pairs = key_value_pairs
        self.tables = tables


class ExtractedTable(Model):
    """Extraction information about a table
    contained in a page.

    :param id: Table identifier.
    :type id: str
    :param columns: List of columns contained in the table.
    :type columns:
     list[~azure.cognitiveservices.formrecognizer.models.ExtractedTableColumn]
    """

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'columns': {'key': 'columns', 'type': '[ExtractedTableColumn]'},
    }

    def __init__(self, *, id: str=None, columns=None, **kwargs) -> None:
        super(ExtractedTable, self).__init__(**kwargs)
        self.id = id
        self.columns = columns


class ExtractedTableColumn(Model):
    """Extraction information of a column in
    a table.

    :param header: List of extracted tokens for the column header.
    :type header:
     list[~azure.cognitiveservices.formrecognizer.models.ExtractedToken]
    :param entries: Extracted text for each cell of a column. Each cell
     in the column can have a list of one or more tokens.
    :type entries:
     list[list[~azure.cognitiveservices.formrecognizer.models.ExtractedToken]]
    """

    _attribute_map = {
        'header': {'key': 'header', 'type': '[ExtractedToken]'},
        'entries': {'key': 'entries', 'type': '[[ExtractedToken]]'},
    }

    def __init__(self, *, header=None, entries=None, **kwargs) -> None:
        super(ExtractedTableColumn, self).__init__(**kwargs)
        self.header = header
        self.entries = entries


class ExtractedToken(Model):
    """Canonical representation of single extracted text.

    :param text: String value of the extracted text.
    :type text: str
    :param bounding_box: Bounding box of the extracted text. Represents the
     location of the extracted text as a pair of
     cartesian co-ordinates. The co-ordinate pairs are arranged by
     top-left, top-right, bottom-right and bottom-left endpoints box
     with origin reference from the bottom-left of the page.
    :type bounding_box: list[float]
    :param confidence: A measure of accuracy of the extracted text.
    :type confidence: float
    """

    _attribute_map = {
        'text': {'key': 'text', 'type': 'str'},
        'bounding_box': {'key': 'boundingBox', 'type': '[float]'},
        'confidence': {'key': 'confidence', 'type': 'float'},
    }

    def __init__(self, *, text: str=None, bounding_box=None, confidence: float=None, **kwargs) -> None:
        super(ExtractedToken, self).__init__(**kwargs)
        self.text = text
        self.bounding_box = bounding_box
        self.confidence = confidence


class FieldValue(Model):
    """Base class representing a recognized field value.

    You probably want to use the sub-classes and not this class directly. Known
    sub-classes are: StringValue, NumberValue

    All required parameters must be populated in order to send to Azure.

    :param text: OCR text content of the recognized field.
    :type text: str
    :param elements: List of references to OCR words comprising the recognized
     field value.
    :type elements:
     list[~azure.cognitiveservices.formrecognizer.models.ElementReference]
    :param value_type: Required. Constant filled by server.
    :type value_type: str
    """

    _validation = {
        'value_type': {'required': True},
    }

    _attribute_map = {
        'text': {'key': 'text', 'type': 'str'},
        'elements': {'key': 'elements', 'type': '[ElementReference]'},
        'value_type': {'key': 'valueType', 'type': 'str'},
    }

    _subtype_map = {
        'value_type': {'stringValue': 'StringValue', 'numberValue': 'NumberValue'}
    }

    def __init__(self, *, text: str=None, elements=None, **kwargs) -> None:
        super(FieldValue, self).__init__(**kwargs)
        self.text = text
        self.elements = elements
        self.value_type = None


class FormDocumentReport(Model):
    """FormDocumentReport.

    :param document_name: Reference to the data that the report is for.
    :type document_name: str
    :param pages: Total number of pages trained on.
    :type pages: int
    :param errors: List of errors per page.
    :type errors: list[str]
    :param status: Status of the training operation. Possible values include:
     'success', 'partialSuccess', 'failure'
    :type status: str or ~azure.cognitiveservices.formrecognizer.models.enum
    """

    _attribute_map = {
        'document_name': {'key': 'documentName', 'type': 'str'},
        'pages': {'key': 'pages', 'type': 'int'},
        'errors': {'key': 'errors', 'type': '[str]'},
        'status': {'key': 'status', 'type': 'str'},
    }

    def __init__(self, *, document_name: str=None, pages: int=None, errors=None, status=None, **kwargs) -> None:
        super(FormDocumentReport, self).__init__(**kwargs)
        self.document_name = document_name
        self.pages = pages
        self.errors = errors
        self.status = status


class FormOperationError(Model):
    """Error reported during an operation.

    :param error_message: Message reported during the train operation.
    :type error_message: str
    """

    _attribute_map = {
        'error_message': {'key': 'errorMessage', 'type': 'str'},
    }

    def __init__(self, *, error_message: str=None, **kwargs) -> None:
        super(FormOperationError, self).__init__(**kwargs)
        self.error_message = error_message


class ImageUrl(Model):
    """ImageUrl.

    All required parameters must be populated in order to send to Azure.

    :param url: Required. Publicly reachable URL of an image.
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


class InnerError(Model):
    """InnerError.

    :param request_id:
    :type request_id: str
    """

    _attribute_map = {
        'request_id': {'key': 'requestId', 'type': 'str'},
    }

    def __init__(self, *, request_id: str=None, **kwargs) -> None:
        super(InnerError, self).__init__(**kwargs)
        self.request_id = request_id


class KeysResult(Model):
    """Result of an operation to get
    the keys extracted by a model.

    :param clusters: Object mapping ClusterIds to Key lists.
    :type clusters: dict[str, list[str]]
    """

    _attribute_map = {
        'clusters': {'key': 'clusters', 'type': '{[str]}'},
    }

    def __init__(self, *, clusters=None, **kwargs) -> None:
        super(KeysResult, self).__init__(**kwargs)
        self.clusters = clusters


class Line(Model):
    """An object representing a recognized text line.

    :param bounding_box: Bounding box of a recognized line.
    :type bounding_box: list[int]
    :param text: The text content of the line.
    :type text: str
    :param words: List of words in the text line.
    :type words: list[~azure.cognitiveservices.formrecognizer.models.Word]
    """

    _attribute_map = {
        'bounding_box': {'key': 'boundingBox', 'type': '[int]'},
        'text': {'key': 'text', 'type': 'str'},
        'words': {'key': 'words', 'type': '[Word]'},
    }

    def __init__(self, *, bounding_box=None, text: str=None, words=None, **kwargs) -> None:
        super(Line, self).__init__(**kwargs)
        self.bounding_box = bounding_box
        self.text = text
        self.words = words


class ModelResult(Model):
    """Result of a model status query operation.

    :param model_id: Get or set model identifier.
    :type model_id: str
    :param status: Get or set the status of model. Possible values include:
     'created', 'ready', 'invalid'
    :type status: str or ~azure.cognitiveservices.formrecognizer.models.enum
    :param created_date_time: Get or set the created date time of the model.
    :type created_date_time: datetime
    :param last_updated_date_time: Get or set the model last updated datetime.
    :type last_updated_date_time: datetime
    """

    _attribute_map = {
        'model_id': {'key': 'modelId', 'type': 'str'},
        'status': {'key': 'status', 'type': 'str'},
        'created_date_time': {'key': 'createdDateTime', 'type': 'iso-8601'},
        'last_updated_date_time': {'key': 'lastUpdatedDateTime', 'type': 'iso-8601'},
    }

    def __init__(self, *, model_id: str=None, status=None, created_date_time=None, last_updated_date_time=None, **kwargs) -> None:
        super(ModelResult, self).__init__(**kwargs)
        self.model_id = model_id
        self.status = status
        self.created_date_time = created_date_time
        self.last_updated_date_time = last_updated_date_time


class ModelsResult(Model):
    """Result of query operation to fetch multiple models.

    :param models_property: Collection of models.
    :type models_property:
     list[~azure.cognitiveservices.formrecognizer.models.ModelResult]
    """

    _attribute_map = {
        'models_property': {'key': 'models', 'type': '[ModelResult]'},
    }

    def __init__(self, *, models_property=None, **kwargs) -> None:
        super(ModelsResult, self).__init__(**kwargs)
        self.models_property = models_property


class NumberValue(FieldValue):
    """Recognized numeric field value.

    All required parameters must be populated in order to send to Azure.

    :param text: OCR text content of the recognized field.
    :type text: str
    :param elements: List of references to OCR words comprising the recognized
     field value.
    :type elements:
     list[~azure.cognitiveservices.formrecognizer.models.ElementReference]
    :param value_type: Required. Constant filled by server.
    :type value_type: str
    :param value: Numeric value of the recognized field.
    :type value: float
    """

    _validation = {
        'value_type': {'required': True},
    }

    _attribute_map = {
        'text': {'key': 'text', 'type': 'str'},
        'elements': {'key': 'elements', 'type': '[ElementReference]'},
        'value_type': {'key': 'valueType', 'type': 'str'},
        'value': {'key': 'value', 'type': 'float'},
    }

    def __init__(self, *, text: str=None, elements=None, value: float=None, **kwargs) -> None:
        super(NumberValue, self).__init__(text=text, elements=elements, **kwargs)
        self.value = value
        self.value_type = 'numberValue'


class ReadReceiptResult(Model):
    """Analysis result of the 'Batch Read Receipt' operation.

    :param status: Status of the read operation. Possible values include: 'Not
     Started', 'Running', 'Failed', 'Succeeded'
    :type status: str or
     ~azure.cognitiveservices.formrecognizer.models.TextOperationStatusCodes
    :param recognition_results: Text recognition result of the 'Batch Read
     Receipt' operation.
    :type recognition_results:
     list[~azure.cognitiveservices.formrecognizer.models.TextRecognitionResult]
    :param understanding_results: Semantic understanding result of the 'Batch
     Read Receipt' operation.
    :type understanding_results:
     list[~azure.cognitiveservices.formrecognizer.models.UnderstandingResult]
    """

    _attribute_map = {
        'status': {'key': 'status', 'type': 'TextOperationStatusCodes'},
        'recognition_results': {'key': 'recognitionResults', 'type': '[TextRecognitionResult]'},
        'understanding_results': {'key': 'understandingResults', 'type': '[UnderstandingResult]'},
    }

    def __init__(self, *, status=None, recognition_results=None, understanding_results=None, **kwargs) -> None:
        super(ReadReceiptResult, self).__init__(**kwargs)
        self.status = status
        self.recognition_results = recognition_results
        self.understanding_results = understanding_results


class StringValue(FieldValue):
    """Recognized string field value.

    All required parameters must be populated in order to send to Azure.

    :param text: OCR text content of the recognized field.
    :type text: str
    :param elements: List of references to OCR words comprising the recognized
     field value.
    :type elements:
     list[~azure.cognitiveservices.formrecognizer.models.ElementReference]
    :param value_type: Required. Constant filled by server.
    :type value_type: str
    :param value: String value of the recognized field.
    :type value: str
    """

    _validation = {
        'value_type': {'required': True},
    }

    _attribute_map = {
        'text': {'key': 'text', 'type': 'str'},
        'elements': {'key': 'elements', 'type': '[ElementReference]'},
        'value_type': {'key': 'valueType', 'type': 'str'},
        'value': {'key': 'value', 'type': 'str'},
    }

    def __init__(self, *, text: str=None, elements=None, value: str=None, **kwargs) -> None:
        super(StringValue, self).__init__(text=text, elements=elements, **kwargs)
        self.value = value
        self.value_type = 'stringValue'


class TextRecognitionResult(Model):
    """An object representing a recognized text region.

    All required parameters must be populated in order to send to Azure.

    :param page: The 1-based page number of the recognition result.
    :type page: int
    :param clockwise_orientation: The orientation of the image in degrees in
     the clockwise direction. Range between [0, 360).
    :type clockwise_orientation: float
    :param width: The width of the image in pixels or the PDF in inches.
    :type width: float
    :param height: The height of the image in pixels or the PDF in inches.
    :type height: float
    :param unit: The unit used in the Width, Height and BoundingBox. For
     images, the unit is 'pixel'. For PDF, the unit is 'inch'. Possible values
     include: 'pixel', 'inch'
    :type unit: str or
     ~azure.cognitiveservices.formrecognizer.models.TextRecognitionResultDimensionUnit
    :param lines: Required. A list of recognized text lines.
    :type lines: list[~azure.cognitiveservices.formrecognizer.models.Line]
    """

    _validation = {
        'lines': {'required': True},
    }

    _attribute_map = {
        'page': {'key': 'page', 'type': 'int'},
        'clockwise_orientation': {'key': 'clockwiseOrientation', 'type': 'float'},
        'width': {'key': 'width', 'type': 'float'},
        'height': {'key': 'height', 'type': 'float'},
        'unit': {'key': 'unit', 'type': 'TextRecognitionResultDimensionUnit'},
        'lines': {'key': 'lines', 'type': '[Line]'},
    }

    def __init__(self, *, lines, page: int=None, clockwise_orientation: float=None, width: float=None, height: float=None, unit=None, **kwargs) -> None:
        super(TextRecognitionResult, self).__init__(**kwargs)
        self.page = page
        self.clockwise_orientation = clockwise_orientation
        self.width = width
        self.height = height
        self.unit = unit
        self.lines = lines


class TrainRequest(Model):
    """Contract to initiate a train request.

    All required parameters must be populated in order to send to Azure.

    :param source: Required. Get or set source path.
    :type source: str
    :param source_filter: Get or set filter to further search the
     source path for content.
    :type source_filter:
     ~azure.cognitiveservices.formrecognizer.models.TrainSourceFilter
    """

    _validation = {
        'source': {'required': True, 'max_length': 2048, 'min_length': 0},
    }

    _attribute_map = {
        'source': {'key': 'source', 'type': 'str'},
        'source_filter': {'key': 'sourceFilter', 'type': 'TrainSourceFilter'},
    }

    def __init__(self, *, source: str, source_filter=None, **kwargs) -> None:
        super(TrainRequest, self).__init__(**kwargs)
        self.source = source
        self.source_filter = source_filter


class TrainResult(Model):
    """Response of the Train API call.

    :param model_id: Identifier of the model.
    :type model_id: str
    :param training_documents: List of documents used to train the model and
     the
     train operation error reported by each.
    :type training_documents:
     list[~azure.cognitiveservices.formrecognizer.models.FormDocumentReport]
    :param errors: Errors returned during the training operation.
    :type errors:
     list[~azure.cognitiveservices.formrecognizer.models.FormOperationError]
    """

    _attribute_map = {
        'model_id': {'key': 'modelId', 'type': 'str'},
        'training_documents': {'key': 'trainingDocuments', 'type': '[FormDocumentReport]'},
        'errors': {'key': 'errors', 'type': '[FormOperationError]'},
    }

    def __init__(self, *, model_id: str=None, training_documents=None, errors=None, **kwargs) -> None:
        super(TrainResult, self).__init__(**kwargs)
        self.model_id = model_id
        self.training_documents = training_documents
        self.errors = errors


class TrainSourceFilter(Model):
    """Filters to be applied when traversing a data source.

    :param prefix: A case-sensitive prefix string to filter content
     under the source location. For e.g., when using a Azure Blob
     Uri use the prefix to restrict subfolders for content.
    :type prefix: str
    :param include_sub_folders: A flag to indicate if sub folders within the
     set of
     prefix folders will also need to be included when searching
     for content to be preprocessed.
    :type include_sub_folders: bool
    """

    _validation = {
        'prefix': {'max_length': 128, 'min_length': 0},
    }

    _attribute_map = {
        'prefix': {'key': 'prefix', 'type': 'str'},
        'include_sub_folders': {'key': 'includeSubFolders', 'type': 'bool'},
    }

    def __init__(self, *, prefix: str=None, include_sub_folders: bool=None, **kwargs) -> None:
        super(TrainSourceFilter, self).__init__(**kwargs)
        self.prefix = prefix
        self.include_sub_folders = include_sub_folders


class UnderstandingResult(Model):
    """A set of extracted fields corresponding to a semantic object, such as a
    receipt, in the input document.

    :param pages: List of pages where the document is found.
    :type pages: list[int]
    :param fields: Dictionary of recognized field values.
    :type fields: dict[str,
     ~azure.cognitiveservices.formrecognizer.models.FieldValue]
    """

    _attribute_map = {
        'pages': {'key': 'pages', 'type': '[int]'},
        'fields': {'key': 'fields', 'type': '{FieldValue}'},
    }

    def __init__(self, *, pages=None, fields=None, **kwargs) -> None:
        super(UnderstandingResult, self).__init__(**kwargs)
        self.pages = pages
        self.fields = fields


class Word(Model):
    """An object representing a recognized word.

    All required parameters must be populated in order to send to Azure.

    :param bounding_box: Required. Bounding box of a recognized word.
    :type bounding_box: list[int]
    :param text: Required. The text content of the word.
    :type text: str
    :param confidence: Qualitative confidence measure. Possible values
     include: 'High', 'Low'
    :type confidence: str or
     ~azure.cognitiveservices.formrecognizer.models.TextRecognitionResultConfidenceClass
    """

    _validation = {
        'bounding_box': {'required': True},
        'text': {'required': True},
    }

    _attribute_map = {
        'bounding_box': {'key': 'boundingBox', 'type': '[int]'},
        'text': {'key': 'text', 'type': 'str'},
        'confidence': {'key': 'confidence', 'type': 'TextRecognitionResultConfidenceClass'},
    }

    def __init__(self, *, bounding_box, text: str, confidence=None, **kwargs) -> None:
        super(Word, self).__init__(**kwargs)
        self.bounding_box = bounding_box
        self.text = text
        self.confidence = confidence
