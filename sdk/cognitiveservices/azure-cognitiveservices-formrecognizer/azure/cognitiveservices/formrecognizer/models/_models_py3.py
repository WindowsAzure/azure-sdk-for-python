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


class AnalyzeOperationResult(Model):
    """Status and result of the queued analyze operation.

    All required parameters must be populated in order to send to Azure.

    :param status: Required. Operation status. Possible values include:
     'notStarted', 'running', 'succeeded', 'failed'
    :type status: str or
     ~azure.cognitiveservices.formrecognizer.models.OperationStatus
    :param created_date_time: Required. Date and time (UTC) when the analyze
     operation was submitted.
    :type created_date_time: datetime
    :param last_updated_date_time: Required. Date and time (UTC) when the
     status was last updated.
    :type last_updated_date_time: datetime
    :param analyze_result: Results of the analyze operation.
    :type analyze_result:
     ~azure.cognitiveservices.formrecognizer.models.AnalyzeResult
    """

    _validation = {
        'status': {'required': True},
        'created_date_time': {'required': True},
        'last_updated_date_time': {'required': True},
    }

    _attribute_map = {
        'status': {'key': 'status', 'type': 'OperationStatus'},
        'created_date_time': {'key': 'createdDateTime', 'type': 'iso-8601'},
        'last_updated_date_time': {'key': 'lastUpdatedDateTime', 'type': 'iso-8601'},
        'analyze_result': {'key': 'analyzeResult', 'type': 'AnalyzeResult'},
    }

    def __init__(self, *, status, created_date_time, last_updated_date_time, analyze_result=None, **kwargs) -> None:
        super(AnalyzeOperationResult, self).__init__(**kwargs)
        self.status = status
        self.created_date_time = created_date_time
        self.last_updated_date_time = last_updated_date_time
        self.analyze_result = analyze_result


class AnalyzeResult(Model):
    """Analyze operation result.

    All required parameters must be populated in order to send to Azure.

    :param version: Required. Version of schema used for this result.
    :type version: str
    :param read_results: Required. Text extracted from the input.
    :type read_results:
     list[~azure.cognitiveservices.formrecognizer.models.ReadResult]
    :param page_results: Page-level information extracted from the input.
    :type page_results:
     list[~azure.cognitiveservices.formrecognizer.models.PageResult]
    :param document_results: Document-level information extracted from the
     input.
    :type document_results:
     list[~azure.cognitiveservices.formrecognizer.models.DocumentResult]
    :param errors: List of errors reported during the analyze operation.
    :type errors:
     list[~azure.cognitiveservices.formrecognizer.models.ErrorInformation]
    """

    _validation = {
        'version': {'required': True},
        'read_results': {'required': True},
    }

    _attribute_map = {
        'version': {'key': 'version', 'type': 'str'},
        'read_results': {'key': 'readResults', 'type': '[ReadResult]'},
        'page_results': {'key': 'pageResults', 'type': '[PageResult]'},
        'document_results': {'key': 'documentResults', 'type': '[DocumentResult]'},
        'errors': {'key': 'errors', 'type': '[ErrorInformation]'},
    }

    def __init__(self, *, version: str, read_results, page_results=None, document_results=None, errors=None, **kwargs) -> None:
        super(AnalyzeResult, self).__init__(**kwargs)
        self.version = version
        self.read_results = read_results
        self.page_results = page_results
        self.document_results = document_results
        self.errors = errors


class DataTable(Model):
    """Information about the extracted table contained in a page.

    All required parameters must be populated in order to send to Azure.

    :param rows: Required. Number of rows.
    :type rows: int
    :param columns: Required. Number of columns.
    :type columns: int
    :param cells: Required. List of cells contained in the table.
    :type cells:
     list[~azure.cognitiveservices.formrecognizer.models.DataTableCell]
    """

    _validation = {
        'rows': {'required': True, 'minimum': 1},
        'columns': {'required': True, 'minimum': 1},
        'cells': {'required': True},
    }

    _attribute_map = {
        'rows': {'key': 'rows', 'type': 'int'},
        'columns': {'key': 'columns', 'type': 'int'},
        'cells': {'key': 'cells', 'type': '[DataTableCell]'},
    }

    def __init__(self, *, rows: int, columns: int, cells, **kwargs) -> None:
        super(DataTable, self).__init__(**kwargs)
        self.rows = rows
        self.columns = columns
        self.cells = cells


class DataTableCell(Model):
    """Information about the extracted cell in a table.

    All required parameters must be populated in order to send to Azure.

    :param row_index: Required. Row index of the cell.
    :type row_index: int
    :param column_index: Required. Column index of the cell.
    :type column_index: int
    :param row_span: Number of rows spanned by this cell. Default value: 1 .
    :type row_span: int
    :param column_span: Number of columns spanned by this cell. Default value:
     1 .
    :type column_span: int
    :param text: Required. Text content of the cell.
    :type text: str
    :param bounding_box: Required. Bounding box of the cell.
    :type bounding_box: list[float]
    :param confidence: Required. Confidence value.
    :type confidence: float
    :param elements: When includeTextDetails is set to true, a list of
     references to the text elements constituting this table cell.
    :type elements: list[str]
    :param is_header: Is the current cell a header cell?. Default value: False
     .
    :type is_header: bool
    :param is_footer: Is the current cell a footer cell?. Default value: False
     .
    :type is_footer: bool
    """

    _validation = {
        'row_index': {'required': True, 'minimum': 0},
        'column_index': {'required': True, 'minimum': 0},
        'row_span': {'minimum': 1},
        'column_span': {'minimum': 1},
        'text': {'required': True},
        'bounding_box': {'required': True},
        'confidence': {'required': True},
    }

    _attribute_map = {
        'row_index': {'key': 'rowIndex', 'type': 'int'},
        'column_index': {'key': 'columnIndex', 'type': 'int'},
        'row_span': {'key': 'rowSpan', 'type': 'int'},
        'column_span': {'key': 'columnSpan', 'type': 'int'},
        'text': {'key': 'text', 'type': 'str'},
        'bounding_box': {'key': 'boundingBox', 'type': '[float]'},
        'confidence': {'key': 'confidence', 'type': 'float'},
        'elements': {'key': 'elements', 'type': '[str]'},
        'is_header': {'key': 'isHeader', 'type': 'bool'},
        'is_footer': {'key': 'isFooter', 'type': 'bool'},
    }

    def __init__(self, *, row_index: int, column_index: int, text: str, bounding_box, confidence: float, row_span: int=1, column_span: int=1, elements=None, is_header: bool=False, is_footer: bool=False, **kwargs) -> None:
        super(DataTableCell, self).__init__(**kwargs)
        self.row_index = row_index
        self.column_index = column_index
        self.row_span = row_span
        self.column_span = column_span
        self.text = text
        self.bounding_box = bounding_box
        self.confidence = confidence
        self.elements = elements
        self.is_header = is_header
        self.is_footer = is_footer


class DocumentResult(Model):
    """A set of extracted fields corresponding to the input document.

    All required parameters must be populated in order to send to Azure.

    :param doc_type: Required. Document type.
    :type doc_type: str
    :param page_range: Required. First and last page number where the document
     is found.
    :type page_range: list[int]
    :param fields: Required. Dictionary of named field values.
    :type fields: dict[str,
     ~azure.cognitiveservices.formrecognizer.models.FieldValue]
    """

    _validation = {
        'doc_type': {'required': True},
        'page_range': {'required': True, 'max_items': 2, 'min_items': 2},
        'fields': {'required': True},
    }

    _attribute_map = {
        'doc_type': {'key': 'docType', 'type': 'str'},
        'page_range': {'key': 'pageRange', 'type': '[int]'},
        'fields': {'key': 'fields', 'type': '{FieldValue}'},
    }

    def __init__(self, *, doc_type: str, page_range, fields, **kwargs) -> None:
        super(DocumentResult, self).__init__(**kwargs)
        self.doc_type = doc_type
        self.page_range = page_range
        self.fields = fields


class ErrorInformation(Model):
    """ErrorInformation.

    All required parameters must be populated in order to send to Azure.

    :param code: Required.
    :type code: str
    :param message: Required.
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

    def __init__(self, *, code: str, message: str, **kwargs) -> None:
        super(ErrorInformation, self).__init__(**kwargs)
        self.code = code
        self.message = message


class ErrorResponse(Model):
    """ErrorResponse.

    All required parameters must be populated in order to send to Azure.

    :param error: Required.
    :type error:
     ~azure.cognitiveservices.formrecognizer.models.ErrorInformation
    """

    _validation = {
        'error': {'required': True},
    }

    _attribute_map = {
        'error': {'key': 'error', 'type': 'ErrorInformation'},
    }

    def __init__(self, *, error, **kwargs) -> None:
        super(ErrorResponse, self).__init__(**kwargs)
        self.error = error


class ErrorResponseException(HttpOperationError):
    """Server responsed with exception of type: 'ErrorResponse'.

    :param deserialize: A deserializer
    :param response: Server response to be deserialized.
    """

    def __init__(self, deserialize, response, *args):

        super(ErrorResponseException, self).__init__(deserialize, response, 'ErrorResponse', *args)


class FieldValue(Model):
    """Recognized field value.

    All required parameters must be populated in order to send to Azure.

    :param type: Required. Type of field value. Possible values include:
     'string', 'date', 'time', 'phoneNumber', 'number', 'integer', 'array',
     'object'
    :type type: str or
     ~azure.cognitiveservices.formrecognizer.models.FieldValueType
    :param value_string: String value.
    :type value_string: str
    :param value_date: Date value.
    :type value_date: date
    :param value_time: Time value.
    :type value_time: str
    :param value_phone_number: Phone number value.
    :type value_phone_number: str
    :param value_number: Floating point value.
    :type value_number: float
    :param value_integer: Integer value.
    :type value_integer: int
    :param value_array: Array of field values.
    :type value_array:
     list[~azure.cognitiveservices.formrecognizer.models.FieldValue]
    :param value_object: Dictionary of named field values.
    :type value_object: dict[str,
     ~azure.cognitiveservices.formrecognizer.models.FieldValue]
    :param text: Text content of the extracted field.
    :type text: str
    :param bounding_box: Bounding box of the field value, if appropriate.
    :type bounding_box: list[float]
    :param confidence: Confidence score.
    :type confidence: float
    :param elements: When includeTextDetails is set to true, a list of
     references to the text elements constituting this field.
    :type elements: list[str]
    :param page: The 1-based page number in the input document.
    :type page: int
    """

    _validation = {
        'type': {'required': True},
        'page': {'minimum': 1},
    }

    _attribute_map = {
        'type': {'key': 'type', 'type': 'FieldValueType'},
        'value_string': {'key': 'valueString', 'type': 'str'},
        'value_date': {'key': 'valueDate', 'type': 'date'},
        'value_time': {'key': 'valueTime', 'type': 'str'},
        'value_phone_number': {'key': 'valuePhoneNumber', 'type': 'str'},
        'value_number': {'key': 'valueNumber', 'type': 'float'},
        'value_integer': {'key': 'valueInteger', 'type': 'int'},
        'value_array': {'key': 'valueArray', 'type': '[FieldValue]'},
        'value_object': {'key': 'valueObject', 'type': '{FieldValue}'},
        'text': {'key': 'text', 'type': 'str'},
        'bounding_box': {'key': 'boundingBox', 'type': '[float]'},
        'confidence': {'key': 'confidence', 'type': 'float'},
        'elements': {'key': 'elements', 'type': '[str]'},
        'page': {'key': 'page', 'type': 'int'},
    }

    def __init__(self, *, type, value_string: str=None, value_date=None, value_time: str=None, value_phone_number: str=None, value_number: float=None, value_integer: int=None, value_array=None, value_object=None, text: str=None, bounding_box=None, confidence: float=None, elements=None, page: int=None, **kwargs) -> None:
        super(FieldValue, self).__init__(**kwargs)
        self.type = type
        self.value_string = value_string
        self.value_date = value_date
        self.value_time = value_time
        self.value_phone_number = value_phone_number
        self.value_number = value_number
        self.value_integer = value_integer
        self.value_array = value_array
        self.value_object = value_object
        self.text = text
        self.bounding_box = bounding_box
        self.confidence = confidence
        self.elements = elements
        self.page = page


class FormFieldsReport(Model):
    """Report for a custom model training field.

    All required parameters must be populated in order to send to Azure.

    :param field_name: Required. Training field name.
    :type field_name: str
    :param accuracy: Required. Estimated extraction accuracy for this field.
    :type accuracy: float
    """

    _validation = {
        'field_name': {'required': True},
        'accuracy': {'required': True},
    }

    _attribute_map = {
        'field_name': {'key': 'fieldName', 'type': 'str'},
        'accuracy': {'key': 'accuracy', 'type': 'float'},
    }

    def __init__(self, *, field_name: str, accuracy: float, **kwargs) -> None:
        super(FormFieldsReport, self).__init__(**kwargs)
        self.field_name = field_name
        self.accuracy = accuracy


class KeysResult(Model):
    """Keys extracted by the custom model.

    All required parameters must be populated in order to send to Azure.

    :param clusters: Required. Object mapping clusterIds to a list of keys.
    :type clusters: dict[str, list[str]]
    """

    _validation = {
        'clusters': {'required': True},
    }

    _attribute_map = {
        'clusters': {'key': 'clusters', 'type': '{[str]}'},
    }

    def __init__(self, *, clusters, **kwargs) -> None:
        super(KeysResult, self).__init__(**kwargs)
        self.clusters = clusters


class KeyValueElement(Model):
    """Information about the extracted key or value in a key-value pair.

    All required parameters must be populated in order to send to Azure.

    :param text: Required. The text content of the key or value.
    :type text: str
    :param bounding_box: Bounding box of the key or value.
    :type bounding_box: list[float]
    :param elements: When includeTextDetails is set to true, a list of
     references to the text elements constituting this key or value.
    :type elements: list[str]
    """

    _validation = {
        'text': {'required': True},
    }

    _attribute_map = {
        'text': {'key': 'text', 'type': 'str'},
        'bounding_box': {'key': 'boundingBox', 'type': '[float]'},
        'elements': {'key': 'elements', 'type': '[str]'},
    }

    def __init__(self, *, text: str, bounding_box=None, elements=None, **kwargs) -> None:
        super(KeyValueElement, self).__init__(**kwargs)
        self.text = text
        self.bounding_box = bounding_box
        self.elements = elements


class KeyValuePair(Model):
    """Information about the extracted key-value pair.

    All required parameters must be populated in order to send to Azure.

    :param label: A user defined label for the key/value pair entry.
    :type label: str
    :param key: Required. Information about the extracted key in a key-value
     pair.
    :type key: ~azure.cognitiveservices.formrecognizer.models.KeyValueElement
    :param value: Required. Information about the extracted value in a
     key-value pair.
    :type value:
     ~azure.cognitiveservices.formrecognizer.models.KeyValueElement
    :param confidence: Required. Confidence value.
    :type confidence: float
    """

    _validation = {
        'key': {'required': True},
        'value': {'required': True},
        'confidence': {'required': True},
    }

    _attribute_map = {
        'label': {'key': 'label', 'type': 'str'},
        'key': {'key': 'key', 'type': 'KeyValueElement'},
        'value': {'key': 'value', 'type': 'KeyValueElement'},
        'confidence': {'key': 'confidence', 'type': 'float'},
    }

    def __init__(self, *, key, value, confidence: float, label: str=None, **kwargs) -> None:
        super(KeyValuePair, self).__init__(**kwargs)
        self.label = label
        self.key = key
        self.value = value
        self.confidence = confidence


class Model(Model):
    """Response to the get custom model operation.

    All required parameters must be populated in order to send to Azure.

    :param model_info: Required.
    :type model_info: ~azure.cognitiveservices.formrecognizer.models.ModelInfo
    :param keys:
    :type keys: ~azure.cognitiveservices.formrecognizer.models.KeysResult
    :param train_result:
    :type train_result:
     ~azure.cognitiveservices.formrecognizer.models.TrainResult
    """

    _validation = {
        'model_info': {'required': True},
    }

    _attribute_map = {
        'model_info': {'key': 'modelInfo', 'type': 'ModelInfo'},
        'keys': {'key': 'keys', 'type': 'KeysResult'},
        'train_result': {'key': 'trainResult', 'type': 'TrainResult'},
    }

    def __init__(self, *, model_info, keys=None, train_result=None, **kwargs) -> None:
        super(Model, self).__init__(**kwargs)
        self.model_info = model_info
        self.keys = keys
        self.train_result = train_result


class ModelInfo(Model):
    """Basic custom model information.

    All required parameters must be populated in order to send to Azure.

    :param model_id: Required. Model identifier.
    :type model_id: str
    :param status: Required. Status of the model. Possible values include:
     'creating', 'ready', 'invalid'
    :type status: str or
     ~azure.cognitiveservices.formrecognizer.models.ModelStatus
    :param created_date_time: Required. Date and time (UTC) when the model was
     created.
    :type created_date_time: datetime
    :param last_updated_date_time: Required. Date and time (UTC) when the
     status was last updated.
    :type last_updated_date_time: datetime
    """

    _validation = {
        'model_id': {'required': True},
        'status': {'required': True},
        'created_date_time': {'required': True},
        'last_updated_date_time': {'required': True},
    }

    _attribute_map = {
        'model_id': {'key': 'modelId', 'type': 'str'},
        'status': {'key': 'status', 'type': 'ModelStatus'},
        'created_date_time': {'key': 'createdDateTime', 'type': 'iso-8601'},
        'last_updated_date_time': {'key': 'lastUpdatedDateTime', 'type': 'iso-8601'},
    }

    def __init__(self, *, model_id: str, status, created_date_time, last_updated_date_time, **kwargs) -> None:
        super(ModelInfo, self).__init__(**kwargs)
        self.model_id = model_id
        self.status = status
        self.created_date_time = created_date_time
        self.last_updated_date_time = last_updated_date_time


class ModelsModel(Model):
    """Response to the list custom models operation.

    :param summary: Summary of all trained custom models.
    :type summary:
     ~azure.cognitiveservices.formrecognizer.models.ModelsSummary
    :param model_list: Collection of trained custom models.
    :type model_list:
     list[~azure.cognitiveservices.formrecognizer.models.ModelInfo]
    :param next_link: Link to the next page of custom models.
    :type next_link: str
    """

    _attribute_map = {
        'summary': {'key': 'summary', 'type': 'ModelsSummary'},
        'model_list': {'key': 'modelList', 'type': '[ModelInfo]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(self, *, summary=None, model_list=None, next_link: str=None, **kwargs) -> None:
        super(ModelsModel, self).__init__(**kwargs)
        self.summary = summary
        self.model_list = model_list
        self.next_link = next_link


class ModelsSummary(Model):
    """Summary of all trained custom models.

    All required parameters must be populated in order to send to Azure.

    :param count: Required. Current count of trained custom models.
    :type count: int
    :param limit: Required. Max number of models that can be trained for this
     account.
    :type limit: int
    :param last_updated_date_time: Required. Date and time (UTC) when the
     summary was last updated.
    :type last_updated_date_time: datetime
    """

    _validation = {
        'count': {'required': True},
        'limit': {'required': True},
        'last_updated_date_time': {'required': True},
    }

    _attribute_map = {
        'count': {'key': 'count', 'type': 'int'},
        'limit': {'key': 'limit', 'type': 'int'},
        'last_updated_date_time': {'key': 'lastUpdatedDateTime', 'type': 'iso-8601'},
    }

    def __init__(self, *, count: int, limit: int, last_updated_date_time, **kwargs) -> None:
        super(ModelsSummary, self).__init__(**kwargs)
        self.count = count
        self.limit = limit
        self.last_updated_date_time = last_updated_date_time


class PageResult(Model):
    """Extracted information from a single page.

    All required parameters must be populated in order to send to Azure.

    :param page: Required. Page number.
    :type page: int
    :param cluster_id: Cluster identifier.
    :type cluster_id: int
    :param key_value_pairs: List of key-value pairs extracted from the page.
    :type key_value_pairs:
     list[~azure.cognitiveservices.formrecognizer.models.KeyValuePair]
    :param tables: List of data tables extracted from the page.
    :type tables:
     list[~azure.cognitiveservices.formrecognizer.models.DataTable]
    """

    _validation = {
        'page': {'required': True, 'minimum': 1},
        'cluster_id': {'minimum': 0},
    }

    _attribute_map = {
        'page': {'key': 'page', 'type': 'int'},
        'cluster_id': {'key': 'clusterId', 'type': 'int'},
        'key_value_pairs': {'key': 'keyValuePairs', 'type': '[KeyValuePair]'},
        'tables': {'key': 'tables', 'type': '[DataTable]'},
    }

    def __init__(self, *, page: int, cluster_id: int=None, key_value_pairs=None, tables=None, **kwargs) -> None:
        super(PageResult, self).__init__(**kwargs)
        self.page = page
        self.cluster_id = cluster_id
        self.key_value_pairs = key_value_pairs
        self.tables = tables


class ReadResult(Model):
    """Text extracted from a page in the input document.

    All required parameters must be populated in order to send to Azure.

    :param page: Required. The 1-based page number in the input document.
    :type page: int
    :param angle: Required. The general orientation of the text in clockwise
     direction, measured in degrees between (-180, 180].
    :type angle: float
    :param width: Required. The width of the image/PDF in pixels/inches,
     respectively.
    :type width: float
    :param height: Required. The height of the image/PDF in pixels/inches,
     respectively.
    :type height: float
    :param unit: Required. The unit used by the width, height and boundingBox
     properties. For images, the unit is "pixel". For PDF, the unit is "inch".
     Possible values include: 'pixel', 'inch'
    :type unit: str or
     ~azure.cognitiveservices.formrecognizer.models.LengthUnit
    :param language: The detected language on the page overall. Possible
     values include: 'en', 'es'
    :type language: str or
     ~azure.cognitiveservices.formrecognizer.models.Language
    :param lines: When includeTextDetails is set to true, a list of recognized
     text lines. The maximum number of lines returned is 300 per page. The
     lines are sorted top to bottom, left to right, although in certain cases
     proximity is treated with higher priority. As the sorting order depends on
     the detected text, it may change across images and OCR version updates.
     Thus, business logic should be built upon the actual line location instead
     of order.
    :type lines: list[~azure.cognitiveservices.formrecognizer.models.TextLine]
    """

    _validation = {
        'page': {'required': True, 'minimum': 1},
        'angle': {'required': True, 'maximum': 180, 'minimum_ex': -180},
        'width': {'required': True, 'minimum': 0},
        'height': {'required': True, 'minimum': 0},
        'unit': {'required': True},
    }

    _attribute_map = {
        'page': {'key': 'page', 'type': 'int'},
        'angle': {'key': 'angle', 'type': 'float'},
        'width': {'key': 'width', 'type': 'float'},
        'height': {'key': 'height', 'type': 'float'},
        'unit': {'key': 'unit', 'type': 'LengthUnit'},
        'language': {'key': 'language', 'type': 'str'},
        'lines': {'key': 'lines', 'type': '[TextLine]'},
    }

    def __init__(self, *, page: int, angle: float, width: float, height: float, unit, language=None, lines=None, **kwargs) -> None:
        super(ReadResult, self).__init__(**kwargs)
        self.page = page
        self.angle = angle
        self.width = width
        self.height = height
        self.unit = unit
        self.language = language
        self.lines = lines


class SourcePath(Model):
    """Uri or local path to source data.

    :param source: File source path.
    :type source: str
    """

    _validation = {
        'source': {'max_length': 2048, 'min_length': 0},
    }

    _attribute_map = {
        'source': {'key': 'source', 'type': 'str'},
    }

    def __init__(self, *, source: str=None, **kwargs) -> None:
        super(SourcePath, self).__init__(**kwargs)
        self.source = source


class TextLine(Model):
    """An object representing an extracted text line.

    All required parameters must be populated in order to send to Azure.

    :param text: Required. The text content of the line.
    :type text: str
    :param bounding_box: Required. Bounding box of an extracted line.
    :type bounding_box: list[float]
    :param language: The detected language of this line, if different from the
     overall page language. Possible values include: 'en', 'es'
    :type language: str or
     ~azure.cognitiveservices.formrecognizer.models.Language
    :param words: Required. List of words in the text line.
    :type words: list[~azure.cognitiveservices.formrecognizer.models.TextWord]
    """

    _validation = {
        'text': {'required': True},
        'bounding_box': {'required': True},
        'words': {'required': True},
    }

    _attribute_map = {
        'text': {'key': 'text', 'type': 'str'},
        'bounding_box': {'key': 'boundingBox', 'type': '[float]'},
        'language': {'key': 'language', 'type': 'str'},
        'words': {'key': 'words', 'type': '[TextWord]'},
    }

    def __init__(self, *, text: str, bounding_box, words, language=None, **kwargs) -> None:
        super(TextLine, self).__init__(**kwargs)
        self.text = text
        self.bounding_box = bounding_box
        self.language = language
        self.words = words


class TextWord(Model):
    """An object representing a word.

    All required parameters must be populated in order to send to Azure.

    :param text: Required. The text content of the word.
    :type text: str
    :param bounding_box: Required. Bounding box of an extracted word.
    :type bounding_box: list[float]
    :param confidence: Confidence value.
    :type confidence: float
    """

    _validation = {
        'text': {'required': True},
        'bounding_box': {'required': True},
    }

    _attribute_map = {
        'text': {'key': 'text', 'type': 'str'},
        'bounding_box': {'key': 'boundingBox', 'type': '[float]'},
        'confidence': {'key': 'confidence', 'type': 'float'},
    }

    def __init__(self, *, text: str, bounding_box, confidence: float=None, **kwargs) -> None:
        super(TextWord, self).__init__(**kwargs)
        self.text = text
        self.bounding_box = bounding_box
        self.confidence = confidence


class TrainingDocumentInfo(Model):
    """Report for a custom model training document.

    All required parameters must be populated in order to send to Azure.

    :param document_name: Required. Training document name.
    :type document_name: str
    :param pages: Required. Total number of pages trained.
    :type pages: int
    :param errors: Required. List of errors.
    :type errors:
     list[~azure.cognitiveservices.formrecognizer.models.ErrorInformation]
    :param status: Required. Status of the training operation. Possible values
     include: 'succeeded', 'partiallySucceeded', 'failed'
    :type status: str or
     ~azure.cognitiveservices.formrecognizer.models.TrainStatus
    """

    _validation = {
        'document_name': {'required': True},
        'pages': {'required': True},
        'errors': {'required': True},
        'status': {'required': True},
    }

    _attribute_map = {
        'document_name': {'key': 'documentName', 'type': 'str'},
        'pages': {'key': 'pages', 'type': 'int'},
        'errors': {'key': 'errors', 'type': '[ErrorInformation]'},
        'status': {'key': 'status', 'type': 'TrainStatus'},
    }

    def __init__(self, *, document_name: str, pages: int, errors, status, **kwargs) -> None:
        super(TrainingDocumentInfo, self).__init__(**kwargs)
        self.document_name = document_name
        self.pages = pages
        self.errors = errors
        self.status = status


class TrainRequest(Model):
    """Request parameter to train a new custom model.

    All required parameters must be populated in order to send to Azure.

    :param source: Required. Source path containing the training documents.
    :type source: str
    :param source_filter: Filter to apply to the documents in the source path
     for training.
    :type source_filter:
     ~azure.cognitiveservices.formrecognizer.models.TrainSourceFilter
    :param use_label_file: Use label file for training a model. Default value:
     False .
    :type use_label_file: bool
    """

    _validation = {
        'source': {'required': True, 'max_length': 2048, 'min_length': 0},
    }

    _attribute_map = {
        'source': {'key': 'source', 'type': 'str'},
        'source_filter': {'key': 'sourceFilter', 'type': 'TrainSourceFilter'},
        'use_label_file': {'key': 'useLabelFile', 'type': 'bool'},
    }

    def __init__(self, *, source: str, source_filter=None, use_label_file: bool=False, **kwargs) -> None:
        super(TrainRequest, self).__init__(**kwargs)
        self.source = source
        self.source_filter = source_filter
        self.use_label_file = use_label_file


class TrainResult(Model):
    """Custom model training result.

    All required parameters must be populated in order to send to Azure.

    :param training_documents: Required. List of the documents used to train
     the model and any errors reported in each document.
    :type training_documents:
     list[~azure.cognitiveservices.formrecognizer.models.TrainingDocumentInfo]
    :param fields: List of fields used to train the model and the train
     operation error reported by each.
    :type fields:
     list[~azure.cognitiveservices.formrecognizer.models.FormFieldsReport]
    :param average_model_accuracy: Average accuracy.
    :type average_model_accuracy: float
    :param errors: Errors returned during the training operation.
    :type errors:
     list[~azure.cognitiveservices.formrecognizer.models.ErrorInformation]
    """

    _validation = {
        'training_documents': {'required': True},
    }

    _attribute_map = {
        'training_documents': {'key': 'trainingDocuments', 'type': '[TrainingDocumentInfo]'},
        'fields': {'key': 'fields', 'type': '[FormFieldsReport]'},
        'average_model_accuracy': {'key': 'averageModelAccuracy', 'type': 'float'},
        'errors': {'key': 'errors', 'type': '[ErrorInformation]'},
    }

    def __init__(self, *, training_documents, fields=None, average_model_accuracy: float=None, errors=None, **kwargs) -> None:
        super(TrainResult, self).__init__(**kwargs)
        self.training_documents = training_documents
        self.fields = fields
        self.average_model_accuracy = average_model_accuracy
        self.errors = errors


class TrainSourceFilter(Model):
    """Filter to apply to the documents in the source path for training.

    :param prefix: A case-sensitive prefix string to filter documents in the
     source path for training. For example, when using a Azure storage blob
     Uri, use the prefix to restrict sub folders for training.
    :type prefix: str
    :param include_sub_folders: A flag to indicate if sub folders within the
     set of prefix folders will also need to be included when searching for
     content to be preprocessed. Default value: False .
    :type include_sub_folders: bool
    """

    _validation = {
        'prefix': {'max_length': 1024, 'min_length': 0},
    }

    _attribute_map = {
        'prefix': {'key': 'prefix', 'type': 'str'},
        'include_sub_folders': {'key': 'includeSubFolders', 'type': 'bool'},
    }

    def __init__(self, *, prefix: str=None, include_sub_folders: bool=False, **kwargs) -> None:
        super(TrainSourceFilter, self).__init__(**kwargs)
        self.prefix = prefix
        self.include_sub_folders = include_sub_folders
