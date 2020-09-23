# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from azure.core.exceptions import HttpResponseError
import msrest.serialization


class AddChatThreadMembersRequest(msrest.serialization.Model):
    """Thread members to be added to the thread.

    All required parameters must be populated in order to send to Azure.

    :param members: Required. Members to add to a chat thread.
    :type members: list[~azure.communication.chat.models.ChatThreadMember]
    """

    _validation = {
        'members': {'required': True},
    }

    _attribute_map = {
        'members': {'key': 'members', 'type': '[ChatThreadMember]'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(AddChatThreadMembersRequest, self).__init__(**kwargs)
        self.members = kwargs['members']


class ChatMessage(msrest.serialization.Model):
    """ChatMessage.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar id: The id of the chat message. This id is server generated.
    :vartype id: str
    :param type: Type of the chat message.
    
     Possible values:
    
     .. code-block::
    
        - Text
        - ThreadActivity/TopicUpdate
        - ThreadActivity/AddMember
        - ThreadActivity/DeleteMember.
    :type type: str
    :param priority: The chat message priority. Possible values include: "Normal", "High".
    :type priority: str or ~azure.communication.chat.models.ChatMessagePriority
    :ivar version: Version of the chat message.
    :vartype version: str
    :param content: Content of the chat message.
    :type content: str
    :param sender_display_name: The display name of the chat message sender. This property is used
     to populate sender name for push notifications.
    :type sender_display_name: str
    :ivar created_on: The timestamp when the chat message arrived at the server. The timestamp is
     in ISO8601 format: ``yyyy-MM-ddTHH:mm:ssZ``.
    :vartype created_on: ~datetime.datetime
    :ivar sender_id: The id of the chat message sender.
    :vartype sender_id: str
    :param deleted_on: The timestamp when the chat message was deleted. The timestamp is in ISO8601
     format: ``yyyy-MM-ddTHH:mm:ssZ``.
    :type deleted_on: ~datetime.datetime
    :param edited_on: The timestamp when the chat message was edited. The timestamp is in ISO8601
     format: ``yyyy-MM-ddTHH:mm:ssZ``.
    :type edited_on: ~datetime.datetime
    """

    _validation = {
        'id': {'readonly': True},
        'version': {'readonly': True},
        'created_on': {'readonly': True},
        'sender_id': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'priority': {'key': 'priority', 'type': 'str'},
        'version': {'key': 'version', 'type': 'str'},
        'content': {'key': 'content', 'type': 'str'},
        'sender_display_name': {'key': 'senderDisplayName', 'type': 'str'},
        'created_on': {'key': 'createdOn', 'type': 'iso-8601'},
        'sender_id': {'key': 'senderId', 'type': 'str'},
        'deleted_on': {'key': 'deletedOn', 'type': 'iso-8601'},
        'edited_on': {'key': 'editedOn', 'type': 'iso-8601'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(ChatMessage, self).__init__(**kwargs)
        self.id = None
        self.type = kwargs.get('type', None)
        self.priority = kwargs.get('priority', None)
        self.version = None
        self.content = kwargs.get('content', None)
        self.sender_display_name = kwargs.get('sender_display_name', None)
        self.created_on = None
        self.sender_id = None
        self.deleted_on = kwargs.get('deleted_on', None)
        self.edited_on = kwargs.get('edited_on', None)


class ChatMessagesCollection(msrest.serialization.Model):
    """Collection of chat messages for a particular chat thread.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar value: Collection of chat messages.
    :vartype value: list[~azure.communication.chat.models.ChatMessage]
    :ivar next_link: If there are more chat messages that can be retrieved, the next link will be
     populated.
    :vartype next_link: str
    """

    _validation = {
        'value': {'readonly': True},
        'next_link': {'readonly': True},
    }

    _attribute_map = {
        'value': {'key': 'value', 'type': '[ChatMessage]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(ChatMessagesCollection, self).__init__(**kwargs)
        self.value = None
        self.next_link = None


class ChatThread(msrest.serialization.Model):
    """ChatThread.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar id: Chat thread id.
    :vartype id: str
    :param topic: Chat thread topic.
    :type topic: str
    :ivar created_on: The timestamp when the chat thread was created. The timestamp is in ISO8601
     format: ``yyyy-MM-ddTHH:mm:ssZ``.
    :vartype created_on: ~datetime.datetime
    :ivar created_by: Id of the chat thread owner.
    :vartype created_by: str
    :param members: Chat thread members.
    :type members: list[~azure.communication.chat.models.ChatThreadMember]
    """

    _validation = {
        'id': {'readonly': True},
        'created_on': {'readonly': True},
        'created_by': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'topic': {'key': 'topic', 'type': 'str'},
        'created_on': {'key': 'createdOn', 'type': 'iso-8601'},
        'created_by': {'key': 'createdBy', 'type': 'str'},
        'members': {'key': 'members', 'type': '[ChatThreadMember]'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(ChatThread, self).__init__(**kwargs)
        self.id = None
        self.topic = kwargs.get('topic', None)
        self.created_on = None
        self.created_by = None
        self.members = kwargs.get('members', None)


class ChatThreadInfo(msrest.serialization.Model):
    """ChatThreadInfo.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar id: Chat thread id.
    :vartype id: str
    :param topic: Chat thread topic.
    :type topic: str
    :param is_deleted: Flag if a chat thread is soft deleted.
    :type is_deleted: bool
    :ivar last_message_received_on: The timestamp when the last message arrived at the server. The
     timestamp is in ISO8601 format: ``yyyy-MM-ddTHH:mm:ssZ``.
    :vartype last_message_received_on: ~datetime.datetime
    """

    _validation = {
        'id': {'readonly': True},
        'last_message_received_on': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'topic': {'key': 'topic', 'type': 'str'},
        'is_deleted': {'key': 'isDeleted', 'type': 'bool'},
        'last_message_received_on': {'key': 'lastMessageReceivedOn', 'type': 'iso-8601'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(ChatThreadInfo, self).__init__(**kwargs)
        self.id = None
        self.topic = kwargs.get('topic', None)
        self.is_deleted = kwargs.get('is_deleted', None)
        self.last_message_received_on = None


class ChatThreadMember(msrest.serialization.Model):
    """A member of the chat thread.

    All required parameters must be populated in order to send to Azure.

    :param id: Required. The id of the chat thread member in the format
     ``8:acs:ResourceId_AcsUserId``.
    :type id: str
    :param display_name: Display name for the chat thread member.
    :type display_name: str
    :param share_history_time: Time from which the chat history is shared with the member. The
     timestamp is in ISO8601 format: ``yyyy-MM-ddTHH:mm:ssZ``.
    :type share_history_time: ~datetime.datetime
    """

    _validation = {
        'id': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'display_name': {'key': 'displayName', 'type': 'str'},
        'share_history_time': {'key': 'shareHistoryTime', 'type': 'iso-8601'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(ChatThreadMember, self).__init__(**kwargs)
        self.id = kwargs['id']
        self.display_name = kwargs.get('display_name', None)
        self.share_history_time = kwargs.get('share_history_time', None)


class ChatThreadMembersCollection(msrest.serialization.Model):
    """Collection of thread members belong to a particular thread.

    Variables are only populated by the server, and will be ignored when sending a request.

    :param value: Chat thread members.
    :type value: list[~azure.communication.chat.models.ChatThreadMember]
    :ivar next_link: If there are more chat threads that can be retrieved, the next link will be
     populated.
    :vartype next_link: str
    """

    _validation = {
        'next_link': {'readonly': True},
    }

    _attribute_map = {
        'value': {'key': 'value', 'type': '[ChatThreadMember]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(ChatThreadMembersCollection, self).__init__(**kwargs)
        self.value = kwargs.get('value', None)
        self.next_link = None


class ChatThreadsInfoCollection(msrest.serialization.Model):
    """Collection of chat threads.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar value: Collection of chat threads.
    :vartype value: list[~azure.communication.chat.models.ChatThreadInfo]
    :ivar next_link: If there are more chat threads that can be retrieved, the next link will be
     populated.
    :vartype next_link: str
    """

    _validation = {
        'value': {'readonly': True},
        'next_link': {'readonly': True},
    }

    _attribute_map = {
        'value': {'key': 'value', 'type': '[ChatThreadInfo]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(ChatThreadsInfoCollection, self).__init__(**kwargs)
        self.value = None
        self.next_link = None


class CreateChatThreadRequest(msrest.serialization.Model):
    """Request payload for creating a chat thread.

    All required parameters must be populated in order to send to Azure.

    :param topic: Required. The chat thread topic.
    :type topic: str
    :param members: Required. Members to be added to the chat thread.
    :type members: list[~azure.communication.chat.models.ChatThreadMember]
    """

    _validation = {
        'topic': {'required': True},
        'members': {'required': True},
    }

    _attribute_map = {
        'topic': {'key': 'topic', 'type': 'str'},
        'members': {'key': 'members', 'type': '[ChatThreadMember]'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(CreateChatThreadRequest, self).__init__(**kwargs)
        self.topic = kwargs['topic']
        self.members = kwargs['members']


class Error(msrest.serialization.Model):
    """Error.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar code:
    :vartype code: str
    :ivar message:
    :vartype message: str
    :ivar target:
    :vartype target: str
    :ivar inner_errors:
    :vartype inner_errors: list[~azure.communication.chat.models.Error]
    """

    _validation = {
        'code': {'readonly': True},
        'message': {'readonly': True},
        'target': {'readonly': True},
        'inner_errors': {'readonly': True},
    }

    _attribute_map = {
        'code': {'key': 'code', 'type': 'str'},
        'message': {'key': 'message', 'type': 'str'},
        'target': {'key': 'target', 'type': 'str'},
        'inner_errors': {'key': 'innerErrors', 'type': '[Error]'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(Error, self).__init__(**kwargs)
        self.code = None
        self.message = None
        self.target = None
        self.inner_errors = None


class IndividualStatusResponse(msrest.serialization.Model):
    """IndividualStatusResponse.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar id: Identifies the resource to which the individual status corresponds.
    :vartype id: str
    :ivar status_code: The status code of the resource operation.
    
     Possible values include:
       200 for a successful update or delete,
       201 for successful creation,
       400 for a malformed input,
       403 for lacking permission to execute the operation,
       404 for resource not found.
    :vartype status_code: int
    :ivar message: The message explaining why the operation failed for the resource identified by
     the key; null if the operation succeeded.
    :vartype message: str
    :ivar type: Identifies the type of the resource to which the individual status corresponds.
    :vartype type: str
    """

    _validation = {
        'id': {'readonly': True},
        'status_code': {'readonly': True},
        'message': {'readonly': True},
        'type': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'status_code': {'key': 'statusCode', 'type': 'int'},
        'message': {'key': 'message', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(IndividualStatusResponse, self).__init__(**kwargs)
        self.id = None
        self.status_code = None
        self.message = None
        self.type = None


class MultiStatusResponse(msrest.serialization.Model):
    """MultiStatusResponse.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar multiple_status: The list of status information for each resource in the request.
    :vartype multiple_status: list[~azure.communication.chat.models.IndividualStatusResponse]
    """

    _validation = {
        'multiple_status': {'readonly': True},
    }

    _attribute_map = {
        'multiple_status': {'key': 'multipleStatus', 'type': '[IndividualStatusResponse]'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(MultiStatusResponse, self).__init__(**kwargs)
        self.multiple_status = None


class ReadReceipt(msrest.serialization.Model):
    """A read receipt indicates the time a chat message was read by a recipient.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar sender_id: Read receipt sender id.
    :vartype sender_id: str
    :ivar chat_message_id: Id for the chat message that has been read. This id is generated by the
     server.
    :vartype chat_message_id: str
    :ivar read_on: Read receipt timestamp. The timestamp is in ISO8601 format: ``yyyy-MM-
     ddTHH:mm:ssZ``.
    :vartype read_on: ~datetime.datetime
    """

    _validation = {
        'sender_id': {'readonly': True},
        'chat_message_id': {'readonly': True},
        'read_on': {'readonly': True},
    }

    _attribute_map = {
        'sender_id': {'key': 'senderId', 'type': 'str'},
        'chat_message_id': {'key': 'chatMessageId', 'type': 'str'},
        'read_on': {'key': 'readOn', 'type': 'iso-8601'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(ReadReceipt, self).__init__(**kwargs)
        self.sender_id = None
        self.chat_message_id = None
        self.read_on = None


class ReadReceiptsCollection(msrest.serialization.Model):
    """ReadReceiptsCollection.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar value: Collection of read receipts.
    :vartype value: list[~azure.communication.chat.models.ReadReceipt]
    :ivar next_link: If there are more read receipts that can be retrieved, the next link will be
     populated.
    :vartype next_link: str
    """

    _validation = {
        'value': {'readonly': True},
        'next_link': {'readonly': True},
    }

    _attribute_map = {
        'value': {'key': 'value', 'type': '[ReadReceipt]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(ReadReceiptsCollection, self).__init__(**kwargs)
        self.value = None
        self.next_link = None


class SendChatMessageRequest(msrest.serialization.Model):
    """Details of the message to send.

    All required parameters must be populated in order to send to Azure.

    :param priority: The chat message priority. Possible values include: "Normal", "High".
    :type priority: str or ~azure.communication.chat.models.ChatMessagePriority
    :param content: Required. Chat message content.
    :type content: str
    :param sender_display_name: The display name of the chat message sender. This property is used
     to populate sender name for push notifications.
    :type sender_display_name: str
    """

    _validation = {
        'content': {'required': True},
    }

    _attribute_map = {
        'priority': {'key': 'priority', 'type': 'str'},
        'content': {'key': 'content', 'type': 'str'},
        'sender_display_name': {'key': 'senderDisplayName', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(SendChatMessageRequest, self).__init__(**kwargs)
        self.priority = kwargs.get('priority', None)
        self.content = kwargs['content']
        self.sender_display_name = kwargs.get('sender_display_name', None)


class SendChatMessageResult(msrest.serialization.Model):
    """Result of the send message operation.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar id: A server-generated message id.
    :vartype id: str
    """

    _validation = {
        'id': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(SendChatMessageResult, self).__init__(**kwargs)
        self.id = None


class SendReadReceiptRequest(msrest.serialization.Model):
    """Request payload for sending a read receipt.

    All required parameters must be populated in order to send to Azure.

    :param chat_message_id: Required. Id of the latest chat message read by the user.
    :type chat_message_id: str
    """

    _validation = {
        'chat_message_id': {'required': True},
    }

    _attribute_map = {
        'chat_message_id': {'key': 'chatMessageId', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(SendReadReceiptRequest, self).__init__(**kwargs)
        self.chat_message_id = kwargs['chat_message_id']


class UpdateChatMessageRequest(msrest.serialization.Model):
    """UpdateChatMessageRequest.

    :param content: Chat message content.
    :type content: str
    :param priority: The chat message priority. Possible values include: "Normal", "High".
    :type priority: str or ~azure.communication.chat.models.ChatMessagePriority
    """

    _attribute_map = {
        'content': {'key': 'content', 'type': 'str'},
        'priority': {'key': 'priority', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(UpdateChatMessageRequest, self).__init__(**kwargs)
        self.content = kwargs.get('content', None)
        self.priority = kwargs.get('priority', None)


class UpdateChatThreadRequest(msrest.serialization.Model):
    """UpdateChatThreadRequest.

    :param topic: Chat thread topic.
    :type topic: str
    """

    _attribute_map = {
        'topic': {'key': 'topic', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(UpdateChatThreadRequest, self).__init__(**kwargs)
        self.topic = kwargs.get('topic', None)
