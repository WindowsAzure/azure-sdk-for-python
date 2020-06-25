# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------
from typing import Dict, Iterable, Any, Optional
from collections import OrderedDict
from datetime import timedelta
from azure.servicebus.management._generated.models import AuthorizationRule, CorrelationFilter, CreateQueueBodyContent, CreateRuleBodyContent, CreateSubscriptionBodyContent, CreateTopicBodyContent, FalseFilter, KeyValue, MessageCountDetails, NamespaceProperties, NamespacePropertiesEntry, NamespacePropertiesEntryContent, QueueDescription, QueueDescriptionEntry, QueueDescriptionEntryContent, QueueDescriptionFeed, ResponseLink, RuleDescription, RuleDescriptionEntry, RuleDescriptionEntryContent, RuleDescriptionFeed, ServiceBusManagementError, SqlFilter, SqlRuleAction, SubscriptionDescription, SubscriptionDescriptionEntry, SubscriptionDescriptionEntryContent, SubscriptionDescriptionFeed, TopicDescription, TopicDescriptionEntry, TopicDescriptionEntryContent, TopicDescriptionFeed, TrueFilter


MODEL_CLASS_ATTRIBUTES = {
    AuthorizationRule: ("type", "claim_type", "claim_value", "rights", "created_time", "modified_time", "key_name", "primary_key", "secondary_key"),
    CorrelationFilter: ("type", "correlation_id", "message_id", "to", "reply_to", "label", "session_id", "reply_to_session_id", "content_type", "properties"),
    CreateQueueBodyContent: ("type", "queue_description"),
    CreateRuleBodyContent: ("type", "rule_description"),
    CreateSubscriptionBodyContent: ("type", "subscription_description"),
    CreateTopicBodyContent: ("type", "topic_description"),
    FalseFilter: ("type", "sql_expression"),
    KeyValue: ("key", "value"),
    MessageCountDetails: ("active_message_count", "dead_letter_message_count", "scheduled_message_count", "transfer_dead_letter_message_count", "transfer_message_count"),
    NamespaceProperties: ("alias", "created_time", "messaging_sku", "messaging_units", "modified_time", "name", "namespace_type"),
    NamespacePropertiesEntry: ("id", "title", "updated", "author", "link", "content"),
    NamespacePropertiesEntryContent: ("type", "namespace_properties"),
    QueueDescription: ("lock_duration", "max_size_in_megabytes", "requires_duplicate_detection", "requires_session", "default_message_time_to_live", "dead_lettering_on_message_expiration", "duplicate_detection_history_time_window", "max_delivery_count", "enable_batched_operations", "size_in_bytes", "message_count", "is_anonymous_accessible", "authorization_rules", "status", "created_at", "updated_at", "accessed_at", "support_ordering", "message_count_details", "auto_delete_on_idle", "enable_partitioning", "entity_availability_status", "enable_express"),
    QueueDescriptionEntry: ("base", "id", "title", "published", "updated", "author", "link", "content"),
    QueueDescriptionEntryContent: ("type", "queue_description"),
    QueueDescriptionFeed: ("id", "title", "updated", "link", "entry"),
    ResponseLink: ("href", "rel"),
    RuleDescription: ("filter", "action", "created_at", "name"),
    RuleDescriptionEntry: ("id", "title", "published", "updated", "link", "content"),
    RuleDescriptionEntryContent: ("type", "rule_description"),
    RuleDescriptionFeed: ("id", "title", "updated", "link", "entry"),
    ServiceBusManagementError: ("code", "detail"),
    SqlFilter: ("type", "sql_expression"),
    SqlRuleAction: ("type", "sql_expression"),
    SubscriptionDescription: ("lock_duration", "requires_session", "default_message_time_to_live", "dead_lettering_on_message_expiration", "dead_lettering_on_filter_evaluation_exceptions", "message_count", "max_delivery_count", "enable_batched_operations", "status", "forward_to", "created_at", "updated_at", "accessed_at", "message_count_details", "auto_delete_on_idle", "entity_availability_status"),
    SubscriptionDescriptionEntry: ("id", "title", "published", "updated", "link", "content"),
    SubscriptionDescriptionEntryContent: ("type", "subscription_description"),
    SubscriptionDescriptionFeed: ("id", "title", "updated", "link", "entry"),
    TopicDescription: ("default_message_time_to_live", "max_size_in_megabytes", "requires_duplicate_detection", "duplicate_detection_history_time_window", "enable_batched_operations", "size_in_bytes", "filtering_messages_before_publishing", "is_anonymous_accessible", "authorization_rules", "status", "created_at", "updated_at", "accessed_at", "support_ordering", "message_count_details", "subscription_count", "auto_delete_on_idle", "enable_partitioning", "entity_availability_status", "enable_subscription_partitioning", "enable_express", "user_metadata"),
    TopicDescriptionEntry: ("base", "id", "title", "published", "updated", "author", "link", "content"),
    TopicDescriptionEntryContent: ("type", "topic_description"),
    TopicDescriptionFeed: ("id", "title", "updated", "link", "entry"),
    TrueFilter: ("type", "sql_expression"),
}


def avoid_timedelta_overflow(td):
    # type: (Optional[timedelta]) -> Optional[timedelta]
    """Service Bus REST API uses "P10675199DT2H48M5.4775807S" as default value for some properties, which are of type
    datetime.timedelta. When they are deserialized, Python round the milliseconds from 4775807 to 477581.
    When we get an entity (for instance, QueueDescription) and update this entity, this default value is
    deserialized to "P10675199DT2H48M5.477581S". Service Bus doesn't accept this value probably because it's too large.
    The workaround is to deduct the milliseconds by 0.000001.
    """
    result = td
    if td is not None and td.days == 10675199 and td.microseconds >= 477581:
        result = timedelta(seconds=td.total_seconds() - 0.000001)
    return result


def _adjust_dict_key_sequence(dct, keys):
    # type: (Dict[str, Any], Iterable[str]) -> Dict[str, Any]

    result = OrderedDict()
    for key in keys:
        result[key] = dct.pop(key)
    result.update(dct)
    return result


def adjust_attribute_map():
    # type: () -> None
    """update_xxx will serialize XXXDescription to XML. The tags sequence is important to service.
    This workaround is to convert the _attribute_map of each model class
    to use OrderedDict instead of dict so their serialized XML tags use the same sequence as
    specified in MODEL_CLASS_ATTRIBUTES.
    """
    # pylint:disable=protected-access
    for class_, attributes in MODEL_CLASS_ATTRIBUTES.items():
        class_._attribute_map = _adjust_dict_key_sequence(
            class_._attribute_map,
            attributes
        )
        if "title" in class_._attribute_map:
            class_._attribute_map["title"] = {
                'key': 'title',
                'type': 'str',
                'xml': {'ns': 'http://www.w3.org/2005/Atom'}
            }
