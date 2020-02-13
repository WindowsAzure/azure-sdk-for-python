class EventHubConsumerClient(ClientBaseAsync):

    #...

    async def receive_batch(
            self, on_event_batch: Callable[[PartitionContext, List[EventData]], Awaitable[None]],
            *,
            max_batch_size: int=...,
            max_wait_time: float=...,
            enable_callback_when_no_event: bool=...,
            partition_id: Optional[str]=...,
            owner_level: Optional[int]=...,
            prefetch: int=...,
            track_last_enqueued_event_properties: bool=...,
            starting_position: Optional[Union[str, int, datetime.datetime, Dict[str, Any]]]=...,
            starting_position_inclusive: Union[bool, Dict[str, bool]]=...,
            on_error: Optional[Callable[[PartitionContext, Exception], Awaitable[None]]]=...,
            on_partition_initialize: Optional[Callable[[PartitionContext], Awaitable[None]]]=...,
            on_partition_close: Optional[Callable[[PartitionContext, CloseReason], Awaitable[None]]]=...
    ) -> None: ...

    # ...
