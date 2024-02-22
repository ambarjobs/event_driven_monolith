# ==================================================================================================
#  Application Pub / Sub services
# ==================================================================================================
from dataclasses import dataclass
from collections.abc import Callable, Sequence
from typing import NamedTuple

import pika
from pika.adapters.blocking_connection import BlockingChannel
from pika.exceptions import (
    AMQPChannelError,
    AMQPConnectionError,
    ConnectionClosedByBroker,
    UnroutableError,
)
from pika.spec import Basic, BasicProperties

import config
from config import logging as log
from exceptions import MessagePublishingConfirmationError


ConsumerCallback = Callable[[BlockingChannel, Basic.Deliver, BasicProperties, bytes], None]

class Subscription(NamedTuple):
    """Consumer service subscription to a topic (rabitmq exchange)."""
    topic_name: str
    consumer_service_name: str


@dataclass
class Consumer:
    queue_name: str
    channel: BlockingChannel
    callback: ConsumerCallback

    def __post_init__(self):
        self.channel.basic_consume(
            queue=self.queue_name,
            on_message_callback=self.callback,
        )

    def start(self) -> None:
        while True:
            try:
                self.channel.start_consuming()
            except (AMQPChannelError, ConnectionClosedByBroker) as err:
                log.error(f'Error inside consumer: {err}')
                raise err
            except AMQPConnectionError as err:
                log.warning(f'Recoverable error inside consumer: {err}')
                continue

@dataclass
class PubSub:
    host: str = config.RABBIT_HOST
    port: int = config.RABBIT_PORT
    topics: Sequence[str] | None = None

    def __post_init__(self) -> None:
        self.topics = self.topics or []
        self.exchange_type = 'fanout'
        self.connection = pika.BlockingConnection(
            parameters=pika.ConnectionParameters(
                host=self.host,
                port=self.port,
                heartbeat=config.RABBIT_HEARTBEAT_TIMEOUT,
                blocked_connection_timeout=config.RABBIT_BLOCKED_CONNECTION_TIMEOUT,
            )
        )
        self.channel = self.connection.channel()
        for topic in self.topics:
            self._create_topic(topic=topic)

    def _create_topic(self, topic: str) -> None:
        """Create a topic if it don't exists."""
        self.channel.exchange_declare(exchange=topic, exchange_type=self.exchange_type)
        if not self.channel._delivery_confirmation: # type: ignore[attr-defined]
            self.channel.confirm_delivery()

    def _create_temporary_queue(self) -> str:
        """Create a temporary queue named automatically."""
        temporary_queue = self.channel.queue_declare(queue='', exclusive=True)
        return temporary_queue.method.queue

    def publish(self, topic: str, message: str | bytes) -> None:
        """Publish a message into a topic."""
        self._create_topic(topic=topic)
        try:
            self.channel.basic_publish(exchange=topic, routing_key='', body=message, mandatory=True)
        except UnroutableError as err:
            error_msg = f'The sending of an event message could not be confirmed: {err}'
            raise MessagePublishingConfirmationError(error_msg)
        self.connection.close()

    def consumer_factory(self, topic: str, callback: ConsumerCallback) -> Consumer:
        """Returns a Consumer instance to receive topic messages ."""
        self._create_topic(topic=topic)
        queue_name = self._create_temporary_queue()
        self.channel.queue_bind(exchange=topic, queue=queue_name)
        return Consumer(queue_name=queue_name, channel=self.channel, callback=callback)
