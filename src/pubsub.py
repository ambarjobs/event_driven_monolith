# ==================================================================================================
#  Application Pub / Sub services
# ==================================================================================================
from dataclasses import dataclass
from typing import Callable

import pika
from pika.adapters.blocking_connection import BlockingChannel
from pika.spec import Basic, BasicProperties

import config


ConsumerCallback = Callable[[BlockingChannel, Basic.Deliver, BasicProperties, bytes], None]


@dataclass
class Consumer:
    queue_name: str
    channel: BlockingChannel
    callback: ConsumerCallback

    def __post_init__(self):
        self.channel.basic_consume(
            queue=self.queue_name,
            on_message_callback=self.callback,
            auto_ack=True
        )

    def start(self) -> None:
        self.channel.start_consuming()

@dataclass
class PubSub:
    host: str = config.RABBIT_HOST
    port: int = config.RABBIT_PORT
    topics: list[str] | None = None

    def __post_init__(self) -> None:
        self.topics = self.topics or []
        self.exchange_type = 'fanout'
        self.connection = pika.BlockingConnection(
            parameters=pika.ConnectionParameters(host=self.host, port=self.port)
        )
        self.channel = self.connection.channel()
        for topic in self.topics:
            self._create_topic(topic=topic)

    def _create_topic(self, topic: str) -> None:
        """Create a topic if it don't exists."""
        self.channel.exchange_declare(exchange=topic, exchange_type=self.exchange_type)

    def _create_temporary_queue(self) -> str:
        """Create a temporary queue named automatically."""
        temporary_queue = self.channel.queue_declare(queue='', exclusive=True)
        return temporary_queue.method.queue

    def publish(self, topic: str, message: str) -> None:
        """Publish a message into a topic."""
        self._create_topic(topic=topic)
        self.channel.basic_publish(exchange=topic, routing_key='', body=message)
        self.connection.close()

    def consumer_factory(self, topic: str, callback: ConsumerCallback) -> Consumer:
        """Returns a Consumer instance to receive topic messages ."""
        self._create_topic(topic=topic)
        queue_name = self._create_temporary_queue()
        self.channel.queue_bind(exchange=topic, queue=queue_name)
        return Consumer(queue_name=queue_name, channel=self.channel, callback=callback)
