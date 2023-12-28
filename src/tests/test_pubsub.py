# ==================================================================================================
#  Pubsub module tests
# ==================================================================================================
import threading as thrd

import config
import pubsub as ps


class TestPubSub:
    # ==============================================================================================
    #   PubSub initialization
    # ==============================================================================================
    def test_initialization__general_case__no_parameters(self, pub_sub: ps.PubSub) -> None:
        assert pub_sub.host == config.RABBIT_HOST
        assert pub_sub.port == config.RABBIT_PORT
        assert pub_sub.topics == []
        assert pub_sub.exchange_type == 'fanout'
        assert hasattr(pub_sub, 'connection')
        assert pub_sub.connection.is_open
        assert hasattr(pub_sub, 'channel')
        assert pub_sub.channel.is_open

    def test_initialization__general_case__with_parameters(self) -> None:
        test_topics = ['test-topic-1', 'test-topic-2', 'test-topic-3']
        pub_sub = ps.PubSub(topics=test_topics)

        try:
            assert pub_sub.topics == test_topics
            assert pub_sub.exchange_type == 'fanout'
            assert hasattr(pub_sub, 'connection')
            assert pub_sub.connection.is_open
            assert hasattr(pub_sub, 'channel')
            assert pub_sub.channel.is_open
        finally:
            for topic in test_topics:
                pub_sub.channel.exchange_delete(exchange=topic)
            pub_sub.connection.close()

    # ==============================================================================================
    #   Consumer
    # ==============================================================================================
    def test_consumer_factory__general_case(
        self,
        pub_sub: ps.PubSub,
        consumer_callback: ps.ConsumerCallback
    ) -> None:
        test_topic = 'test-topic'
        try:
            consumer = pub_sub.consumer_factory(topic=test_topic, callback=consumer_callback)

            assert consumer.channel == pub_sub.channel
        finally:
            consumer.channel.exchange_delete(test_topic)

    def test_consumer_called__general_case(self, capsys) -> None:

        def start_consumer_thread(
            consumer: ps.Consumer
        ) -> None:
            """Test thread to start the consumer."""
            consumer.start()

        def callback_test_func(channel, method, properties, body: bytes) -> None:
            """Test consumer callback function."""
            print(body.decode(), end='', flush=True)

        test_topic = 'test-topic'
        test_message = 'This is the test message!!!'

        pub_sub = ps.PubSub()
        consumer = pub_sub.consumer_factory(
        topic=test_topic,
        callback=callback_test_func
        )

        thread = thrd.Thread(
            target=start_consumer_thread,
            kwargs={'consumer': consumer},
            daemon=True,
            )
        thread.start()
        thread.join(timeout=0.0)

        pub_sub = ps.PubSub()
        pub_sub.publish(topic=test_topic, message=test_message)
        captured = capsys.readouterr()

        assert captured.out == test_message

# ==================================================================================================
#   Test helpers to copy and paste on python shells to do end-to-end PubSub tests.
# --------------------------------------------------------------------------------------------------
"""
# --------------------------------------------------------------------------------------------------
#   Consumers shell
# --------------------------------------------------------------------------------------------------
import pubsub as ps
import schemas as sch

test_topic = 'test-topic'

def test_callback(channel, method, properties, body: bytes) -> None:
    print(f'\n################## channel: {channel}\n')
    print(f'\n################## method: {method}\n')
    print(f'\n################## properties: {properties}\n')
    print(f'\n################## message: {body.decode()}\n')
    if b'phone_number' in body:
        user_info = sch.UserInfo.model_validate_json(body)
        print(f'\n################## user_info: {user_info}\n')

def test_consume():
    pub_sub = ps.PubSub()
    consumer = pub_sub.consumer_factory(test_topic, test_callback)
    consumer.start()

test_consume()

# --------------------------------------------------------------------------------------------------
#   Producer shell
# --------------------------------------------------------------------------------------------------
import pubsub as ps
import schemas as sch

test_topic = 'test-topic'

def test_produce(msg: str):
    pub_sub = ps.PubSub()
    pub_sub.publish(test_topic, msg)

test_produce('Test Message!!')

user_info = sch.UserInfo(id='test@user.info', name='Mr. User', address='Test Street, 123')
test_produce(user_info.model_dump_json())
"""
