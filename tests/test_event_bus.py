import unittest

from monitor.event_bus import EventBus


class EventBusTests(unittest.TestCase):
    def test_subscriber_added_during_publish_does_not_mutate_iteration(self):
        bus = EventBus()
        received = []

        def second_listener(event):
            received.append(("second", event["type"]))

        def first_listener(event):
            received.append(("first", event["type"]))
            bus.subscribe(second_listener)

        bus.subscribe(first_listener)
        bus.publish({"type": "TEST_EVENT"})

        self.assertEqual(received, [("first", "TEST_EVENT")])

        bus.publish({"type": "TEST_EVENT_2"})
        self.assertEqual(
            received,
            [
                ("first", "TEST_EVENT"),
                ("first", "TEST_EVENT_2"),
                ("second", "TEST_EVENT_2"),
            ],
        )

    def test_subscriber_can_publish_without_deadlock(self):
        bus = EventBus()
        received = []

        def listener(event):
            received.append(event["type"])
            if event["type"] == "PARENT":
                bus.publish({"type": "CHILD"})

        bus.subscribe(listener)
        bus.publish({"type": "PARENT"})

        self.assertEqual(received, ["PARENT", "CHILD"])


if __name__ == "__main__":
    unittest.main()
