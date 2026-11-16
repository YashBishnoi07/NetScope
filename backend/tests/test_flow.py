from netscope.flow import FlowTracker


def test_flow_tracker_updates_packets() -> None:
    tracker = FlowTracker()
    flow = tracker.update({"flow_key": "a->b", "src": "a", "dst": "b", "src_port": 80, "dst_port": 443, "protocol": "TCP", "length": 128, "timestamp": 1.0})
    flow = tracker.update({"flow_key": "a->b", "src": "a", "dst": "b", "src_port": 80, "dst_port": 443, "protocol": "TCP", "length": 256, "timestamp": 2.0})

    assert flow.packets == 2
    assert flow.bytes_total == 384
    assert flow.protocol == "TCP"
    assert tracker.flows["a->b"].key == "a->b"
