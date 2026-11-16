from netscope.core.ring_buffer import RingBuffer
from netscope.core.time_window import TimeWindow


def test_ring_buffer_id_monotonicity_and_eviction() -> None:
    buffer = RingBuffer[int](max_size=2)
    first = buffer.append(10)
    second = buffer.append(20)
    third = buffer.append(30)

    assert first == 1
    assert second == 2
    assert third == 3
    assert buffer.snapshot() == [10, 20, 30][-2:]
    assert buffer.get(1) is None
    assert buffer.get(2) == 20
    assert buffer.get(3) == 30


def test_ring_buffer_slice() -> None:
    buffer = RingBuffer[int](max_size=5)
    for value in [1, 2, 3, 4]:
        buffer.append(value)

    assert buffer.slice(1, 2) == [2, 3]
    assert buffer.slice(4, 2) == []


def test_time_window_bucket_sums() -> None:
    window = TimeWindow()
    window.add(100.0, 5.0)
    window.add(101.5, 7.0)
    window.add(150.0, 9.0)

    assert window.sum(60.0) == 21.0
    assert window.sum(10.0) == 9.0
    assert len(window.series(20.0, 4)) == 4
