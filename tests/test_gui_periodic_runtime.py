import queue
import threading
from types import SimpleNamespace

from lldp_tool.gui import LldpToolApp
from lldp_tool.input_packets import InputMode
from lldp_tool.periodic import PeriodicSendConfig
from lldp_tool.scapy_io import ScapyRuntimeError


class StoppingRuntime:
    def __init__(self, stop_event):
        self.stop_event = stop_event
        self.sent = []

    def send_frame(self, interface_name, frame):
        self.sent.append((interface_name, frame))
        self.stop_event.set()


class FailingRuntime:
    def send_frame(self, interface_name, frame):
        raise ScapyRuntimeError("周期送信のテスト失敗")


def test_periodic_send_loop_sends_immediately_and_stops():
    stop_event = threading.Event()
    event_queue = queue.Queue()
    runtime = StoppingRuntime(stop_event)
    app = SimpleNamespace(
        periodic_stop=stop_event,
        event_queue=event_queue,
        runtime=runtime,
    )
    config = PeriodicSendConfig(
        interval_seconds=1,
        mode=InputMode.LLDPDU,
        input_data=b"\x00\x00",
        source_mac="74:13:ea:66:33:e8",
        adapter_name="eth0",
    )

    LldpToolApp._periodic_send_loop(app, config)

    assert len(runtime.sent) == 1
    assert runtime.sent[0][0] == "eth0"
    assert event_queue.get_nowait()[0] == "periodic_sent"
    assert event_queue.get_nowait()[0] == "periodic_stopped"


def test_periodic_send_loop_stops_on_send_error():
    stop_event = threading.Event()
    event_queue = queue.Queue()
    app = SimpleNamespace(
        periodic_stop=stop_event,
        event_queue=event_queue,
        runtime=FailingRuntime(),
    )
    config = PeriodicSendConfig(
        interval_seconds=1,
        mode=InputMode.LLDPDU,
        input_data=b"\x00\x00",
        source_mac="74:13:ea:66:33:e8",
        adapter_name="eth0",
    )

    LldpToolApp._periodic_send_loop(app, config)

    error_kind, error_message = event_queue.get_nowait()
    assert error_kind == "periodic_error"
    assert "周期送信のテスト失敗" in error_message
    assert event_queue.get_nowait()[0] == "periodic_stopped"
    assert stop_event.is_set()
