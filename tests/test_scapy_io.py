from types import SimpleNamespace

from lldp_tool.scapy_io import ScapyLldpRuntime


class FakeScapyApi:
    def __init__(self):
        self.conf = SimpleNamespace(
            ifaces={
                "eth0": {
                    "name": "eth0",
                    "description": "Intel Ethernet",
                    "mac": "74:13:ea:66:33:e8",
                }
            }
        )
        self.sent = None
        self.ether_input = None

    def Ether(self, frame):
        self.ether_input = frame
        return ("Ether", frame)

    def sendp(self, packet, iface, verbose):
        self.sent = (packet, iface, verbose)

    def sniff(self, iface, filter, timeout, store):
        valid = bytes.fromhex("0180c200000e7413ea6633e888cc020704001122334455")
        invalid = bytes.fromhex("ffffffffffff7413ea6633e808000001")
        return [valid, invalid]


def test_scapy_runtime_lists_adapters_from_conf():
    runtime = ScapyLldpRuntime(scapy_api=FakeScapyApi())

    adapters = runtime.list_adapters()

    assert len(adapters) == 1
    assert adapters[0].name == "eth0"
    assert adapters[0].display_name == "Intel Ethernet"


def test_scapy_runtime_sends_frame_with_selected_interface():
    api = FakeScapyApi()
    runtime = ScapyLldpRuntime(scapy_api=api)
    frame = bytes.fromhex("0180c200000e7413ea6633e888cc020704001122334455")

    runtime.send_frame("eth0", frame)

    assert api.ether_input == frame
    assert api.sent == (("Ether", frame), "eth0", False)


def test_scapy_runtime_sniff_once_returns_only_lldp_frames():
    runtime = ScapyLldpRuntime(scapy_api=FakeScapyApi())

    packets = runtime.sniff_once("eth0", timeout=0.1)

    assert len(packets) == 1
    assert packets[0].ethertype == 0x88CC
    assert packets[0].src_mac == "74:13:ea:66:33:e8"
