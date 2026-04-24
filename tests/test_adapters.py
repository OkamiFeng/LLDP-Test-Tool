from lldp_tool.adapters import adapter_info_from_record, format_adapter_label
from lldp_tool.models import AdapterInfo


class FakeScapyInterface:
    name = r"\Device\NPF_{1234}"
    description = "Intel(R) Ethernet"
    mac = "74:13:ea:66:33:e8"


def test_adapter_info_from_record_accepts_mapping():
    adapter = adapter_info_from_record(
        {
            "name": "Wi-Fi",
            "description": "Intel(R) Wi-Fi",
            "mac": "74-13-EA-66-33-E8",
        }
    )

    assert adapter.name == "Wi-Fi"
    assert adapter.display_name == "Intel(R) Wi-Fi"
    assert adapter.mac == "74:13:ea:66:33:e8"
    assert adapter.status == "利用可能"


def test_adapter_info_from_record_accepts_object():
    adapter = adapter_info_from_record(FakeScapyInterface())

    assert adapter.name == r"\Device\NPF_{1234}"
    assert adapter.display_name == "Intel(R) Ethernet"
    assert adapter.mac == "74:13:ea:66:33:e8"


def test_format_adapter_label_includes_name_and_mac():
    adapter = AdapterInfo(
        name="Wi-Fi",
        display_name="Intel(R) Wi-Fi",
        mac="74:13:ea:66:33:e8",
        status="利用可能",
    )

    assert format_adapter_label(adapter) == "Intel(R) Wi-Fi (Wi-Fi) - 74:13:ea:66:33:e8"


def test_format_adapter_label_handles_missing_mac():
    adapter = AdapterInfo(
        name="Tailscale",
        display_name="Tailscale Tunnel",
        mac=None,
        status="MACなし",
    )

    assert format_adapter_label(adapter) == "Tailscale Tunnel (Tailscale) - MACなし"
