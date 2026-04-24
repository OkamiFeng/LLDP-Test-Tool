from pathlib import Path

from lldp_tool.npcap import detect_npcap_status, find_bundled_npcap_installer


def test_detect_npcap_status_reports_available_when_dlls_and_driver_exist(tmp_path):
    npcap_dir = tmp_path / "System32" / "Npcap"
    npcap_dir.mkdir(parents=True)
    (npcap_dir / "wpcap.dll").write_bytes(b"")
    (npcap_dir / "Packet.dll").write_bytes(b"")

    status = detect_npcap_status(
        system_root=tmp_path,
        service_lookup=lambda: {"npcap": "Running"},
    )

    assert status.installed is True
    assert status.driver_running is True
    assert "利用可能" in status.message


def test_detect_npcap_status_reports_missing_when_dlls_do_not_exist(tmp_path):
    status = detect_npcap_status(
        system_root=tmp_path,
        service_lookup=lambda: {},
    )

    assert status.installed is False
    assert status.driver_running is False
    assert "見つかりません" in status.message


def test_find_bundled_npcap_installer_prefers_drivers_directory(tmp_path):
    (tmp_path / "drivers").mkdir()
    expected = tmp_path / "drivers" / "npcap-1.80.exe"
    fallback = tmp_path / "npcap-1.79.exe"
    expected.write_bytes(b"")
    fallback.write_bytes(b"")

    assert find_bundled_npcap_installer(tmp_path) == expected


def test_find_bundled_npcap_installer_returns_none_when_absent(tmp_path):
    assert find_bundled_npcap_installer(Path(tmp_path)) is None
