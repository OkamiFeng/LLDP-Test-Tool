import runpy
from pathlib import Path


def test_main_entrypoint_can_be_loaded_as_a_pyinstaller_script():
    runpy.run_path(
        str(Path("src") / "lldp_tool" / "__main__.py"),
        run_name="pyinstaller_entry_probe",
    )
