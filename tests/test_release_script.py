from pathlib import Path


def test_build_release_uses_temporary_pyinstaller_workpath_and_cleans_it():
    script = Path("scripts/build_release.ps1").read_text(encoding="utf-8")

    assert "--workpath" in script
    assert "--specpath" in script
    assert "Remove-Item -LiteralPath $PyInstallerWorkDir -Recurse -Force" in script
    assert "Remove-Item -LiteralPath $PyInstallerSpecDir -Recurse -Force" in script
