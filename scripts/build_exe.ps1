# Builds dist\chokidaar.exe: trains the model, then packs the proxy, its
# dependencies and the model into one executable with PyInstaller.
#
# Usage (from any directory, with requirements-dev.txt installed):
#   powershell -ExecutionPolicy Bypass -File scripts\build_exe.ps1

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$model = Join-Path "models" "model.joblib"

# Imported by name at run time (pickled model, Cython modules, uvicorn's
# protocol and loop selection), so PyInstaller cannot find them on its own.
$hiddenImports = @(
    "sklearn.feature_extraction.text",
    "sklearn.linear_model._logistic",
    "sklearn.preprocessing._data",
    "sklearn.utils._typedefs",
    "sklearn.utils._heap",
    "sklearn.utils._sorting",
    "sklearn.utils._vector_sentinel",
    "sklearn.utils._cython_blas",
    "sklearn.neighbors._partition_nodes",
    "scipy.sparse.csgraph._validation",
    "scipy._lib.messagestream",
    "joblib",
    "joblib.numpy_pickle",
    "uvicorn.logging",
    "uvicorn.loops.auto",
    "uvicorn.loops.asyncio",
    "uvicorn.protocols.http.auto",
    "uvicorn.protocols.http.h11_impl",
    "uvicorn.protocols.websockets.auto",
    "uvicorn.lifespan.on",
    "uvicorn.lifespan.off"
)

Push-Location $root
try {
    Write-Host "Training the model..."
    python -m ml.train --out $model
    if ($LASTEXITCODE -ne 0) { throw "python -m ml.train failed" }

    $pyinstallerArgs = @(
        "--noconfirm", "--clean", "--onefile", "--console",
        "--name", "chokidaar",
        "--paths", ".",
        "--add-data", "$model;models"
    )
    foreach ($name in $hiddenImports) { $pyinstallerArgs += @("--hidden-import", $name) }

    Write-Host "Building dist\chokidaar.exe..."
    python -m PyInstaller @pyinstallerArgs (Join-Path "proxy" "cli.py")
    if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed" }

    Write-Host "Built $(Join-Path $root 'dist\chokidaar.exe')"
}
finally {
    Pop-Location
}
