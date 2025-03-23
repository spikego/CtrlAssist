# Game Control Dashboard

## Overview

This project is a game control dashboard that allows users to manage game processes, scan and modify memory, control game speed, and execute Python and Kotlin scripts. It also supports uploading script files for execution.

## Features

- **Process Management**: View and select running processes.
- **Memory Scanning**: Scan memory for specific values.
- **Memory Modification**: Modify memory values at specific addresses.
- **Game Speed Control**: Adjust the speed of games.
- **Script Execution**: Execute Python and Kotlin scripts.
- **Script File Upload**: Upload and execute script files.

## Prerequisites

- Python 3.x
- Flask
- psutil
- ctypes
- struct
- subprocess
- werkzeug

## Installation

1. Clone the repository:
    ```sh
    git clone https://github.com/spikego/game-control-dashboard.git
    cd game-control-dashboard
    ```

2. Create and activate a virtual environment:
    ```sh
    python -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`
    ```

3. Install the required packages:
    ```sh
    pip install -r requirements.txt
    ```

## Building the Executable

1. Install PyInstaller:
    ```sh
    pip install pyinstaller
    ```

2. Create a `pyinstaller.spec` file with the following content:
    ```python
    # -*- mode: python ; coding: utf-8 -*-

    block_cipher = None

    a = Analysis(
        ['main.py'],
        pathex=['.'],
        binaries=[],
        datas=[('app/templates', 'app/templates'), ('app/static', 'app/static')],
        hiddenimports=[],
        hookspath=[],
        runtime_hooks=[],
        excludes=[],
        noarchive=False,
        optimize=0,
    )
    pyz = PYZ(a.pure)

    exe = EXE(
        pyz,
        a.scripts,
        [],
        exclude_binaries=True,
        name='game_control_dashboard',
        debug=False,
        bootloader_ignore_signals=False,
        strip=False,
        upx=True,
        console=True,
    )
    coll = COLLECT(
        exe,
        a.binaries,
        a.zipfiles,
        a.datas,
        strip=False,
        upx=True,
        upx_exclude=[],
        name='game_control_dashboard',
    )
    ```

3. Build the executable:
    ```sh
    pyinstaller CtrlAssist.spec
    ```

4. Find the executable in the `dist/game_control_dashboard` directory.

## Usage

1. Run the application:
    ```sh
    python main.py
    ```

2. Open your web browser and navigate to `http://127.0.0.1:5000`.

## Detailed Tutorial

### Process Management

1. **View Processes**: The dashboard displays a list of running processes. Click on a process to view its details.
2. **Refresh Processes**: Click the "Refresh Processes" button to update the list of running processes.

### Memory Scanning

1. **Select Scan Type**: Choose "Exact Value" or "Value Range".
2. **Select Value Type**: Choose the type of value to scan for (integer, float, or string).
3. **Enter Value**: Enter the value to scan for.
4. **Scan Memory**: Click the "Scan" button to start scanning memory. Results will be displayed in a list.

### Memory Modification

1. **Enter Memory Address**: Enter the memory address to modify.
2. **Enter New Value**: Enter the new value to write to the memory address.
3. **Modify Memory**: Click the "Modify Memory" button to apply the changes.

### Game Speed Control

1. **Enter Game ID**: Enter the ID of the game to control.
2. **Adjust Speed**: Use the range slider to set the desired game speed.
3. **Change Speed**: Click the "Change Speed" button to apply the new speed.

### Script System Tutorial

#### Script Execution

1. **Select Script Type**: Choose the type of script to execute (Python or Kotlin).
2. **Enter Script Content**: Input the script content in the text area.
3. **Execute Script**: Click the "Execute Script" button to run the script. The result will be displayed below.

#### Script File Upload

1. **Select Script File**: Click the "Choose File" button to select a script file (.py, .kt).
2. **Upload Script**: Click the "Upload Script" button to upload and execute the script file. The result will be displayed below.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.