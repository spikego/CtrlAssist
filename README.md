# CtrlAssist Memory Engine

## Overview

CtrlAssist is a powerful memory manipulation and analysis tool designed for application debugging, reverse engineering, and memory research. It provides comprehensive memory scanning, editing, and process control capabilities through a modern web-based interface.

## Core Features

- **Process Attachment**: Attach to any running process with full memory access
- **Memory Scanner**: Scan for specific values (Int32, Int64, Float, Double, String)
- **Memory Editor**: Modify memory values at specific addresses
- **Offset Calculator**: Calculate memory offsets between addresses
- **Module Base Finder**: Get base addresses of loaded modules
- **Pointer Chain Resolver**: Resolve complex pointer chains
- **Game Speed Control**: Modify application speed using kernel32.dll
- **JVM Detection**: Identify and analyze Java Virtual Machine processes
- **JNI Interface**: Java Native Interface integration for Java applications
- **Visual Overlay**: Pygame-based rendering system for drawing overlays on target windows
- **Single EXE Build**: Portable executable with no dependencies

## Prerequisites

- Windows 10/11 (Administrator privileges required)
- Python 3.8+ (for development)

## Quick Start (Pre-built)

1. Download the latest `CtrlAssist.exe` from releases
2. Run as Administrator (required for memory access)
3. Browser will open automatically to the control interface

## Development Setup

1. Clone the repository:
    ```sh
    git clone <repository-url>
    cd CtrlAssist
    ```

2. Install dependencies:
    ```sh
    pip install -r requirements.txt
    ```

3. Run in development mode:
    ```sh
    python main.py
    ```

## Building the Executable

### Manual Build

1. Install dependencies:
    ```sh
    pip install Flask==2.3.3 psutil==5.9.6 Werkzeug==2.3.7 PyQt6==6.6.0 PyInstaller==6.2.0 Pillow pygame
    ```

2. Clean previous builds (optional):
    ```sh
    taskkill /f /im CtrlAssist.exe
    rmdir /s /q build
    rmdir /s /q dist
    ```

3. Build the executable:
    ```sh
    pyinstaller CtrlAssist.spec
    ```

4. Find `CtrlAssist.exe` in the `dist` folder

## Usage Guide

### 1. Process Management
- View all running processes in the left panel
- Use the search box to filter processes by name
- Click on any process to select it
- Process information will be displayed in the status bar

### 2. Memory Operations

#### Attach to Process
1. Select a process from the list
2. Click "Attach to Selected Process"
3. Wait for confirmation message

#### Memory Scanning
1. Choose value type (Int32, Int64, Float, Double, String)
2. Enter the value to search for
3. Click "Scan Memory"
4. Results will show up to 100 matches
5. Click any result to auto-fill the memory editor

#### Memory Editing
1. Enter memory address (hex format)
2. Enter new value
3. Select value type
4. Click "Write Memory"

### 3. Advanced Features

#### Offset Calculator
1. Enter module name to get base address
2. Enter base and target addresses
3. Calculate the offset between them

#### Pointer Chain Resolver
1. Enter base address
2. Enter comma-separated offsets (hex)
3. Resolve the final memory address

#### Game Speed Control (TAS)
1. Select a process
2. Adjust speed multiplier (0.1x to 5.0x)
3. Apply speed changes using TAS technology
4. Use "Unload DLL" to stop speed control

#### Network Analyzer
1. **Start Capture**: Begin monitoring network traffic
2. **Protocol Filter**: Filter by TCP, UDP, ICMP, or All
3. **Port Filter**: Monitor specific ports (e.g., 80, 443)
4. **IP Filter**: Monitor traffic to/from specific IP addresses
5. **Statistics**: View packet counts and data transfer stats
6. **Clear**: Remove captured packets from display
7. **Stop**: End packet capture session

**Network Features:**
- Real-time packet monitoring
- Protocol analysis (TCP/UDP/ICMP)
- Source/destination tracking
- Packet size and timing information
- Click packets for detailed information
- Export capabilities for analysis

## Quick Start Tutorial

### For Beginners
1. **Run as Administrator**: Right-click CtrlAssist.exe and select "Run as administrator"
2. **Select Target Process**: Use the search box to find your game/application, then click on it
3. **Attach to Process**: Click "Attach to Selected Process" button
4. **Find Values**: Enter a known value (like health, money) and click "Scan Memory"
5. **Modify Values**: Click on a scan result, modify the value, and click "Write Memory"
6. **Verify Changes**: Check if the value changed in your game/application

### Common Use Cases
- **Game Analysis**: Find memory addresses for game variables
- **Speed Control**: Use TAS technology for frame-perfect gameplay
- **Network Monitoring**: Analyze game network traffic and protocols
- **Debugging**: Analyze application memory and network behavior
- **Research**: Study application behavior and data flow

### Network Analysis Tutorial
1. **Start Monitoring**: Click "Start Capture" in Network Analyzer
2. **Set Filters**: Choose protocol (TCP/UDP) and specific ports if needed
3. **Monitor Traffic**: Watch real-time packet flow
4. **Analyze Packets**: Click on packets to see detailed information
5. **Export Data**: Use statistics to understand traffic patterns

## Technical Details

### Memory Engine
- Uses Windows API (kernel32.dll) for memory operations
- Supports multiple data types with proper struct packing
- Implements memory protection and error handling
- Efficient memory scanning with region filtering

### Speed Control (TAS)
- Uses Tool-Assisted Speedrun (TAS) technology
- Process suspension/resumption for precise timing
- Frame-perfect speed control
- Safe operation with automatic cleanup

### Network Engine
- Real-time packet capture and analysis
- Protocol filtering (TCP/UDP/ICMP)
- Port and IP address filtering
- Traffic statistics and monitoring
- Packet inspection and export capabilities

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.