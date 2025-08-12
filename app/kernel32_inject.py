import ctypes
import os
import logging

logger = logging.getLogger(__name__)

class Kernel32Hook:
    def __init__(self):
        self.hooked_processes = {}
        self.dll_path = os.path.join(os.path.dirname(__file__), 'static', 'dll', 'libSpeedHook.dll')
        
    def inject_hook(self, pid: int, speed_multiplier: float) -> bool:
        try:
            if not os.path.exists(self.dll_path):
                logger.error(f"DLL not found: {self.dll_path}")
                return False
            
            # 使用subprocess调用外部DLL注入工具
            import subprocess
            result = subprocess.run([
                'powershell', '-Command',
                f'Add-Type -TypeDefinition @"\nusing System;\nusing System.Diagnostics;\nusing System.Runtime.InteropServices;\npublic class DllInjector {{\n    [DllImport("kernel32.dll")]\n    public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);\n    [DllImport("kernel32.dll")]\n    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);\n    [DllImport("kernel32.dll")]\n    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);\n    [DllImport("kernel32.dll")]\n    public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);\n    [DllImport("kernel32.dll")]\n    public static extern IntPtr GetModuleHandle(string lpModuleName);\n    [DllImport("kernel32.dll")]\n    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);\n    [DllImport("kernel32.dll")]\n    public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);\n    [DllImport("kernel32.dll")]\n    public static extern bool CloseHandle(IntPtr hObject);\n    public static bool InjectDll(int processId, string dllPath) {{\n        IntPtr hProcess = OpenProcess(0x1F0FFF, false, processId);\n        if (hProcess == IntPtr.Zero) return false;\n        IntPtr allocMem = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)((dllPath.Length + 1) * 2), 0x3000, 0x40);\n        if (allocMem == IntPtr.Zero) {{ CloseHandle(hProcess); return false; }}\n        byte[] dllBytes = System.Text.Encoding.Unicode.GetBytes(dllPath + "\\0");\n        UIntPtr bytesWritten;\n        if (!WriteProcessMemory(hProcess, allocMem, dllBytes, (uint)dllBytes.Length, out bytesWritten)) {{ CloseHandle(hProcess); return false; }}\n        IntPtr hKernel32 = GetModuleHandle("kernel32.dll");\n        IntPtr hLoadLib = GetProcAddress(hKernel32, "LoadLibraryW");\n        IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, hLoadLib, allocMem, 0, IntPtr.Zero);\n        if (hThread == IntPtr.Zero) {{ CloseHandle(hProcess); return false; }}\n        WaitForSingleObject(hThread, 5000);\n        CloseHandle(hThread);\n        CloseHandle(hProcess);\n        return true;\n    }}\n}}\n"@; [DllInjector]::InjectDll({pid}, "{self.dll_path}")'
            ], capture_output=True, text=True)
            
            if result.returncode == 0 and 'True' in result.stdout:
                self.hooked_processes[pid] = {'speed': speed_multiplier}
                logger.info(f"DLL injected to process {pid}")
                return True
            else:
                logger.error(f"PowerShell injection failed: {result.stderr}")
                return False
            
        except Exception as e:
            logger.error(f"Injection failed: {e}")
            return False
    
    def remove_hook(self, pid: int) -> bool:
        if pid in self.hooked_processes:
            del self.hooked_processes[pid]
            logger.info(f"Hook removed for process {pid}")
        return True