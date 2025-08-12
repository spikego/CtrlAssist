import ctypes
import struct
import psutil
import ctypes.wintypes as wintypes

# 定义MEMORY_BASIC_INFORMATION结构
class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD)
    ]
from typing import List, Dict, Any, Optional, Tuple
import threading
import time

class MemoryEngine:
    def __init__(self):
        self.kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        self.process_handle = None
        self.current_pid = None
        
        # 定义常量
        self.PROCESS_ALL_ACCESS = 0x1F0FFF
        self.MEM_COMMIT = 0x1000
        self.PAGE_READWRITE = 0x04
        self.PAGE_READONLY = 0x02
        
    def attach_process(self, pid: int) -> bool:
        """附加到进程"""
        try:
            if self.process_handle:
                self.kernel32.CloseHandle(self.process_handle)
            
            self.process_handle = self.kernel32.OpenProcess(
                self.PROCESS_ALL_ACCESS, False, pid
            )
            if self.process_handle:
                self.current_pid = pid
                return True
            return False
        except Exception:
            return False
    
    def detach_process(self):
        """分离进程"""
        if self.process_handle:
            self.kernel32.CloseHandle(self.process_handle)
            self.process_handle = None
            self.current_pid = None
    
    def read_memory(self, address: int, size: int) -> Optional[bytes]:
        """读取内存"""
        if not self.process_handle:
            return None
        
        buffer = ctypes.create_string_buffer(size)
        bytes_read = ctypes.c_size_t()
        
        success = self.kernel32.ReadProcessMemory(
            self.process_handle,
            ctypes.c_void_p(address),
            buffer,
            size,
            ctypes.byref(bytes_read)
        )
        
        return buffer.raw if success else None
    
    def write_memory(self, address: int, data: bytes) -> bool:
        """写入内存"""
        if not self.process_handle:
            return False
        
        bytes_written = ctypes.c_size_t()
        success = self.kernel32.WriteProcessMemory(
            self.process_handle,
            ctypes.c_void_p(address),
            data,
            len(data),
            ctypes.byref(bytes_written)
        )
        
        return success and bytes_written.value == len(data)
    
    def scan_memory_value(self, value: Any, value_type: str, start_addr: int = 0, end_addr: int = 0x7FFFFFFF) -> List[int]:
        """扫描内存中的特定值"""
        if not self.process_handle:
            return []
        
        results = []
        current_addr = start_addr
        
        # 根据类型确定数据格式和大小
        type_info = {
            'int32': (4, 'i'),
            'int64': (8, 'q'),
            'float': (4, 'f'),
            'double': (8, 'd'),
            'string': (len(str(value)), 's')
        }
        
        if value_type not in type_info:
            return []
        
        size, fmt = type_info[value_type]
        
        # 准备搜索的字节模式
        if value_type == 'string':
            search_bytes = str(value).encode('utf-8')
        else:
            search_bytes = struct.pack(fmt, value)
        
        # 内存扫描
        while current_addr < end_addr:
            mbi = MEMORY_BASIC_INFORMATION()
            if not self.kernel32.VirtualQueryEx(
                self.process_handle,
                ctypes.c_void_p(current_addr),
                ctypes.byref(mbi),
                ctypes.sizeof(mbi)
            ):
                break
            
            if (mbi.State == self.MEM_COMMIT and 
                mbi.Protect in [self.PAGE_READWRITE, self.PAGE_READONLY]):
                
                data = self.read_memory(mbi.BaseAddress, mbi.RegionSize)
                if data:
                    offset = 0
                    while True:
                        pos = data.find(search_bytes, offset)
                        if pos == -1:
                            break
                        results.append(mbi.BaseAddress + pos)
                        offset = pos + 1
            
            current_addr = mbi.BaseAddress + mbi.RegionSize
        
        return results
    
    def rescan_memory_addresses(self, addresses: List[str], value: Any, value_type: str) -> List[int]:
        """在指定地址列表中重新扫描特定值"""
        if not self.process_handle:
            return []
        
        results = []
        
        # 根据类型确定数据格式和大小
        type_info = {
            'int32': (4, 'i'),
            'int64': (8, 'q'),
            'float': (4, 'f'),
            'double': (8, 'd'),
            'string': (len(str(value)), 's')
        }
        
        if value_type not in type_info:
            return []
        
        size, fmt = type_info[value_type]
        
        # 准备搜索的字节模式
        if value_type == 'string':
            search_bytes = str(value).encode('utf-8')
        else:
            search_bytes = struct.pack(fmt, value)
        
        # 检查每个地址
        for addr_str in addresses:
            try:
                addr = int(addr_str, 16)
                data = self.read_memory(addr, len(search_bytes))
                if data and data == search_bytes:
                    results.append(addr)
            except Exception:
                continue
        
        return results
    
    def get_module_base(self, module_name: str) -> Optional[int]:
        """获取模块基址"""
        if not self.current_pid:
            return None
        
        try:
            process = psutil.Process(self.current_pid)
            for module in process.memory_maps():
                if module_name.lower() in module.path.lower():
                    return int(module.addr.split('-')[0], 16)
        except Exception:
            pass
        return None
    
    def calculate_offset(self, base_addr: int, target_addr: int) -> int:
        """计算偏移值"""
        return target_addr - base_addr
    
    def resolve_pointer_chain(self, base_addr: int, offsets: List[int]) -> Optional[int]:
        """解析指针链"""
        if not self.process_handle:
            return None
        
        current_addr = base_addr
        
        for offset in offsets[:-1]:
            addr_data = self.read_memory(current_addr + offset, 8)
            if not addr_data:
                return None
            current_addr = struct.unpack('Q', addr_data)[0]
        
        return current_addr + offsets[-1] if offsets else current_addr

class GameSpeedController:
    def __init__(self):
        from .kernel32_inject import Kernel32Hook
        self.hook = Kernel32Hook()
        
    def set_game_speed(self, pid: int, speed_multiplier: float) -> bool:
        """设置游戏速度"""
        return self.hook.inject_hook(pid, speed_multiplier)
    
    def reset_speed(self, pid: int) -> bool:
        """重置游戏速度"""
        return self.hook.remove_hook(pid)