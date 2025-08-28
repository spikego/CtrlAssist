import ctypes
import struct
import psutil
import ctypes.wintypes as wintypes
from typing import List, Dict, Any, Optional, Tuple, Union
import threading
import time
from enum import Enum
import logging
import array
import mmap

try:
    import pymem
    import pymem.process
except ImportError:
    pymem = None

# 设置日志
logger = logging.getLogger(__name__)

# Windows API常量
PROCESS_ALL_ACCESS = 0x1F0FFF
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008
PAGE_READWRITE = 0x04
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000

class MemoryError(Exception):
    """内存操作异常"""
    pass

# 定义MEMORY_BASIC_INFORMATION结构
class MEMORY_BASIC_INFORMATION64(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_ulonglong),
        ("AllocationBase", ctypes.c_ulonglong),
        ("AllocationProtect", wintypes.DWORD),
        ("__alignment1", wintypes.DWORD),
        ("RegionSize", ctypes.c_ulonglong),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
        ("__alignment2", wintypes.DWORD)
    ]


class ScanType(Enum):
    EXACT_VALUE = "exact_value"
    BIGGER_THAN = "bigger_than"
    SMALLER_THAN = "smaller_than"
    BETWEEN = "between"
    INCREASED_VALUE = "increased_value"
    INCREASED_BY = "increased_by"
    DECREASED_VALUE = "decreased_value"
    DECREASED_BY = "decreased_by"
    CHANGED_VALUE = "changed_value"
    UNCHANGED_VALUE = "unchanged_value"
    UNKNOWN_INITIAL = "unknown_initial"


class ValueType(Enum):
    BINARY = "binary"
    BYTE = "byte"  # 1字节
    WORD_2BYTES = "2bytes"  # 2字节
    DWORD_4BYTES = "4bytes"  # 4字节
    QWORD_8BYTES = "8bytes"  # 8字节
    FLOAT = "float"  # 4字节浮点
    DOUBLE = "double"  # 8字节浮点
    STRING = "string"  # 字符串
    BYTE_ARRAY = "byte_array"  # 字节数组
    ALL_TYPES = "all_types"  # 自动检测类型
    GROUP = "group"  # 组合类型


class MemoryRegion:
    """内存区域描述"""
    def __init__(self, base_address: int, size: int, protect: int, state: int, type: int):
        self.base_address = base_address
        self.size = size
        self.protect = protect
        self.state = state
        self.type = type
        self.is_readable = bool(protect & 0x04 or protect & 0x20 or protect & 0x40)
        self.is_writable = bool(protect & 0x04 or protect & 0x40)
        self.is_executable = bool(protect & 0x10 or protect & 0x20 or protect & 0x40)
        self.is_private = bool(type & 0x20000)


class ScanResult:
    """扫描结果"""
    def __init__(self, address: int, current_value: Any, previous_value: Any = None,
                 value_type: ValueType = None, size: int = 0):
        self.address = address
        self.current_value = current_value
        self.previous_value = previous_value
        self.frozen = False
        self.value_type = value_type
        self.size = size
        self.last_update = time.time()
        self._lock = threading.Lock()

    def update_value(self, new_value: Any):
        """更新值"""
        with self._lock:
            self.previous_value = self.current_value
            self.current_value = new_value
            self.last_update = time.time()


class ScanOptions:
    """扫描选项"""
    def __init__(self):
        self.start_address = 0x00000000
        self.stop_address = 0x7FFFFFFFFFFFFFFF
        self.readable = True
        self.writable = False
        self.executable = False
        self.private_only = True
        self.fast_scan = True
        self.alignment = 4
        self.max_results = 10000
        self.min_value_size = 1
        self.max_value_size = 8
        self.buffer_size = 1024 * 1024  # 1MB缓冲区
        self.scan_page_size = mmap.PAGESIZE
        self.string_encoding = 'utf-8'
        self.string_null_terminated = True


class MemoryEngine:
    def __init__(self):
        self.kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        self.process_handle = None
        self.current_pid = None
        self.scan_results = []
        self.scan_history = []
        self.scan_options = ScanOptions()
        self.pymem_process = None
        self.previous_scan_results = []  # 存储上一次扫描结果用于比较

        # 定义常量
        self.PROCESS_ALL_ACCESS = 0x1F0FFF
        self.MEM_COMMIT = 0x1000
        self.MEM_FREE = 0x10000
        self.PAGE_NOACCESS = 0x01
        self.PAGE_READONLY = 0x02
        self.PAGE_READWRITE = 0x04
        self.PAGE_WRITECOPY = 0x08
        self.PAGE_EXECUTE = 0x10
        self.PAGE_EXECUTE_READ = 0x20
        self.PAGE_EXECUTE_READWRITE = 0x40
        self.PAGE_EXECUTE_WRITECOPY = 0x80
        self.PAGE_GUARD = 0x100
        self.MEM_PRIVATE = 0x20000
        self.MEM_MAPPED = 0x40000
        self.MEM_IMAGE = 0x1000000

        # 设置VirtualQueryEx为64位版本
        self.VirtualQueryEx = self.kernel32.VirtualQueryEx
        self.VirtualQueryEx.argtypes = [
            wintypes.HANDLE,
            wintypes.LPCVOID,
            ctypes.POINTER(MEMORY_BASIC_INFORMATION64),
            ctypes.c_size_t
        ]
        self.VirtualQueryEx.restype = ctypes.c_size_t

    def attach_process(self, pid: int) -> bool:
        """附加到进程"""
        try:
            if self.process_handle:
                self.kernel32.CloseHandle(self.process_handle)

            if self.pymem_process:
                self.pymem_process.close()

            # 优先使用pymem
            if pymem:
                try:
                    self.pymem_process = pymem.Pymem(pid)
                    self.current_pid = pid
                    logger.info(f"Attached to process {pid} using pymem")
                    return True
                except Exception as e:
                    logger.error(f"Pymem attach failed: {e}")
                    pass

            # 备用方案
            self.process_handle = self.kernel32.OpenProcess(
                self.PROCESS_ALL_ACCESS, False, pid
            )
            if self.process_handle:
                self.current_pid = pid
                logger.info(f"Attached to process {pid} using OpenProcess")
                return True
            logger.error(f"OpenProcess failed for PID {pid}")
            return False
        except Exception as e:
            logger.error(f"Attach process failed: {e}")
            return False

    def detach_process(self):
        """分离进程"""
        if self.pymem_process:
            self.pymem_process.close()
            self.pymem_process = None
        if self.process_handle:
            self.kernel32.CloseHandle(self.process_handle)
            self.process_handle = None
        self.current_pid = None
        self.scan_results = []
        self.scan_history = []
        self.previous_scan_results = []

    def read_memory(self, address: int, size: int) -> Optional[bytes]:
        """读取内存"""
        try:
            if self.pymem_process:
                return self.pymem_process.read_bytes(address, size)
        except Exception as e:
            logger.debug(f"Pymem read failed at {hex(address)}: {e}")
            pass

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

        if not success:
            logger.debug(f"ReadProcessMemory failed at {hex(address)}")
            return None

        return buffer.raw

    def write_memory(self, address: int, data: bytes) -> bool:
        """写入内存"""
        try:
            if self.pymem_process:
                self.pymem_process.write_bytes(address, data, len(data))
                return True
        except Exception as e:
            logger.debug(f"Pymem write failed at {hex(address)}: {e}")
            pass

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

    def _value_to_bytes(self, value: Any, value_type: ValueType) -> bytes:
        """将不同类型的值转换为字节序列"""
        if value_type == ValueType.BYTE:
            return struct.pack('B', value)
        elif value_type == ValueType.WORD_2BYTES:
            return struct.pack('H', value)
        elif value_type == ValueType.DWORD_4BYTES:
            return struct.pack('I', value)
        elif value_type == ValueType.QWORD_8BYTES:
            return struct.pack('Q', value)
        elif value_type == ValueType.FLOAT:
            return struct.pack('f', value)
        elif value_type == ValueType.DOUBLE:
            return struct.pack('d', value)
        elif value_type == ValueType.STRING:
            return value.encode('utf-8')
        elif value_type == ValueType.BYTE_ARRAY:
            return bytes(value)
        raise ValueError(f"Unsupported value type: {value_type}")

    def _bytes_to_value(self, data: bytes, value_type: ValueType) -> Any:
        """将字节序列转换为指定类型的值"""
        try:
            if value_type == ValueType.BYTE:
                return struct.unpack('B', data)[0]
            elif value_type == ValueType.WORD_2BYTES:
                return struct.unpack('H', data)[0]
            elif value_type == ValueType.DWORD_4BYTES:
                return struct.unpack('I', data)[0]
            elif value_type == ValueType.QWORD_8BYTES:
                return struct.unpack('Q', data)[0]
            elif value_type == ValueType.FLOAT:
                return struct.unpack('f', data)[0]
            elif value_type == ValueType.DOUBLE:
                return struct.unpack('d', data)[0]
            elif value_type == ValueType.STRING:
                return data.decode('utf-8').rstrip('\0')
            elif value_type == ValueType.BYTE_ARRAY:
                return list(data)
        except struct.error:
            return None
        return None

    def write_value_to_address(self, address: int, value: Any, value_type: ValueType) -> bool:
        """向指定地址写入数值"""
        try:
            if value_type == ValueType.BYTE:
                data = struct.pack('B', int(value))
            elif value_type == ValueType.WORD_2BYTES:
                data = struct.pack('H', int(value))
            elif value_type == ValueType.DWORD_4BYTES:
                data = struct.pack('I', int(value))
            elif value_type == ValueType.QWORD_8BYTES:
                data = struct.pack('Q', int(value))
            elif value_type == ValueType.FLOAT:
                data = struct.pack('f', float(value))
            elif value_type == ValueType.DOUBLE:
                data = struct.pack('d', float(value))
            elif value_type == ValueType.STRING:
                data = str(value).encode('utf-8')
            else:
                return False

            return self.write_memory(address, data)
        except Exception as e:
            logger.error(f"Write value failed: {e}")
            return False

    def first_scan(self, scan_type: ScanType, value_type: ValueType, value1: Any = None, value2: Any = None) -> int:
        """首次扫描"""
        logger.info(f"Starting first scan: type={scan_type}, value_type={value_type}, value1={value1}, value2={value2}")

        if not self.pymem_process and not self.process_handle:
            logger.error("No process attached")
            return 0

            # 保存上一次扫描结果用于比较
        self.previous_scan_results = [(r.address, r.current_value) for r in
                                        self.scan_results] if self.scan_results else []

        self.scan_results = []
        results = []
        regions_scanned = 0


        # 使用pymem的简化扫描
        if self.pymem_process and scan_type == ScanType.EXACT_VALUE and value1 is not None:
            try:
                logger.info("Using pymem scan")
                addresses = self._pymem_scan_value(value1, value_type)
                logger.info(f"Pymem found {len(addresses)} addresses")
                for addr in addresses[:10000]:
                    results.append(ScanResult(addr, value1))
            except Exception as e:
                logger.error(f"Pymem scan failed: {e}")

        # 如果pymem扫描失败或不支持，使用原始方法
        if not results:
            logger.info("Using manual scan")
            current_addr = self.scan_options.start_address
            logger.info(f"Scan range: {hex(self.scan_options.start_address)} - {hex(self.scan_options.stop_address)}")

            while current_addr < self.scan_options.stop_address:
                try:
                    mbi = MEMORY_BASIC_INFORMATION64()
                    handle = self.pymem_process.process_handle if self.pymem_process else self.process_handle

                    result_size = self.VirtualQueryEx(
                        handle,
                        ctypes.c_void_p(current_addr),
                        ctypes.byref(mbi),
                        ctypes.sizeof(mbi)
                    )

                    if result_size == 0:
                        logger.debug(f"VirtualQueryEx failed at {hex(current_addr)}")
                        current_addr += 0x1000
                        continue

                    if self._should_scan_region(mbi):
                        regions_scanned += 1
                        logger.debug(f"Scanning region {regions_scanned}: {hex(mbi.BaseAddress)} size={mbi.RegionSize}")
                        region_results = self._scan_memory_region(mbi, scan_type, value_type, value1, value2)
                        results.extend(region_results)
                        logger.debug(f"Region {regions_scanned} found {len(region_results)} results")

                        if len(results) >= 100000:  # 增加限制到100000
                            break

                    if mbi.RegionSize == 0:
                        break

                    next_addr = mbi.BaseAddress + mbi.RegionSize
                    if next_addr <= current_addr:
                        break
                    current_addr = next_addr

                except Exception as e:
                    logger.debug(f"Error scanning at {hex(current_addr)}: {e}")
                    current_addr += 0x1000
                    continue

            logger.info(f"Manual scan completed: {regions_scanned} regions scanned, {len(results)} results found")

        self.scan_results = results
        self.scan_history.append({
            'scan_type': scan_type,
            'value_type': value_type,
            'value1': value1,
            'value2': value2,
            'results_count': len(results)
        })

        logger.info(f"First scan completed with {len(results)} results")
        return len(results)

    def _pymem_scan_value(self, value: Any, value_type: ValueType) -> List[int]:
        """使用pymem扫描数值"""
        if not self.pymem_process:
            return []

        try:
            if value_type == ValueType.DWORD_4BYTES:
                return list(self.pymem_process.pattern_scan_all(struct.pack('<I', int(value))))
            elif value_type == ValueType.FLOAT:
                return list(self.pymem_process.pattern_scan_all(struct.pack('<f', float(value))))
            elif value_type == ValueType.BYTE:
                return list(self.pymem_process.pattern_scan_all(struct.pack('<B', int(value))))
            elif value_type == ValueType.WORD_2BYTES:
                return list(self.pymem_process.pattern_scan_all(struct.pack('<H', int(value))))
            elif value_type == ValueType.QWORD_8BYTES:
                return list(self.pymem_process.pattern_scan_all(struct.pack('<Q', int(value))))
            elif value_type == ValueType.DOUBLE:
                return list(self.pymem_process.pattern_scan_all(struct.pack('<d', float(value))))
        except Exception as e:
            logger.error(f"Pymem pattern scan failed: {e}")
        return []

    def next_scan(self, scan_type: ScanType, value_type: ValueType, value1: Any = None, value2: Any = None) -> int:
        """再次扫描"""
        if not self.process_handle or not self.scan_results:
            logger.error("No process handle or no previous results")
            return 0

        new_results = []
        logger.info(f"Starting next scan with {len(self.scan_results)} addresses to check")
        logger.info(f"Scan type: {scan_type}, Value type: {value_type}, Value1: {value1}, Value2: {value2}")

        for result in self.scan_results:
            # 读取当前地址的新值
            current_bytes = self.read_memory(result.address, self._get_value_size(value_type))
            if not current_bytes:
                continue

            try:
                # 转换当前值
                current_value = self._bytes_to_value(current_bytes, value_type)
                if current_value is None:
                    continue

                # 保存当前和前一个值用于比较
                prev_value = result.current_value

                # 根据值类型进行适当的类型转换
                try:
                    if value_type in [ValueType.FLOAT, ValueType.DOUBLE]:
                        current_value = float(current_value)
                        if value1 is not None:
                            value1 = float(value1)
                        if value2 is not None:
                            value2 = float(value2)
                        if prev_value is not None:
                            prev_value = float(prev_value)
                    elif value_type in [ValueType.BYTE, ValueType.WORD_2BYTES, ValueType.DWORD_4BYTES, ValueType.QWORD_8BYTES]:
                        current_value = int(current_value)
                        if value1 is not None:
                            value1 = int(value1)
                        if value2 is not None:
                            value2 = int(value2)
                        if prev_value is not None:
                            prev_value = int(prev_value)
                except (ValueError, TypeError) as e:
                    logger.debug(f"Type conversion error at {hex(result.address)}: {e}")
                    continue

                # 检查是否匹配扫描条件
                matched = False
                if scan_type == ScanType.EXACT_VALUE:
                    matched = value1 is not None and current_value == value1
                elif scan_type == ScanType.BIGGER_THAN:
                    matched = value1 is not None and current_value > value1
                elif scan_type == ScanType.SMALLER_THAN:
                    matched = value1 is not None and current_value < value1
                elif scan_type == ScanType.BETWEEN:
                    matched = value1 is not None and value2 is not None and value1 <= current_value <= value2
                elif scan_type == ScanType.INCREASED_VALUE:
                    matched = prev_value is not None and current_value > prev_value
                elif scan_type == ScanType.DECREASED_VALUE:
                    matched = prev_value is not None and current_value < prev_value
                elif scan_type == ScanType.CHANGED_VALUE:
                    matched = prev_value is not None and current_value != prev_value
                elif scan_type == ScanType.UNCHANGED_VALUE:
                    matched = prev_value is not None and current_value == prev_value
                elif scan_type == ScanType.INCREASED_BY:
                    matched = prev_value is not None and value1 is not None and current_value == prev_value + value1
                elif scan_type == ScanType.DECREASED_BY:
                    matched = prev_value is not None and value1 is not None and current_value == prev_value - value1
                elif scan_type == ScanType.UNKNOWN_INITIAL:
                    matched = True

                if matched:
                    new_results.append(ScanResult(result.address, current_value, prev_value))
                    if len(new_results) <= 5:  # 调试输出前5个匹配结果
                        logger.debug(f"Match found at {hex(result.address)}: Previous={prev_value}, Current={current_value}")

            except Exception as e:
                logger.debug(f"Error processing address {hex(result.address)}: {e}")
                continue

        logger.info(f"Next scan completed: Found {len(new_results)} matches")
        # 更新扫描结果
        self.scan_results = new_results
        self.scan_history.append({
            'scan_type': scan_type,
            'value_type': value_type,
            'value1': value1,
            'value2': value2,
            'results_count': len(new_results)
        })

        return len(new_results)

    def undo_scan(self) -> bool:
        """撤销扫描"""
        if len(self.scan_history) <= 1:
            return False

        # 恢复上一次扫描结果
        if self.previous_scan_results:
            self.scan_results = [ScanResult(addr, val) for addr, val in self.previous_scan_results]

        self.scan_history.pop()
        return True

    def _should_scan_region(self, mbi: MEMORY_BASIC_INFORMATION64) -> bool:
        """判断是否应该扫描该内存区域"""
        # 跳过未提交的内存
        if mbi.State != self.MEM_COMMIT:
            logger.debug(f"Skipping region {hex(mbi.BaseAddress)}: not committed (state={mbi.State})")
            return False

        # 跳过保护页
        if mbi.Protect & self.PAGE_GUARD:
            logger.debug(f"Skipping region {hex(mbi.BaseAddress)}: guard page")
            return False

        # 跳过不可读的内存
        base_protect = mbi.Protect & 0xFF
        readable_protects = [
            self.PAGE_READONLY,
            self.PAGE_READWRITE,
            self.PAGE_EXECUTE_READ,
            self.PAGE_EXECUTE_READWRITE,
            self.PAGE_WRITECOPY,
            self.PAGE_EXECUTE_WRITECOPY
        ]

        if base_protect not in readable_protects:
            logger.debug(f"Skipping region {hex(mbi.BaseAddress)}: protection {hex(mbi.Protect)} not readable")
            return False

        # 优先扫描私有内存区域（进程专用）
        if mbi.Type == self.MEM_PRIVATE:
            logger.debug(f"Scanning private region {hex(mbi.BaseAddress)}: protection {hex(mbi.Protect)}")
            return True

        # 也可以扫描映射的内存区域
        if mbi.Type == self.MEM_MAPPED:
            logger.debug(f"Scanning mapped region {hex(mbi.BaseAddress)}: protection {hex(mbi.Protect)}")
            return True

        # 跳过镜像区域（通常是DLL）
        if mbi.Type == self.MEM_IMAGE:
            logger.debug(f"Skipping image region {hex(mbi.BaseAddress)}: protection {hex(mbi.Protect)}")
            return False

        logger.debug(f"Skipping region {hex(mbi.BaseAddress)}: type {hex(mbi.Type)}")
        return False

    def _scan_memory_region(self, mbi: MEMORY_BASIC_INFORMATION64, scan_type: ScanType, value_type: ValueType,
                            value1: Any, value2: Any) -> List[ScanResult]:
        """扫描内存区域"""
        results = []
        try:
            base_address = mbi.BaseAddress
            region_size = mbi.RegionSize
            if base_address is None or region_size == 0:
                return results

            # 确定值大小和类型
            if value_type == ValueType.ALL_TYPES:
                value_types_to_try = [
                    ValueType.BYTE,
                    ValueType.WORD_2BYTES,
                    ValueType.DWORD_4BYTES,
                    ValueType.QWORD_8BYTES,
                    ValueType.FLOAT,
                    ValueType.DOUBLE
                ]
            else:
                value_types_to_try = [value_type]

            # 分块读取内存，每块1MB
            chunk_size = 1024 * 1024
            for chunk_start in range(0, region_size, chunk_size):
                chunk_end = min(chunk_start + chunk_size, region_size)
                data = self.read_memory(base_address + chunk_start, chunk_end - chunk_start)
                if not data:
                    break

                # 尝试每种值类型
                for value_type_to_try in value_types_to_try:
                    value_size = self._get_value_size(value_type_to_try)
                    if value_size == 0:
                        continue

                    # 根据数据类型和fast_scan选项决定步长
                    if self.scan_options.fast_scan:
                        # 使用数据类型的自然对齐
                        step = min(self.scan_options.alignment, value_size)
                        if step < 1:
                            step = 1
                    else:
                        # 不使用快速扫描时，逐字节扫描
                        step = 1

                    # 确保起始地址对齐
                    aligned_start = (base_address + chunk_start + (step - 1)) & ~(step - 1)
                    offset_start = aligned_start - (base_address + chunk_start)

                    # 在当前块中扫描
                    for offset in range(int(offset_start), len(data) - value_size + 1, step):
                        try:
                            address = base_address + chunk_start + offset
                            # 检查地址对齐
                            if address % value_size != 0 and self.scan_options.fast_scan:
                                continue

                            current_value = self._parse_value_from_data(data[offset:offset + value_size], value_type_to_try)
                            if current_value is not None:
                                if self._matches_scan_criteria(current_value, None, scan_type, value1, value2):
                                    results.append(ScanResult(address, current_value))

                                    # 限制结果数量防止内存溢出
                                    if len(results) >= 100000:
                                        return results
                        except Exception as e:
                            logger.debug(f"Error processing value at {hex(base_address + chunk_start + offset)}: {e}")
                            continue

        except Exception as e:
            logger.debug(f"Error scanning region {hex(base_address)}: {e}")

        return results

    def _get_value_size(self, value_type: ValueType) -> int:
        """获取数值类型的字节大小"""
        size_map = {
            ValueType.BINARY: 1,
            ValueType.BYTE: 1,
            ValueType.WORD_2BYTES: 2,
            ValueType.DWORD_4BYTES: 4,
            ValueType.QWORD_8BYTES: 8,
            ValueType.FLOAT: 4,
            ValueType.DOUBLE: 8,
            ValueType.ALL_TYPES: 4  # 默认使用4字节
        }
        return size_map.get(value_type, 4)

    def _parse_value_from_data(self, data: bytes, value_type: ValueType) -> Any:
        """从字节数据解析数值"""
        try:
            if len(data) < self._get_value_size(value_type):
                return None

            if value_type == ValueType.BYTE:
                return struct.unpack('<B', data[:1])[0]
            elif value_type == ValueType.WORD_2BYTES:
                return struct.unpack('<H', data[:2])[0]
            elif value_type == ValueType.DWORD_4BYTES:
                return struct.unpack('<I', data[:4])[0]
            elif value_type == ValueType.QWORD_8BYTES:
                return struct.unpack('<Q', data[:8])[0]
            elif value_type == ValueType.FLOAT:
                return struct.unpack('<f', data[:4])[0]
            elif value_type == ValueType.DOUBLE:
                return struct.unpack('<d', data[:8])[0]
            elif value_type == ValueType.STRING:
                # 只返回可打印字符
                text = data.decode('utf-8', errors='ignore').rstrip('\x00')
                return text if text and text.isprintable() else None
        except (struct.error, UnicodeDecodeError):
            return None
        return None

    def _read_value_at_address(self, address: int, value_type: ValueType) -> Any:
        """读取指定地址的数值"""
        size = self._get_value_size(value_type)
        data = self.read_memory(address, size)
        if data:
            return self._parse_value_from_data(data, value_type)
        return None

    def _matches_scan_criteria(self, current_value: Any, previous_value: Any, scan_type: ScanType, value1: Any,
                               value2: Any) -> bool:
        """检查是否匹配扫描条件"""
        try:
            # 检查当前值是否有效
            if current_value is None:
                return False

            if scan_type == ScanType.EXACT_VALUE:
                return value1 is not None and current_value == value1
            elif scan_type == ScanType.BIGGER_THAN:
                return value1 is not None and current_value > value1
            elif scan_type == ScanType.SMALLER_THAN:
                return value1 is not None and current_value < value1
            elif scan_type == ScanType.BETWEEN:
                return value1 is not None and value2 is not None and value1 <= current_value <= value2
            elif scan_type == ScanType.INCREASED_VALUE:
                return previous_value is not None and current_value > previous_value
            elif scan_type == ScanType.INCREASED_BY:
                return previous_value is not None and value1 is not None and current_value == previous_value + value1
            elif scan_type == ScanType.DECREASED_VALUE:
                return previous_value is not None and current_value < previous_value
            elif scan_type == ScanType.DECREASED_BY:
                return previous_value is not None and value1 is not None and current_value == previous_value - value1
            elif scan_type == ScanType.CHANGED_VALUE:
                return previous_value is not None and current_value != previous_value
            elif scan_type == ScanType.UNCHANGED_VALUE:
                return previous_value is not None and current_value == previous_value
            elif scan_type == ScanType.UNKNOWN_INITIAL:
                return True  # 对于未知初始值，总是返回True
        except (TypeError, ValueError):
            return False
        return False

    def get_scan_results(self, start_index: int = 0, count: int = 100) -> List[Dict]:
        """获取扫描结果"""
        results = []
        end_index = min(start_index + count, len(self.scan_results))

        for i in range(start_index, end_index):
            result = self.scan_results[i]
            # Convert bytes to hex strings for JSON serialization
            current_value = result.current_value.hex() if isinstance(result.current_value,
                                                                     bytes) else result.current_value
            previous_value = result.previous_value.hex() if isinstance(result.previous_value,
                                                                       bytes) else result.previous_value
            results.append({
                'address': hex(result.address),
                'current_value': current_value,
                'previous_value': previous_value,
                'frozen': result.frozen
            })

        return results

    def get_scan_count(self) -> int:
        """获取扫描结果数量"""
        return len(self.scan_results)

    def update_scan_results(self, value_type: ValueType) -> int:
        """更新扫描结果的当前值，保存当前值作为前一个值"""
        if not self.scan_results:
            return 0

        updated_count = 0
        for result in self.scan_results:
            new_value = self._read_value_at_address(result.address, value_type)
            if new_value is not None:
                # 保存当前值为前一个值，更新当前值
                result.previous_value = result.current_value
                result.current_value = new_value
                updated_count += 1

        # 记录日志
        if updated_count > 0:
            logger.debug(f"Updated {updated_count} values")

            # 取样输出一些值的变化
            sample_size = min(5, len(self.scan_results))
            for i in range(sample_size):
                result = self.scan_results[i]
                logger.debug(f"Sample {i + 1}: Address={hex(result.address)}, Previous={result.previous_value}, Current={result.current_value}")

        return updated_count

    def set_scan_options(self, options: Dict) -> bool:
        """设置扫描选项"""
        try:
            if 'start_address' in options:
                self.scan_options.start_address = int(options['start_address'], 16)
            if 'stop_address' in options:
                self.scan_options.stop_address = int(options['stop_address'], 16)
            if 'readable' in options:
                self.scan_options.readable = options['readable']
            if 'writable' in options:
                self.scan_options.writable = options['writable']
            if 'executable' in options:
                self.scan_options.executable = options['executable']
            if 'copy_on_write' in options:
                self.scan_options.copy_on_write = options['copy_on_write']
            if 'fast_scan' in options:
                self.scan_options.fast_scan = options['fast_scan']
            if 'alignment' in options:
                self.scan_options.alignment = max(1, int(options['alignment']))
            if 'last_digits' in options:
                self.scan_options.last_digits = max(0, int(options['last_digits']))
            return True
        except Exception as e:
            logger.error(f"Set scan options failed: {e}")
            return False

    def get_module_base(self, module_name: str) -> Optional[int]:
        """获取模块基址"""
        if not self.current_pid:
            return None

        try:
            process = psutil.Process(self.current_pid)
            for module in process.memory_maps():
                if module_name.lower() in module.path.lower():
                    return int(module.addr.split('-')[0], 16)
        except Exception as e:
            logger.error(f"Get module base failed: {e}")
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

