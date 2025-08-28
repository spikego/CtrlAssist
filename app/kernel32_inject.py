import ctypes
import os
import logging
import hashlib
import struct
from ctypes import wintypes, windll, c_void_p, create_string_buffer, sizeof, byref, c_size_t

logger = logging.getLogger(__name__)

# 定义Windows API常量
PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40

class InjectionError(Exception):
    pass

class Kernel32Hook:
    def __init__(self):
        self.hooked_processes = {}
        self.dll_path = os.path.join(os.path.dirname(__file__), 'static', 'dll', 'libSpeedHook.dll')
        self._original_dll_hash = None
        self._verify_dll()

    def _verify_dll(self):
        """验证DLL文件的完整性"""
        try:
            if not os.path.exists(self.dll_path):
                raise InjectionError(f"DLL not found: {self.dll_path}")

            with open(self.dll_path, 'rb') as f:
                dll_hash = hashlib.sha256(f.read()).hexdigest()

            if not self._original_dll_hash:
                self._original_dll_hash = dll_hash
            elif dll_hash != self._original_dll_hash:
                raise InjectionError("DLL file has been modified")

        except Exception as e:
            logger.error(f"DLL verification failed: {e}")
            raise

    def _check_admin_rights(self):
        """检查是否有管理员权限"""
        try:
            return windll.shell32.IsUserAnAdmin()
        except Exception:
            return False

    def _is_process_64bit(self, process_handle):
        """检查目标进程是否是64位"""
        if hasattr(windll.kernel32, 'IsWow64Process'):
            is_wow64 = wintypes.BOOL()
            if windll.kernel32.IsWow64Process(process_handle, byref(is_wow64)):
                return not bool(is_wow64.value)
        return True

    def _inject_dll_native(self, pid: int) -> bool:
        """使用原生方式注入DLL"""
        try:
            # 打开目标进程
            process_handle = windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
            if not process_handle:
                raise InjectionError(f"Failed to open process {pid}")

            try:
                # 检查进程位数匹配
                if not self._is_process_64bit(process_handle):
                    raise InjectionError("Target process is not 64-bit")

                # 在目标进程中分配内存
                dll_path_bytes = (self.dll_path + '\0').encode('utf-16le')
                address = windll.kernel32.VirtualAllocEx(
                    process_handle, None,
                    len(dll_path_bytes),
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_READWRITE
                )

                if not address:
                    raise InjectionError("Failed to allocate memory in target process")

                # 写入DLL路径
                written = c_size_t()
                if not windll.kernel32.WriteProcessMemory(
                    process_handle, address, dll_path_bytes,
                    len(dll_path_bytes), byref(written)
                ):
                    raise InjectionError("Failed to write to process memory")

                # 获取LoadLibraryW地址
                kernel32_handle = windll.kernel32.GetModuleHandleW("kernel32.dll")
                loadlibrary_addr = windll.kernel32.GetProcAddress(
                    kernel32_handle, b"LoadLibraryW"
                )

                # 创建远程线程
                thread_handle = windll.kernel32.CreateRemoteThread(
                    process_handle, None, 0,
                    loadlibrary_addr, address, 0, None
                )

                if not thread_handle:
                    raise InjectionError("Failed to create remote thread")

                # 等待注入完成
                windll.kernel32.WaitForSingleObject(thread_handle, 5000)

                # 检查注入结果
                exit_code = wintypes.DWORD()
                windll.kernel32.GetExitCodeThread(thread_handle, byref(exit_code))
                if exit_code.value == 0:
                    raise InjectionError("DLL injection failed")

                # 获取注入的DLL句柄
                injected_handle = exit_code.value

                # 释放资源
                windll.kernel32.CloseHandle(thread_handle)
                windll.kernel32.VirtualFreeEx(process_handle, address, 0, 0x8000)  # MEM_RELEASE

                return True

            finally:
                windll.kernel32.CloseHandle(process_handle)

        except Exception as e:
            logger.error(f"Native injection failed: {e}")
            return False

    def _set_speed_multiplier(self, pid: int, speed: float) -> bool:
        """设置游戏速度"""
        try:
            process_handle = windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
            if not process_handle:
                return False

            try:
                # 在共享内存中查找速度控制变量
                modules = self._enum_process_modules(process_handle)
                for base_addr in modules:
                    # 查找特定的内存标记
                    pattern = struct.pack('f', 1.0)  # 默认速度标记
                    found = self._pattern_scan(process_handle, base_addr, pattern)
                    if found:
                        # 写入新的速度值
                        speed_bytes = struct.pack('f', speed)
                        written = c_size_t()
                        if windll.kernel32.WriteProcessMemory(
                            process_handle, found, speed_bytes,
                            len(speed_bytes), byref(written)
                        ):
                            return True
            finally:
                windll.kernel32.CloseHandle(process_handle)

            return False

        except Exception as e:
            logger.error(f"Failed to set speed multiplier: {e}")
            return False

    def _enum_process_modules(self, process_handle):
        """枚举进程模块"""
        modules = []
        try:
            # 使用 EnumProcessModules 获取所有模块
            needed = wintypes.DWORD()
            module_handles = (wintypes.HMODULE * 1024)()

            if windll.psapi.EnumProcessModules(
                process_handle,
                byref(module_handles),
                sizeof(module_handles),
                byref(needed)
            ):
                for i in range(needed.value // sizeof(wintypes.HMODULE)):
                    modules.append(module_handles[i])

        except Exception as e:
            logger.debug(f"Failed to enumerate modules: {e}")

        return modules

    def _pattern_scan(self, process_handle, base_address, pattern: bytes):
        """在内存中搜索特定模式"""
        try:
            # 读取模块信息
            mi = wintypes.MODULEINFO()
            if not windll.psapi.GetModuleInformation(
                process_handle, base_address,
                byref(mi), sizeof(mi)
            ):
                return None

            # 读取模块内存
            buffer = create_string_buffer(mi.SizeOfImage)
            read = c_size_t()
            if not windll.kernel32.ReadProcessMemory(
                process_handle, base_address,
                buffer, mi.SizeOfImage,
                byref(read)
            ):
                return None

            # 搜索模式
            data = buffer.raw
            pattern_len = len(pattern)
            for i in range(len(data) - pattern_len):
                if data[i:i+pattern_len] == pattern:
                    return base_address + i

            return None

        except Exception as e:
            logger.debug(f"Pattern scan failed: {e}")
            return None

    def inject_hook(self, pid: int, speed_multiplier: float) -> bool:
        """注入DLL并设置速度"""
        try:
            if not self._check_admin_rights():
                raise InjectionError("Administrator rights required")

            self._verify_dll()

            # 先注入DLL
            if not self._inject_dll_native(pid):
                raise InjectionError("DLL injection failed")

            # 设置速度
            if not self._set_speed_multiplier(pid, speed_multiplier):
                logger.warning("Failed to set initial speed multiplier")

            # 记录注入状态
            self.hooked_processes[pid] = {
                'speed': speed_multiplier,
                'injected': True
            }

            logger.info(f"Successfully hooked process {pid} with speed {speed_multiplier}")
            return True

        except Exception as e:
            logger.error(f"Hook injection failed: {e}")
            return False

    def remove_hook(self, pid: int) -> bool:
        """移除注入的DLL"""
        try:
            if pid not in self.hooked_processes:
                return True

            # 恢复原始速度
            if not self._set_speed_multiplier(pid, 1.0):
                logger.warning("Failed to reset speed multiplier")

            # 尝试卸载DLL（通过注入FreeLibrary）
            process_handle = windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
            if process_handle:
                try:
                    # 获取 FreeLibrary 函数地址
                    kernel32_handle = windll.kernel32.GetModuleHandleW("kernel32.dll")
                    freelibrary_addr = windll.kernel32.GetProcAddress(
                        kernel32_handle, b"FreeLibrary"
                    )

                    # 创建远程线程执行 FreeLibrary
                    if self.hooked_processes[pid].get('injected'):
                        thread_handle = windll.kernel32.CreateRemoteThread(
                            process_handle, None, 0,
                            freelibrary_addr,
                            self.hooked_processes[pid].get('module_handle', 0),
                            0, None
                        )

                        if thread_handle:
                            windll.kernel32.WaitForSingleObject(thread_handle, 5000)
                            windll.kernel32.CloseHandle(thread_handle)

                finally:
                    windll.kernel32.CloseHandle(process_handle)

            # 清理状态
            del self.hooked_processes[pid]
            logger.info(f"Successfully removed hook from process {pid}")
            return True

        except Exception as e:
            logger.error(f"Failed to remove hook: {e}")
            return False

    def is_process_hooked(self, pid: int) -> bool:
        """检查进程是否已被注入"""
        return pid in self.hooked_processes and self.hooked_processes[pid].get('injected', False)

    def get_process_speed(self, pid: int) -> float:
        """获取进程当前的速度倍率"""
        if pid in self.hooked_processes:
            return self.hooked_processes[pid].get('speed', 1.0)
        return 1.0
