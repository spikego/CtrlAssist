import ctypes
import logging
from ctypes import wintypes, windll, byref, c_size_t
import threading
import time

logger = logging.getLogger(__name__)

# 定义要 hook 的时间函数
TIME_FUNCS = [
    "timeGetTime",
    "GetTickCount",
    "GetTickCount64",
    "QueryPerformanceCounter"
]

class TimeHook:
    def __init__(self):
        self.speed_multiplier = 1.0
        self.start_time = time.perf_counter()
        self.base_time = time.perf_counter()
        self.is_active = False
        self._lock = threading.Lock()
        self._original_funcs = {}
        self._hooked_processes = set()

        # 加载必要的 DLL
        self.kernel32 = windll.kernel32
        self.winmm = windll.winmm

        # 保存原始函数
        self._save_original_funcs()

    def _save_original_funcs(self):
        """保存原始时间函数的地址"""
        try:
            # timeGetTime
            self._original_funcs["timeGetTime"] = self.winmm.timeGetTime

            # GetTickCount
            self._original_funcs["GetTickCount"] = self.kernel32.GetTickCount

            # GetTickCount64
            self._original_funcs["GetTickCount64"] = self.kernel32.GetTickCount64

            # QueryPerformanceCounter
            self._original_funcs["QueryPerformanceCounter"] = self.kernel32.QueryPerformanceCounter

        except Exception as e:
            logger.error(f"Failed to save original functions: {e}")

    def _get_modified_time(self, original_time: int) -> int:
        """根据速度倍率修改时间"""
        with self._lock:
            current_time = time.perf_counter()
            elapsed = current_time - self.start_time
            modified_elapsed = elapsed * self.speed_multiplier
            return int(original_time + modified_elapsed * 1000)  # 转换为毫秒

    def _get_modified_qpc(self, original_qpc: int) -> int:
        """修改 QPC 计数器值"""
        with self._lock:
            current_time = time.perf_counter()
            elapsed = current_time - self.start_time
            modified_elapsed = elapsed * self.speed_multiplier
            # QPC 频率通常是 10MHz
            return int(original_qpc + modified_elapsed * 10000000)

    def hook_time_functions(self):
        """Hook 系统时间函数"""
        if self.is_active:
            return

        try:
            # Hook timeGetTime
            def new_time_get_time():
                original = self._original_funcs["timeGetTime"]()
                return self._get_modified_time(original)

            # Hook GetTickCount
            def new_get_tick_count():
                original = self._original_funcs["GetTickCount"]()
                return self._get_modified_time(original)

            # Hook GetTickCount64
            def new_get_tick_count64():
                original = self._original_funcs["GetTickCount64"]()
                return self._get_modified_time(original)

            # Hook QueryPerformanceCounter
            def new_query_performance_counter(lpPerformanceCount):
                original_count = ctypes.c_longlong()
                self._original_funcs["QueryPerformanceCounter"](byref(original_count))
                modified_count = self._get_modified_qpc(original_count.value)
                ctypes.memmove(lpPerformanceCount, byref(ctypes.c_longlong(modified_count)), 8)
                return True

            # 应用 hook
            self.winmm.timeGetTime = new_time_get_time
            self.kernel32.GetTickCount = new_get_tick_count
            self.kernel32.GetTickCount64 = new_get_tick_count64
            self.kernel32.QueryPerformanceCounter = new_query_performance_counter

            self.is_active = True
            logger.info("Time functions hooked successfully")

        except Exception as e:
            logger.error(f"Failed to hook time functions: {e}")
            self.unhook_time_functions()

    def unhook_time_functions(self):
        """恢复原始时间函数"""
        try:
            # 恢复所有原始函数
            for func_name, original_func in self._original_funcs.items():
                if func_name == "timeGetTime":
                    self.winmm.timeGetTime = original_func
                else:
                    setattr(self.kernel32, func_name, original_func)

            self.is_active = False
            self._hooked_processes.clear()
            logger.info("Time functions restored")

        except Exception as e:
            logger.error(f"Failed to restore time functions: {e}")

    def set_speed(self, multiplier: float):
        """设置速度倍率"""
        with self._lock:
            # 保存当前时间作为新的基准点
            current_time = time.perf_counter()
            self.base_time = current_time
            self.speed_multiplier = max(0.1, min(10.0, multiplier))  # 限制在 0.1-10 倍范围内
            logger.info(f"Speed multiplier set to {self.speed_multiplier}x")

    def get_speed(self) -> float:
        """获取当前速度倍率"""
        return self.speed_multiplier

    def add_process(self, pid: int):
        """添加要影响的进程"""
        self._hooked_processes.add(pid)

    def remove_process(self, pid: int):
        """移除受影响的进程"""
        self._hooked_processes.discard(pid)

    def is_process_affected(self, pid: int) -> bool:
        """检查进程是否受影响"""
        return pid in self._hooked_processes
