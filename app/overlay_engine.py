import ctypes
import ctypes.wintypes
import threading
import time
from typing import Tuple, List

class WindowOverlay:
    def __init__(self):
        self.running = False
        self.overlay_thread = None
        self.target_hwnd = None
        self.rectangles = []
        
        # Windows API
        self.user32 = ctypes.windll.user32
        self.gdi32 = ctypes.windll.gdi32
        self.kernel32 = ctypes.windll.kernel32
        
    def find_window_by_pid(self, pid: int) -> int:
        """通过PID查找窗口句柄"""
        def enum_windows_proc(hwnd, lParam):
            if self.user32.IsWindowVisible(hwnd):
                _, found_pid = ctypes.wintypes.DWORD(), ctypes.wintypes.DWORD()
                self.user32.GetWindowThreadProcessId(hwnd, ctypes.byref(found_pid))
                if found_pid.value == pid:
                    self.target_hwnd = hwnd
                    return False
            return True
        
        enum_proc = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.wintypes.HWND, ctypes.wintypes.LPARAM)(enum_windows_proc)
        self.user32.EnumWindows(enum_proc, 0)
        return self.target_hwnd
    
    def start_overlay(self, pid: int):
        """启动覆盖层"""
        if self.running:
            return False
            
        hwnd = self.find_window_by_pid(pid)
        if not hwnd:
            return False
            
        self.target_hwnd = hwnd
        self.running = True
        
        # 检查是否为全屏应用
        if self._is_fullscreen():
            print(f"Detected fullscreen application, using desktop overlay mode")
        else:
            print(f"Using window overlay mode")
            
        self.overlay_thread = threading.Thread(target=self._overlay_loop, daemon=True)
        self.overlay_thread.start()
        return True
    
    def stop_overlay(self):
        """停止覆盖层"""
        self.running = False
        if self.overlay_thread:
            self.overlay_thread.join()
    
    def add_rectangle(self, x: int, y: int, width: int, height: int, color: Tuple[int, int, int] = (255, 0, 0)):
        """添加矩形"""
        self.rectangles.append({
            'x': x, 'y': y, 'width': width, 'height': height, 'color': color
        })
    
    def clear_rectangles(self):
        """清除所有矩形"""
        self.rectangles.clear()
        # 强制刷新窗口或屏幕
        if self.target_hwnd and self.user32.IsWindow(self.target_hwnd):
            if self._is_fullscreen():
                # 全屏模式：刷新整个屏幕
                self.user32.InvalidateRect(0, None, True)
            else:
                # 窗口模式：刷新窗口
                self.user32.InvalidateRect(self.target_hwnd, None, True)
                self.user32.UpdateWindow(self.target_hwnd)
    
    def _overlay_loop(self):
        """覆盖层主循环"""
        while self.running and self.target_hwnd:
            try:
                # 检查窗口是否仍然存在
                if not self.user32.IsWindow(self.target_hwnd):
                    break
                
                # 检查是否为全屏模式
                if self._is_fullscreen():
                    # 全屏模式：使用桌面DC
                    hdc = self.user32.GetDC(0)  # 获取桌面DC
                else:
                    # 窗口模式：使用窗口DC
                    hdc = self.user32.GetWindowDC(self.target_hwnd)
                
                if not hdc:
                    time.sleep(0.1)
                    continue
                
                # 绘制所有矩形
                for rect in self.rectangles:
                    self._draw_rectangle_with_offset(hdc, rect)
                
                # 释放DC
                if self._is_fullscreen():
                    self.user32.ReleaseDC(0, hdc)
                else:
                    self.user32.ReleaseDC(self.target_hwnd, hdc)
                
                time.sleep(0.033)  # ~30 FPS
                
            except Exception as e:
                time.sleep(0.1)
    
    def _is_fullscreen(self) -> bool:
        """检查窗口是否为全屏模式"""
        try:
            # 获取窗口矩形
            rect = ctypes.wintypes.RECT()
            self.user32.GetWindowRect(self.target_hwnd, ctypes.byref(rect))
            
            # 获取屏幕尺寸
            screen_width = self.user32.GetSystemMetrics(0)  # SM_CXSCREEN
            screen_height = self.user32.GetSystemMetrics(1)  # SM_CYSCREEN
            
            # 判断是否全屏
            window_width = rect.right - rect.left
            window_height = rect.bottom - rect.top
            
            return (window_width >= screen_width and window_height >= screen_height and 
                    rect.left <= 0 and rect.top <= 0)
        except Exception:
            return False
    
    def _get_window_screen_pos(self) -> tuple:
        """获取窗口在屏幕上的位置"""
        try:
            rect = ctypes.wintypes.RECT()
            self.user32.GetWindowRect(self.target_hwnd, ctypes.byref(rect))
            return rect.left, rect.top
        except Exception:
            return 0, 0
    
    def _draw_rectangle_with_offset(self, hdc, rect):
        """绘制矩形（考虑全屏偏移）"""
        try:
            # 创建画笔
            color = rect['color']
            rgb_color = (color[2] << 16) | (color[1] << 8) | color[0]  # BGR格式
            pen = self.gdi32.CreatePen(0, 3, rgb_color)  # PS_SOLID, width=3
            if not pen:
                return
                
            old_pen = self.gdi32.SelectObject(hdc, pen)
            
            # 设置透明背景
            self.gdi32.SetBkMode(hdc, 1)  # TRANSPARENT
            
            # 创建透明画刷
            brush = self.gdi32.GetStockObject(5)  # NULL_BRUSH
            old_brush = self.gdi32.SelectObject(hdc, brush)
            
            # 计算绘制坐标
            if self._is_fullscreen():
                # 全屏模式：直接使用屏幕坐标
                x = rect['x']
                y = rect['y']
            else:
                # 窗口模式：使用窗口内坐标
                window_x, window_y = self._get_window_screen_pos()
                x = window_x + rect['x']
                y = window_y + rect['y']
            
            # 绘制矩形边框
            self.gdi32.Rectangle(hdc, x, y, x + rect['width'], y + rect['height'])
            
            # 恢复原对象
            self.gdi32.SelectObject(hdc, old_pen)
            self.gdi32.SelectObject(hdc, old_brush)
            self.gdi32.DeleteObject(pen)
            
        except Exception as e:
            pass
    


class OverlayRenderer:
    def __init__(self):
        self.overlay = WindowOverlay()
        
    def start_rendering(self, pid: int) -> bool:
        """开始渲染"""
        return self.overlay.start_overlay(pid)
    
    def stop_rendering(self):
        """停止渲染"""
        self.overlay.stop_rendering()
    
    def draw_box(self, x: int, y: int, width: int, height: int, color: str = "red"):
        """绘制方框"""
        color_map = {
            "red": (255, 0, 0),
            "green": (0, 255, 0),
            "blue": (0, 0, 255),
            "yellow": (255, 255, 0),
            "white": (255, 255, 255)
        }
        rgb_color = color_map.get(color, (255, 0, 0))
        self.overlay.add_rectangle(x, y, width, height, rgb_color)
    
    def clear_all(self):
        """清除所有绘制"""
        self.overlay.clear_rectangles()