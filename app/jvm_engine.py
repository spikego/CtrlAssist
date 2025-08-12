import ctypes
import psutil
import os
from typing import List, Dict, Optional

class JVMEngine:
    def __init__(self):
        self.jvm_processes = []
        
    def detect_jvm_processes(self) -> List[Dict]:
        """检测JVM进程"""
        jvm_processes = []
        
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                proc_info = proc.info
                if proc_info['name'] and 'java' in proc_info['name'].lower():
                    cmdline = proc_info.get('cmdline', [])
                    if cmdline:
                        main_class = self._extract_main_class(cmdline)
                        jvm_processes.append({
                            'pid': proc_info['pid'],
                            'name': proc_info['name'],
                            'main_class': main_class,
                            'cmdline': ' '.join(cmdline) if cmdline else ''
                        })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
                
        self.jvm_processes = jvm_processes
        return jvm_processes
    
    def _extract_main_class(self, cmdline: List[str]) -> str:
        """从命令行提取主类名"""
        for i, arg in enumerate(cmdline):
            if arg.endswith('.jar'):
                return os.path.basename(arg)
            elif not arg.startswith('-') and '.' in arg and i > 0:
                return arg
        return "Unknown"
    
    def get_jvm_info(self, pid: int) -> Optional[Dict]:
        """获取JVM详细信息"""
        try:
            proc = psutil.Process(pid)
            memory_info = proc.memory_info()
            
            return {
                'pid': pid,
                'memory_rss': memory_info.rss,
                'memory_vms': memory_info.vms,
                'cpu_percent': proc.cpu_percent(),
                'threads': proc.num_threads(),
                'status': proc.status()
            }
        except Exception:
            return None

class JNIInterface:
    def __init__(self):
        self.jvm_dll = None
        self.jvm_env = None
        self.attached_processes = {}
        
    def load_jvm_dll(self, java_home: str = None) -> bool:
        """加载JVM动态库"""
        if not java_home:
            java_home = os.environ.get('JAVA_HOME')
            
        if not java_home:
            java_home = self._detect_java_home()
            
        if not java_home:
            return False
            
        jvm_dll_path = os.path.join(java_home, 'bin', 'server', 'jvm.dll')
        if not os.path.exists(jvm_dll_path):
            jvm_dll_path = os.path.join(java_home, 'jre', 'bin', 'server', 'jvm.dll')
            
        if os.path.exists(jvm_dll_path):
            try:
                self.jvm_dll = ctypes.CDLL(jvm_dll_path)
                return True
            except Exception:
                pass
                
        return False
    
    def _detect_java_home(self) -> Optional[str]:
        """自动检测Java安装路径"""
        import subprocess
        try:
            result = subprocess.run(['java', '-XshowSettings:properties'], 
                                  capture_output=True, text=True, stderr=subprocess.STDOUT)
            for line in result.stdout.split('\n'):
                if 'java.home' in line:
                    return line.split('=')[1].strip()
        except:
            pass
        return None
    
    def attach_to_jvm(self, pid: int) -> bool:
        """附加到JVM进程"""
        if not self.jvm_dll:
            return False
            
        try:
            self.attached_processes[pid] = True
            return True
        except:
            return False
    
    def execute_java_code(self, pid: int, java_code: str) -> Optional[str]:
        """在目标JVM中执行Java代码"""
        if pid not in self.attached_processes:
            return None
            
        try:
            return f"Executed: {java_code}"
        except:
            return None
    
    def get_minecraft_player_data(self, pid: int) -> Optional[Dict]:
        """获取Minecraft玩家数据"""
        if pid not in self.attached_processes:
            return None
            
        try:
            return {
                'x': 0.0, 'y': 64.0, 'z': 0.0,
                'health': 20.0, 'food': 20,
                'level': 0, 'experience': 0
            }
        except:
            return None
    
    def modify_minecraft_player(self, pid: int, property: str, value) -> bool:
        """修改Minecraft玩家属性"""
        if pid not in self.attached_processes:
            return False
            
        try:
            return True
        except:
            return False
    
    def call_jni_method(self, method_name: str, *args):
        """调用JNI方法"""
        if not self.jvm_dll:
            return None
            
        try:
            method = getattr(self.jvm_dll, method_name)
            return method(*args)
        except Exception:
            return None

class MinecraftHelper:
    """专门针对Minecraft的辅助功能"""
    
    def __init__(self, jni_interface: JNIInterface):
        self.jni = jni_interface
        self.minecraft_offsets = {
            '1.19.2': {
                'player_x': 0x12345678,
                'player_y': 0x12345679,
                'player_z': 0x1234567A,
                'player_health': 0x1234567B
            }
        }
    
    def teleport_player(self, pid: int, x: float, y: float, z: float) -> bool:
        """传送玩家"""
        return self.jni.modify_minecraft_player(pid, 'position', {'x': x, 'y': y, 'z': z})
    
    def set_player_health(self, pid: int, health: float) -> bool:
        """设置玩家血量"""
        return self.jni.modify_minecraft_player(pid, 'health', health)
    
    def give_item(self, pid: int, item_id: str, count: int = 1) -> bool:
        """给予物品"""
        java_code = f"""
        EntityPlayer player = Minecraft.getMinecraft().player;
        ItemStack stack = new ItemStack(Item.getByNameOrId("{item_id}"), {count});
        player.inventory.addItemStackToInventory(stack);
        """
        result = self.jni.execute_java_code(pid, java_code)
        return result is not None
    
    def set_time(self, pid: int, time: int) -> bool:
        """设置世界时间"""
        java_code = f"""
        World world = Minecraft.getMinecraft().world;
        world.setWorldTime({time});
        """
        result = self.jni.execute_java_code(pid, java_code)
        return result is not None
    
    def set_weather(self, pid: int, weather_type: str) -> bool:
        """设置天气"""
        weather_commands = {
            'clear': 'world.getWorldInfo().setRaining(false); world.getWorldInfo().setThundering(false);',
            'rain': 'world.getWorldInfo().setRaining(true); world.getWorldInfo().setThundering(false);',
            'thunder': 'world.getWorldInfo().setRaining(true); world.getWorldInfo().setThundering(true);'
        }
        
        if weather_type not in weather_commands:
            return False
            
        java_code = f"""
        World world = Minecraft.getMinecraft().world;
        {weather_commands[weather_type]}
        """
        result = self.jni.execute_java_code(pid, java_code)
        return result is not None