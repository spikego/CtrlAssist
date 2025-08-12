import os
import logging
from flask import Blueprint, render_template, request, jsonify
import psutil
import ctypes
import struct
import subprocess
from werkzeug.utils import secure_filename
from .memory_engine import MemoryEngine, GameSpeedController
from .jvm_engine import JVMEngine, JNIInterface, MinecraftHelper
from .overlay_engine import OverlayRenderer
from .network_engine import NetworkEngine

logger = logging.getLogger(__name__)
main = Blueprint('main', __name__)

# 全局引擎实例
memory_engine = MemoryEngine()
speed_controller = GameSpeedController()
jvm_engine = JVMEngine()
jni_interface = JNIInterface()
minecraft_helper = MinecraftHelper(jni_interface)
overlay_renderer = OverlayRenderer()
network_engine = NetworkEngine()

@main.route('/')
def index():
    processes = []
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            processes.append(proc.info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return render_template('index.html', processes=processes)

@main.route('/refresh_processes')
def refresh_processes():
    processes = []
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            processes.append(proc.info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return jsonify({'processes': processes})

@main.route('/process/<int:pid>')
def process(pid):
    try:
        process = psutil.Process(pid)
        threads = []
        for thread in process.threads():
            threads.append({
                'id': thread.id,
                'user_time': thread.user_time,
                'system_time': thread.system_time
            })
        
        # Get system stats
        cpu_usage = process.cpu_percent(interval=0.1)
        memory_usage = process.memory_percent()
        
        # Get disk usage for C: drive on Windows
        try:
            disk_usage = psutil.disk_usage('C:\\').percent
        except:
            disk_usage = 0
            
        gpu_usage = 0  # GPU usage requires additional libraries
        
        return jsonify({
            'threads': threads,
            'memory_info': {},
            'cpu_usage': round(cpu_usage, 1),
            'memory_usage': round(memory_usage, 1),
            'disk_usage': round(disk_usage, 1),
            'gpu_usage': gpu_usage,
            'name': process.name(),
            'pid': process.pid
        })
    except psutil.NoSuchProcess:
        return jsonify({'error': 'Process not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@main.route('/attach_process', methods=['POST'])
def attach_process():
    data = request.json
    pid = data.get('pid')
    
    if memory_engine.attach_process(pid):
        return jsonify({'status': 'success', 'message': f'Attached to process {pid}'})
    else:
        return jsonify({'status': 'error', 'message': 'Failed to attach to process'}), 400

@main.route('/scan_memory', methods=['POST'])
def scan_memory():
    data = request.json
    value_type = data['valueType']
    scan_value = data['scanValue']
    
    try:
        # 根据类型转换值
        if value_type in ['int32', 'int64']:
            scan_value = int(scan_value)
        elif value_type in ['float', 'double']:
            scan_value = float(scan_value)
        # string 保持原样
        
        results = memory_engine.scan_memory_value(scan_value, value_type)
        
        # 格式化结果
        formatted_results = [{
            'address': hex(addr),
            'value': scan_value,
            'type': value_type
        } for addr in results[:100]]  # 限制结果数量
        
        logger.info(f"Found {len(results)} results for {scan_value} ({value_type})")
        return jsonify({'results': formatted_results, 'total': len(results)})
        
    except Exception as e:
        logger.error(f"Memory scan error: {str(e)}")
        return jsonify({'error': str(e)}), 400

@main.route('/rescan_memory', methods=['POST'])
def rescan_memory():
    data = request.json
    value_type = data['valueType']
    scan_value = data['scanValue']
    addresses = data['addresses']
    
    try:
        # 根据类型转换值
        if value_type in ['int32', 'int64']:
            scan_value = int(scan_value)
        elif value_type in ['float', 'double']:
            scan_value = float(scan_value)
        # string 保持原样
        
        results = memory_engine.rescan_memory_addresses(addresses, scan_value, value_type)
        
        # 格式化结果
        formatted_results = [{
            'address': hex(addr),
            'value': scan_value,
            'type': value_type
        } for addr in results]
        
        logger.info(f"Rescan found {len(results)} matching results")
        return jsonify({'results': formatted_results, 'total': len(results)})
        
    except Exception as e:
        logger.error(f"Memory rescan error: {str(e)}")
        return jsonify({'error': str(e)}), 400
@main.route('/modify_memory', methods=['POST'])
def modify_memory():
    data = request.json
    address = int(data['address'], 16)
    value = data['value']
    value_type = data.get('valueType', 'int32')
    
    try:
        # 根据类型准备数据
        if value_type == 'int32':
            data_bytes = struct.pack('i', int(value))
        elif value_type == 'int64':
            data_bytes = struct.pack('q', int(value))
        elif value_type == 'float':
            data_bytes = struct.pack('f', float(value))
        elif value_type == 'double':
            data_bytes = struct.pack('d', float(value))
        elif value_type == 'string':
            data_bytes = str(value).encode('utf-8')
        else:
            return jsonify({'error': 'Unsupported value type'}), 400
        
        if memory_engine.write_memory(address, data_bytes):
            return jsonify({'status': 'success'})
        else:
            return jsonify({'error': 'Failed to write memory'}), 400
            
    except Exception as e:
        logger.error(f"Memory modification error: {str(e)}")
        return jsonify({'error': str(e)}), 400

@main.route('/toggle_pause', methods=['POST'])
def toggle_pause():
    data = request.json
    pause = data['pause']
    return jsonify({'status': 'success'})

@main.route('/change_speed', methods=['POST'])
def change_speed():
    data = request.json
    pid = data['pid']
    speed = float(data['speed'])
    
    if speed_controller.set_game_speed(pid, speed):
        return jsonify({'status': 'success', 'message': f'Speed set to {speed}x'})
    else:
        return jsonify({'error': 'Failed to change game speed'}), 400

@main.route('/reset_speed', methods=['POST'])
def reset_speed():
    data = request.json
    pid = data['pid']
    
    if speed_controller.reset_speed(pid):
        return jsonify({'status': 'success', 'message': 'Speed reset to normal'})
    else:
        return jsonify({'error': 'Failed to reset speed'}), 400

@main.route('/get_module_base', methods=['POST'])
def get_module_base():
    data = request.json
    module_name = data['moduleName']
    
    base_addr = memory_engine.get_module_base(module_name)
    if base_addr:
        return jsonify({'baseAddress': hex(base_addr)})
    else:
        return jsonify({'error': 'Module not found'}), 404

@main.route('/calculate_offset', methods=['POST'])
def calculate_offset():
    data = request.json
    base_addr = int(data['baseAddress'], 16)
    target_addr = int(data['targetAddress'], 16)
    
    offset = memory_engine.calculate_offset(base_addr, target_addr)
    return jsonify({'offset': hex(offset)})

@main.route('/resolve_pointer', methods=['POST'])
def resolve_pointer():
    data = request.json
    base_addr = int(data['baseAddress'], 16)
    offsets = [int(offset, 16) if isinstance(offset, str) else offset for offset in data['offsets']]
    
    final_addr = memory_engine.resolve_pointer_chain(base_addr, offsets)
    if final_addr:
        return jsonify({'finalAddress': hex(final_addr)})
    else:
        return jsonify({'error': 'Failed to resolve pointer chain'}), 400

@main.route('/detect_jvm', methods=['POST'])
def detect_jvm():
    jvm_processes = jvm_engine.detect_jvm_processes()
    return jsonify({'jvmProcesses': jvm_processes})

@main.route('/attach_jvm', methods=['POST'])
def attach_jvm():
    data = request.json
    pid = data['pid']
    
    if jni_interface.attach_to_jvm(pid):
        return jsonify({'status': 'success', 'message': f'Attached to JVM process {pid}'})
    else:
        return jsonify({'error': 'Failed to attach to JVM'}), 400

@main.route('/get_minecraft_player', methods=['POST'])
def get_minecraft_player():
    data = request.json
    pid = data['pid']
    
    player_data = jni_interface.get_minecraft_player_data(pid)
    if player_data:
        return jsonify({'playerData': player_data})
    else:
        return jsonify({'error': 'Failed to get player data'}), 400



@main.route('/give_item', methods=['POST'])
def give_item():
    data = request.json
    pid = data['pid']
    item_id = data['itemId']
    count = int(data.get('count', 1))
    
    if minecraft_helper.give_item(pid, item_id, count):
        return jsonify({'status': 'success', 'message': f'Gave {count} {item_id} to player'})
    else:
        return jsonify({'error': 'Failed to give item'}), 400

@main.route('/set_world_time', methods=['POST'])
def set_world_time():
    data = request.json
    pid = data['pid']
    time = int(data['time'])
    
    if minecraft_helper.set_time(pid, time):
        return jsonify({'status': 'success', 'message': f'World time set to {time}'})
    else:
        return jsonify({'error': 'Failed to set world time'}), 400

@main.route('/set_weather', methods=['POST'])
def set_weather():
    data = request.json
    pid = data['pid']
    weather = data['weather']
    
    if minecraft_helper.set_weather(pid, weather):
        return jsonify({'status': 'success', 'message': f'Weather set to {weather}'})
    else:
        return jsonify({'error': 'Failed to set weather'}), 400

@main.route('/start_overlay', methods=['POST'])
def start_overlay():
    data = request.json
    pid = data['pid']
    
    if overlay_renderer.start_rendering(pid):
        return jsonify({'status': 'success', 'message': 'Overlay started'})
    else:
        return jsonify({'error': 'Failed to start overlay'}), 400

@main.route('/stop_overlay', methods=['POST'])
def stop_overlay():
    overlay_renderer.stop_rendering()
    return jsonify({'status': 'success', 'message': 'Overlay stopped'})

@main.route('/draw_box', methods=['POST'])
def draw_box():
    data = request.json
    x = int(data['x'])
    y = int(data['y'])
    width = int(data['width'])
    height = int(data['height'])
    color = data.get('color', 'red')
    
    overlay_renderer.draw_box(x, y, width, height, color)
    return jsonify({'status': 'success'})

@main.route('/clear_overlay', methods=['POST'])
def clear_overlay():
    overlay_renderer.clear_all()
    return jsonify({'status': 'success'})

@main.route('/start_packet_capture', methods=['POST'])
def start_packet_capture():
    data = request.json
    pid = data.get('pid') if data else None
    
    if network_engine.start_packet_capture(pid):
        message = f'Packet capture started for process {pid}' if pid else 'Packet capture started'
        return jsonify({'status': 'success', 'message': message})
    else:
        return jsonify({'error': 'Failed to start packet capture'}), 400

@main.route('/stop_packet_capture', methods=['POST'])
def stop_packet_capture():
    if network_engine.stop_packet_capture():
        return jsonify({'status': 'success', 'message': 'Packet capture stopped'})
    else:
        return jsonify({'error': 'Failed to stop packet capture'}), 400

@main.route('/get_packets')
def get_packets():
    packets = network_engine.get_packets()
    stats = network_engine.get_statistics()
    hooked_info = network_engine.get_hooked_process_info()
    return jsonify({'packets': packets, 'stats': stats, 'hookedProcess': hooked_info})

@main.route('/clear_packets', methods=['POST'])
def clear_packets():
    network_engine.clear_packets()
    return jsonify({'status': 'success'})

@main.route('/get_network_stats')
def get_network_stats():
    stats = network_engine.get_statistics()
    hooked_info = network_engine.get_hooked_process_info()
    return jsonify({'stats': stats, 'hookedProcess': hooked_info})

@main.route('/set_network_filter', methods=['POST'])
def set_network_filter():
    data = request.json
    filter_type = data.get('type')
    value = data.get('value')
    
    network_engine.set_filter(filter_type, value)
    return jsonify({'status': 'success'})

@main.route('/hook_process', methods=['POST'])
def hook_process():
    data = request.json
    pid = data.get('pid')
    
    if network_engine.hook_process(pid):
        return jsonify({'status': 'success', 'message': f'Hooked process {pid}'})
    else:
        return jsonify({'error': 'Failed to hook process'}), 400

@main.route('/unhook_process', methods=['POST'])
def unhook_process():
    network_engine.unhook_process()
    return jsonify({'status': 'success', 'message': 'Process unhooked'})

@main.route('/get_hooked_process_info')
def get_hooked_process_info():
    info = network_engine.get_hooked_process_info()
    return jsonify({'processInfo': info})

@main.route('/exit_app', methods=['POST'])
def exit_app():
    import os
    import threading
    
    def shutdown():
        import time
        time.sleep(1)
        os._exit(0)
    
    threading.Thread(target=shutdown, daemon=True).start()
    return jsonify({'status': 'success', 'message': 'Application shutting down...'})

@main.route('/update_function_content', methods=['POST'])
def update_function_content():
    data = request.json
    function_content = data['functionContent']
    with open('app/game_speed_function.py', 'w') as f:
        f.write(function_content)
    return jsonify({'status': 'success'})

@main.route('/execute_script', methods=['POST'])
def execute_script():
    data = request.json
    script_type = data['scriptType']
    script_content = data['scriptContent']

    if script_type == 'python':
        exec_globals = {}
        exec(script_content, exec_globals)
        result = exec_globals.get('result', 'No result returned')
    elif script_type == 'kotlin':
        result = execute_kotlin_script(script_content)
    else:
        return jsonify({'status': 'error', 'message': 'Unsupported script type'}), 400

    return jsonify({'status': 'success', 'result': result})

def execute_kotlin_script(script_content):
    with open('script.kt', 'w') as f:
        f.write(script_content)

    result = subprocess.run(['kotlinc', 'script.kt', '-script'], capture_output=True, text=True)
    if result.returncode != 0:
        return f"Error: {result.stderr}"
    return result.stdout

@main.route('/upload_script', methods=['POST'])
def upload_script():
    if 'scriptFile' not in request.files:
        return jsonify({'status': 'error', 'message': 'No file part'}), 400

    file = request.files['scriptFile']
    if file.filename == '':
        return jsonify({'status': 'error', 'message': 'No selected file'}), 400

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join('uploads', filename))
        return jsonify({'status': 'success', 'message': 'File uploaded successfully'})

    return jsonify({'status': 'error', 'message': 'File type not allowed'}), 400



def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'py', 'kt'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS