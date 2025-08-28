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
    """获取进程详细信息"""
    try:
        process = psutil.Process(pid)
        if not process.is_running():
            return jsonify({'error': 'Process not found'}), 404

        # 获取进程基本信息
        name = process.name()
        try:
            exe = process.exe()
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            exe = "Access Denied"

        # 获取资源使用情况
        try:
            with process.oneshot():  # 优化性能，一次性获取所有信息
                cpu_percent = process.cpu_percent(interval=0.1)
                memory_percent = process.memory_percent()
                memory_info = process.memory_info()
                io_counters = process.io_counters() if hasattr(process, 'io_counters') else None
                num_threads = process.num_threads()
                status = process.status()

                disk_usage = None
                try:
                    disk_usage = psutil.disk_usage(os.path.dirname(exe)).percent if exe != "Access Denied" else None
                except:
                    pass

                # 获取更多详细信息
                create_time = process.create_time()
                ppid = process.ppid()

                # 获取命令行（如果可能）
                try:
                    cmdline = ' '.join(process.cmdline())
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    cmdline = "Access Denied"

                # 获取工作目录
                try:
                    cwd = process.cwd()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    cwd = "Access Denied"

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return jsonify({'error': 'Failed to get process details'}), 500

        return jsonify({
            'name': name,
            'pid': pid,
            'exe': exe,
            'status': status,
            'cpu_usage': round(cpu_percent, 1),
            'memory_usage': round(memory_percent, 1),
            'memory_info': {
                'rss': memory_info.rss,
                'vms': memory_info.vms,
            },
            'num_threads': num_threads,
            'create_time': create_time,
            'parent_pid': ppid,
            'cmdline': cmdline,
            'cwd': cwd,
            'disk_usage': round(disk_usage, 1) if disk_usage is not None else None,
            'io_info': {
                'read_bytes': io_counters.read_bytes if io_counters else None,
                'write_bytes': io_counters.write_bytes if io_counters else None,
            } if io_counters else None
        })

    except psutil.NoSuchProcess:
        return jsonify({'error': 'Process not found'}), 404
    except psutil.AccessDenied:
        return jsonify({'error': 'Access denied'}), 403
    except Exception as e:
        logger.error(f"Error getting process info: {str(e)}")
        return jsonify({'error': str(e)}), 500


@main.route('/attach_process', methods=['POST'])
def attach_process():
    data = request.json
    pid = data.get('pid')

    if memory_engine.attach_process(pid):
        return jsonify({'status': 'success', 'message': f'Attached to process {pid}'})
    else:
        return jsonify({'status': 'error', 'message': 'Failed to attach to process'}), 400


@main.route('/first_scan', methods=['POST'])
def first_scan():
    from .memory_engine import ScanType, ValueType

    # 首先检查是否已附加进程
    if not memory_engine.process_handle and not memory_engine.pymem_process:
        return jsonify({'status': 'error', 'message': '请先选择并附加一个进程'}), 400

    data = request.json
    scan_type = ScanType(data['scanType'])
    value_type = ValueType(data['valueType'])
    value1 = data.get('value1')
    value2 = data.get('value2')

    try:
        # 转换数值类型，检查空值
        if value1 is not None and str(value1).strip():
            if value_type in [ValueType.BYTE, ValueType.WORD_2BYTES, ValueType.DWORD_4BYTES, ValueType.QWORD_8BYTES]:
                value1 = int(value1)
            elif value_type in [ValueType.FLOAT, ValueType.DOUBLE]:
                value1 = float(value1)
        else:
            value1 = None

        if value2 is not None and str(value2).strip():
            if value_type in [ValueType.BYTE, ValueType.WORD_2BYTES, ValueType.DWORD_4BYTES, ValueType.QWORD_8BYTES]:
                value2 = int(value2)
            elif value_type in [ValueType.FLOAT, ValueType.DOUBLE]:
                value2 = float(value2)
        else:
            value2 = None

        result_count = memory_engine.first_scan(scan_type, value_type, value1, value2)

        logger.info(f"First scan found {result_count} results")
        return jsonify({'status': 'success', 'count': result_count})

    except Exception as e:
        logger.error(f"First scan error: {str(e)}")
        return jsonify({'error': str(e)}), 400


@main.route('/next_scan', methods=['POST'])
def next_scan():
    from .memory_engine import ScanType, ValueType

    # 首先检查是否已附加进程
    if not memory_engine.process_handle and not memory_engine.pymem_process:
        return jsonify({'status': 'error', 'message': '请先选择并附加一个进程'}), 400

    data = request.json
    scan_type = ScanType(data['scanType'])
    value_type = ValueType(data['valueType'])
    value1 = data.get('value1')
    value2 = data.get('value2')

    try:
        # 转换数值类型
        if value1 is not None and value_type in [ValueType.BYTE, ValueType.WORD_2BYTES, ValueType.DWORD_4BYTES,
                                                 ValueType.QWORD_8BYTES]:
            value1 = int(value1)
        elif value1 is not None and value_type in [ValueType.FLOAT, ValueType.DOUBLE]:
            value1 = float(value1)

        if value2 is not None and value_type in [ValueType.BYTE, ValueType.WORD_2BYTES, ValueType.DWORD_4BYTES,
                                                 ValueType.QWORD_8BYTES]:
            value2 = int(value2)
        elif value2 is not None and value_type in [ValueType.FLOAT, ValueType.DOUBLE]:
            value2 = float(value2)

        result_count = memory_engine.next_scan(scan_type, value_type, value1, value2)

        logger.info(f"Next scan found {result_count} results")
        return jsonify({'status': 'success', 'count': result_count})

    except Exception as e:
        logger.error(f"Next scan error: {str(e)}")
        return jsonify({'error': str(e)}), 400


@main.route('/undo_scan', methods=['POST'])
def undo_scan():
    try:
        if memory_engine.undo_scan():
            return jsonify({'status': 'success', 'message': 'Scan undone'})
        else:
            return jsonify({'error': 'Cannot undo scan'}), 400
    except Exception as e:
        logger.error(f"Undo scan error: {str(e)}")
        return jsonify({'error': str(e)}), 400


@main.route('/get_scan_results', methods=['GET'])
def get_scan_results():
    start = int(request.args.get('start', 0))
    count = int(request.args.get('count', 100))

    try:
        results = memory_engine.get_scan_results(start, count)
        total_count = memory_engine.get_scan_count()

        return jsonify({
            'results': results,
            'total': total_count,
            'start': start,
            'count': len(results)
        })
    except Exception as e:
        logger.error(f"Get scan results error: {str(e)}")
        return jsonify({'error': str(e)}), 400


@main.route('/update_scan_results', methods=['POST'])
def update_scan_results():
    from .memory_engine import ValueType

    data = request.json
    value_type = ValueType(data['valueType'])

    try:
        updated_count = memory_engine.update_scan_results(value_type)
        return jsonify({'status': 'success', 'updated': updated_count})
    except Exception as e:
        logger.error(f"Update scan results error: {str(e)}")
        return jsonify({'error': str(e)}), 400


@main.route('/set_scan_options', methods=['POST'])
def set_scan_options():
    data = request.json

    try:
        if memory_engine.set_scan_options(data):
            return jsonify({'status': 'success'})
        else:
            return jsonify({'error': 'Failed to set scan options'}), 400
    except Exception as e:
        logger.error(f"Set scan options error: {str(e)}")
        return jsonify({'error': str(e)}), 400


@main.route('/modify_memory', methods=['POST'])
def modify_memory():
    from .memory_engine import ValueType

    data = request.json
    address = int(data['address'], 16)
    value = data['value']
    value_type = ValueType(data.get('valueType', 'dword_4bytes'))

    try:
        if memory_engine.write_value_to_address(address, value, value_type):
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