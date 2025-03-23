import os

from flask import Blueprint, render_template, request, jsonify
import psutil
import ctypes
import struct
import subprocess
from werkzeug.utils import secure_filename

main = Blueprint('main', __name__)

@main.route('/')
def index():
    processes = [proc.info for proc in psutil.process_iter(['pid', 'name'])]
    return render_template('index.html', processes=processes)

@main.route('/process/<int:pid>')
def process(pid):
    process = psutil.Process(pid)
    threads = []
    for thread in process.threads():
        threads.append({
            'id': thread.id,
            'user_time': thread.user_time,
            'system_time': thread.system_time
        })
    memory_info = {}
    cpu_usage = process.cpu_percent(interval=1)
    memory_usage = process.memory_percent()
    disk_usage = psutil.disk_usage('/').percent
    gpu_usage = 0
    return jsonify({
        'threads': threads,
        'memory_info': memory_info,
        'cpu_usage': cpu_usage,
        'memory_usage': memory_usage,
        'disk_usage': disk_usage,
        'gpu_usage': gpu_usage,
        'name': process.name(),
        'pid': process.pid
    })

@main.route('/scan_memory', methods=['POST'])
def scan_memory():
    data = request.json
    scan_type = data['scanType']
    value_type = data['valueType']
    scan_value = data['scanValue']
    results = []
    return jsonify({'results': results})

@main.route('/modify_memory', methods=['POST'])
def modify_memory():
    data = request.json
    address = int(data['address'], 16)
    value = data['value']
    modify_memory_value(address, value)
    return jsonify({'status': 'success'})

def modify_memory_value(address, value):
    PROCESS_ALL_ACCESS = 0x1F0FFF
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

    h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h_process:
        raise ctypes.WinError(ctypes.get_last_error())

    addr = ctypes.c_void_p(address)
    val = ctypes.create_string_buffer(value.encode('utf-8'))
    size = len(val)

    written = ctypes.c_size_t()
    if not kernel32.WriteProcessMemory(h_process, addr, val, size, ctypes.byref(written)):
        raise ctypes.WinError(ctypes.get_last_error())

    kernel32.CloseHandle(h_process)

@main.route('/toggle_pause', methods=['POST'])
def toggle_pause():
    data = request.json
    pause = data['pause']
    return jsonify({'status': 'success'})

@main.route('/change_speed', methods=['POST'])
def change_speed():
    data = request.json
    game_id = data['gameId']
    speed = data['speed']
    adjust_game_speed(game_id, speed)
    return jsonify({'status': 'success'})

def adjust_game_speed(game_id, speed):
    pass

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