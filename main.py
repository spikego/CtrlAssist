import ctypes
import sys
import logging
import traceback
import threading
import webbrowser
from PyQt6.QtWidgets import QApplication, QMessageBox, QSystemTrayIcon, QMenu
from PyQt6.QtCore import QTimer
from PyQt6.QtGui import QIcon
from app import create_app

# Setup logging to file and console
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

def is_admin():
    """
    Check if the script is running with administrator privileges.
    """
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    """
    Relaunch the script with administrator privileges if not already running as admin.
    """
    if not is_admin():
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, " ".join(sys.argv), None, 1
        )
        sys.exit(0)

def open_browser():
    """Auto-open browser after Flask starts"""
    import time
    time.sleep(3)
    webbrowser.open('http://127.0.0.1:5000')
    print("Browser opened automatically. Access: http://127.0.0.1:5000")

def run_flask_app():
    """在单独线程中运行Flask应用"""
    try:
        app = create_app()
        app.run(host='127.0.0.1', port=5000, debug=False, use_reloader=False)
    except Exception as e:
        logger.error(f"Flask error: {str(e)}")

def main():
    try:
        print("CtrlAssist Memory Engine Starting...")
        logger.info("Starting application initialization...")
        
        # 启动Flask服务器
        flask_thread = threading.Thread(target=run_flask_app, daemon=True)
        flask_thread.start()
        
        # 启动浏览器打开线程
        browser_thread = threading.Thread(target=open_browser, daemon=True)
        browser_thread.start()
        
        print("Server running at: http://127.0.0.1:5000")
        print("Press Ctrl+C to stop the server")
        
        # 保持程序运行
        try:
            while True:
                import time
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nShutting down...")
            logger.info("Application stopped by user")
        
    except Exception as e:
        logger.error(f"Fatal error: {str(e)}")
        logger.error(traceback.format_exc())
        input("Press Enter to exit...")
        sys.exit(1)

if __name__ == '__main__':
    try:
        logger.info("Application starting...")
        run_as_admin()  # Ensure admin privileges before running the main logic
        main()
    except KeyboardInterrupt:
        logger.info("Application stopped by user")
    except Exception as e:
        logger.error(f"Unhandled exception: {str(e)}")
        logger.error(traceback.format_exc())
        input("Press Enter to exit...")