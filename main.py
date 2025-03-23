import sys
import logging
import traceback
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

def main():
    try:
        logger.info("Starting application initialization...")
        app = create_app()
        logger.info("Application created successfully")
        app.run(host='127.0.0.1', port=5000, debug=False)
    except Exception as e:
        logger.error(f"Fatal error: {str(e)}")
        logger.error(traceback.format_exc())
        input("Press Enter to exit...")
        sys.exit(1)

if __name__ == '__main__':
    try:
        logger.info("Application starting...")
        main()
    except KeyboardInterrupt:
        logger.info("Application stopped by user")
    except Exception as e:
        logger.error(f"Unhandled exception: {str(e)}")
        logger.error(traceback.format_exc())
        input("Press Enter to exit...")