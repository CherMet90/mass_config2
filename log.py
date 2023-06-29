import logging
import sys

# Initialize logger with the name 'NetBox'
logger = logging.getLogger('NetBox')

# Set logging level (uncomment the desired level)
logger.setLevel(logging.DEBUG)
# logger.setLevel(logging.INFO)
# logger.setLevel(logging.WARNING)
# logger.setLevel(logging.ERROR)

# Configure console (stream) handler to print log messages
c_handler = logging.StreamHandler(sys.stdout)
c_format = logging.Formatter(
    "[%(asctime)s.%(msecs)03d %(module)s - %(funcName)23s() ] %(message)s", datefmt='%d.%m.%Y %H:%M:%S')
c_handler.setFormatter(c_format)
logger.addHandler(c_handler)

# Configure file handler to store log messages in 'NetBox.log' with mode 'w' (overwrite)
f_handler = logging.FileHandler('NetBox.log', mode='w', encoding='utf-8')
f_format = logging.Formatter(
    "[%(asctime)s.%(msecs)03d - %(funcName)23s() ] %(message)s", datefmt='%d.%m.%Y %H:%M:%S')
f_handler.setFormatter(f_format)
logger.addHandler(f_handler)

# Uncomment the following lines to test different logging levels
# logger.debug('logger.debug')
# logger.info('logger.info')
# logger.warning('logger.warning')
# logger.error('logger.error')
# logger.exception('logger.exception')
