import logging

def configure_logging():
    """
    Sets up the universal JSON-friendly or standard structured logging.
    """
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(name)s - %(message)s')

def get_logger(name):
    """
    Creates and returns a named logger instance.
    """
    return logging.getLogger(name)
