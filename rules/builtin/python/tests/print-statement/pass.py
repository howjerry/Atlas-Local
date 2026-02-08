import logging

logger = logging.getLogger(__name__)

def proper_logging(value):
    logger.info("Processing value: %s", value)

def process_data(data):
    logger.debug("Processing %d items", len(data))
    return [x * 2 for x in data]
