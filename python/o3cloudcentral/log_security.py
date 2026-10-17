"""Preserve operational HTTP logs without recording enrollment bearer URLs."""
import logging
import re

INSTALL_TOKEN = re.compile(r'(/(?:api/install/pfsense|install/windows)/)[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])')


def redact(value):
    return INSTALL_TOKEN.sub(r'\1[REDACTED]', value) if isinstance(value, str) else value


class InstallationTokenFilter(logging.Filter):
    def filter(self, record):
        record.msg = redact(record.msg)
        if isinstance(record.args, tuple):
            record.args = tuple(redact(value) for value in record.args)
        elif isinstance(record.args, dict):
            record.args = {key:redact(value) for key,value in record.args.items()}
        return True


def install_log_filters():
    for name in ('uvicorn.access', 'aiohttp.access', 'httpx'):
        logger = logging.getLogger(name)
        if not any(isinstance(item, InstallationTokenFilter) for item in logger.filters):
            logger.addFilter(InstallationTokenFilter())
