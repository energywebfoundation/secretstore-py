import logging
from decorator import decorator

try:
    from web3.datastructures import AttributeDict
except ModuleNotFoundError:
    from web3.utils.datastructures import AttributeDict

def add_0x(value: str) -> str:
    if value.startswith("0x"):
        return str(value)
    return "0x" + str(value)


def remove_0x(value: str) -> str:
    if value.startswith("0x"):
        return str(value)[2:]
    return str(value)


def remove_enclosing(value: str, enclosing: str="\"") -> str:
    strval = str(value)
    if strval.startswith(enclosing) and strval.endswith(enclosing):
        return strval[1:-1]
    return strval


def get_default_logger(name) -> logging.RootLogger:
    if not name:
        name = __name__
    logger = logging.getLogger(name)
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        '%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    return logger

@decorator
def response_to_dict(f, *args, **kwargs):
    resp = f(*args, **kwargs)
    
    if not resp.text:
        return {}

    return resp.json()

@decorator
def response_to_str(f, *args, **kwargs):
    resp = f(*args, **kwargs)

    if not resp.text:
        return ""

    # this removes closing dquotes
    return resp.json()

@decorator
def response_to_attrdict(f, *args, **kwargs):
    resp = f(*args, **kwargs)

    if not resp.text:
        return AttributeDict({})

    # this removes closing dquotes
    return AttributeDict(resp.json())