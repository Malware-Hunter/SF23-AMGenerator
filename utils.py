import json
import time
import datetime
import os
from termcolor import colored
import pandas as pd

def print_exception(e, addicional_info, logger = None):
    error_type = type(e).__name__
    error_message = e.args[0]
    msg = colored(f'{addicional_info} >> {error_type}: {error_message}', 'red', attrs = ['bold'])
    if logger:
        logger.exception(msg)
    else:
        print(f'[EXCEPTION] {msg}')

def print_error(message, logger = None):
    msg = colored(message, 'red')
    if logger:
        logger.error(msg)
    else:
        print(f'[ERROR] {msg}')

def print_info(message, logger = None, color = 'green'):
    msg = colored(message, color)
    if logger:
        logger.info(msg)
    else:
        print(f'[INFO] {msg}')

def wait_for_file(file_path, timeout = 3600, interval = 1):
    start_time = time.time()
    while not os.path.exists(file_path):
        if time.time() - start_time > timeout:
            raise TimeoutError(f'File {file_path} Not Found After Timeout')
        time.sleep(interval)

def load_csv_file(file_path, cols = list()):
    if os.path.exists(file_path):
        if cols:
            df = pd.read_csv(file_path, header = None, names = cols)
        else:
            df = pd.read_csv(file_path)
        return df
    return pd.DataFrame()

def load_file(file_path):
    with open(file_path, 'r') as text_file:
        lines = text_file.readlines()
        lines = [line.rstrip('\n') for line in lines]
    return lines

def epoch_to_human_date(epoch_time):
    date = datetime.datetime.fromtimestamp(epoch_time)
    human_readable_date = date.strftime('%Y-%m-%d %H:%M:%S')
    return human_readable_date

def save_as_json(data, json_file):
    with open(str(json_file), 'w') as fp:
        json.dump(data, fp, indent = 4)
