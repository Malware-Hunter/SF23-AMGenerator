#!/usr/bin/python3
import threading
import argparse
import os
from os.path import basename, dirname
import sys
from termcolor import colored
import logging
import requests
from concurrent.futures import ThreadPoolExecutor
from utils import *
import pandas as pd
import time
import fcntl
import glob

class APIKeyAccess:
    def __init__(self):
        self.available = True
        #self.lock = threading.Semaphore(1) #semaphore with count of 1 (a single API key)

    def acquire(self):
        #self.lock.acquire()
        while not self.available:
            time.sleep(1)
        self.available = False

    def release(self):
        self.available = True
        time.sleep(2)
        #self.lock.release()

class VirusTotalLabeler:
    def __init__(self, args):
        self.api_key_access = APIKeyAccess()
        self.api_key = args.vt_key
        self.label_dir = os.path.join(args.output_data, 'label')
        self.request_number = 0
        self.wait_time = {
            'report': 15,
            'reanalyze': 15
        }
        self.report_wait_time = 15
        self.reanalyze_wait_time = 15
        self.reanalyze_time = args.reanalyze_time * 60
        self.next_start = int(time.time() + 86400)
        self.log_file = {
            'report': f'log_report_{self.api_key}.log',
            'reanalyze': f'log_reanalyze_{self.api_key}.log'
        }
        self.queue_file = 'queue_reanalyze.que'
        self.deadline = 1672531201 #epoch time to 2023-01-01 00:00:01
        os.makedirs(self.label_dir, exist_ok = True)
        self.logger = {
            'report': logging.getLogger('REPORT'),
            'reanalyze': logging.getLogger('REANALYZE')
        }
        for l in self.logger.values():
            l.setLevel(logging.INFO)

    def update_counters(self, source, reset = False):
        self.wait_time[source] = 15
        self.request_number += 1
        if self.request_number == 500 or reset:
            self.request_number = 0
            self.wait_time['report'] = int(self.next_start - time.time())
            self.wait_time['reanalyze'] = int(self.next_start - time.time())
            self.next_start += 86400 #next start in 24h

    def write_label_log(self, sha256, status, source):
        try:
            with open(self.log_file[source], 'a') as f:
                f.write(f'{sha256},{status}\n')
        except Exception as e:
            print_exception(e, 'Exception Writing to Label Log', self.logger[source])

    def handle_vt_error(self, sha256, code, message, source):
        print_error(f'{sha256} :: {code}: {message}', self.logger[source])
        #code = code.replace('.','_')
        self.write_label_log(sha256, code, source)
        if code == 'QuotaExceededError':
            self.update_counters(reset = True)
        elif code == 'UserNotActiveError':
            print_exception(f'{code} :: Finishing Execution', self.logger[source])
            exit(1)

    def save_json(self, sha256, json_data, epoch_time, source):
        try:
            json_object = json.dumps(json_data, indent = 3)
            filename = f'{sha256}_{epoch_time}.json'
            json_location = os.path.join(self.label_dir, filename)
            json_file = open(json_location, 'w')
            json_file.write(json_object)
            json_file.close()
        except Exception as e:
            self.handle_vt_error(sha256, type(e).__name__, e.args[0], source)

    def process_report(self, sha256, json_data, analysis_date, is_updated, source):
        self.save_json(sha256, json_data, analysis_date, source)
        if is_updated:
            self.write_label_log(sha256, 'Labeled', source)

    def write_label_queue(self, sha256, source):
        try:
            with open(self.queue_file, 'a+') as file:
                fcntl.flock(file.fileno(), fcntl.LOCK_EX)
                now = int(time.time())
                file.write(f'{sha256},{now}\n')
                fcntl.flock(file.fileno(), fcntl.LOCK_UN)
            self.write_label_log(sha256, 'Reanalyze', source)
        except Exception as e:
            self.write_label_log(sha256, type(e).__name__, source)
            print_exception(e, 'Exception Writing to Queue', self.logger[source])

    def read_label_queue(self, action):
        try:
            with open(self.queue_file, 'r+') as file:
                fcntl.flock(file.fileno(), fcntl.LOCK_EX)
                lines = file.readlines()
                amount_ = len(lines)
                if amount_ > 0:
                    first_line = lines[0].strip()
                    older_, timestamp = first_line.split(',')
                    if action == 'dequeue':
                        file.seek(0)
                        file.writelines(lines[1:])
                        file.truncate()
                    fcntl.flock(file.fileno(), fcntl.LOCK_UN)
                    return amount_, older_, int(timestamp)
                else:
                    fcntl.flock(file.fileno(), fcntl.LOCK_UN)
        except FileNotFoundError:
            return None, None, None
        return None, None, None

    def request_reanalyze(self, sha256):
        time.sleep(self.wait_time['report'])
        print_info(f'Send {sha256} to Reanalyze (Waiting For New Request)', self.logger['report'], 'yellow')
        json_data = self.vt_reanalyze(sha256)
        if json_data:
            self.write_label_queue(sha256, 'report')

    def vt_reanalyze(self, sha256):
        url = f'https://www.virustotal.com/api/v3/files/{sha256}/analyse'
        headers = {
            'accept': 'application/json',
            'x-apikey': self.api_key
            }
        try:
            response = requests.post(url, headers = headers)
            self.update_counters('report')
            response.raise_for_status()
            if response.text:
                return response.json()
        except requests.exceptions.HTTPError as errh:
            if errh.response.text and 'error' in errh.response.text:
                json_data = (errh.response).json()
                code = json_data['error']['code']
                message = json_data['error']['message']
                self.handle_vt_error(sha256, code, message, 'report')
            else:
                self.handle_vt_error(sha256, type(errh).__name__, errh.args[0], 'report')
        except json.decoder.JSONDecodeError as errj:
            self.handle_vt_error(sha256, type(errj).__name__, errj.args[0], 'report')
        except Exception as e:
            self.handle_vt_error(sha256, type(e).__name__, e.args[0], 'report')
        return None

    def vt_report(self, sha256, source):
        url = f'https://www.virustotal.com/api/v3/files/{sha256}'
        headers = {
            'accept': 'application/json',
            'x-apikey': self.api_key
            }
        try:
            response = requests.get(url, headers = headers)
            self.update_counters(source)
            response.raise_for_status()
            if response.text:
                return response.json()
        except requests.exceptions.HTTPError as errh:
            if errh.response.text and 'error' in errh.response.text:
                json_data = (errh.response).json()
                code = json_data['error']['code']
                message = json_data['error']['message']
                self.handle_vt_error(sha256, code, message, source)
            else:
                self.handle_vt_error(sha256, type(errh).__name__, errh.args[0], source)
        except json.decoder.JSONDecodeError as errj:
            self.handle_vt_error(sha256, type(errj).__name__, errj.args[0], source)
        except Exception as e:
            self.handle_vt_error(sha256, type(e).__name__, e.args[0], source)
        return None

    def updated_or_reanalyze(self, sha256):
        filename_pattern = os.path.join(self.label_dir, f'{sha256}_*.json')
        file_list = glob.glob(filename_pattern)
        analysis_date = 0
        for file in file_list:
            filename = os.path.splitext(basename(file))[0]
            _, timestamp = filename.split('_')
            if int(timestamp) > analysis_date:
                analysis_date = int(timestamp)
        if analysis_date > self.deadline:
            print_info(f'{sha256} Labeling is Updated', self.logger['report'])
            return True
        else:
            try:
                with open(self.queue_file, 'r') as file:
                    fcntl.flock(file.fileno(), fcntl.LOCK_EX)
                    for line in file:
                        sha256_queued, _ = line.strip().split(',')
                        if sha256 == sha256_queued:
                            print_info(f'{sha256} is in Reanalysis', self.logger['report'], 'yellow')
                            fcntl.flock(file.fileno(), fcntl.LOCK_UN)
                            return True
                    fcntl.flock(file.fileno(), fcntl.LOCK_UN)
            except FileNotFoundError:
                return False
        return False

    def run_report(self, sha256_list):
        processed = 0
        for sha256 in sha256_list:
            print_info(f'Processing {sha256} ...', self.logger['report'])
            if self.updated_or_reanalyze(sha256):
                continue
            self.api_key_access.acquire()
            json_data = self.vt_report(sha256, 'report')
            if json_data:
                try:
                    analysis_date = int(json_data['data']['attributes']['last_analysis_date'])
                    human_readable_date = epoch_to_human_date(analysis_date)
                    is_updated = analysis_date > self.deadline
                    color = 'green' if is_updated else 'red'
                    status = 'Updated' if is_updated else 'Out of Date'
                    print_info(f'Last Analysis: {human_readable_date} ({status})', self.logger['report'], color)
                    self.process_report(sha256, json_data, analysis_date, is_updated, 'report')
                    if not is_updated:
                        print_info(f'Requests Used: {self.request_number} (Waiting For New Request)', self.logger['report'])
                        self.request_reanalyze(sha256)
                except Exception as e:
                    print_exception(e, 'Exception Processing Report', self.logger['report'])
                    self.write_label_log(sha256, type(e).__name__, 'report')
            processed += 1
            print_info(f'Requests Used: {self.request_number} (Waiting For New Request)', self.logger['report'])
            if processed != len(sha256_list):
                time.sleep(self.wait_time['report'])
            self.api_key_access.release()
        print_info('REPORT Process Finished', self.logger['reanalyze'], 'blue')

    def run_reanalyze(self):
        while True:
            amount, sha256, timestamp = self.read_label_queue('peek')
            if not amount: #if no files wait self.reanalyze_time and test again
                print_info('Reanalyze Queue is Empty', self.logger['reanalyze'], 'blue')
                if self.thread_report.done():
                    print_info('REANALYZE Process Finished', self.logger['reanalyze'], 'blue')
                    break
                print_info('The REPORT Process is Still Running', self.logger['reanalyze'], 'blue')
                time.sleep(self.wait_time['reanalyze'])
                continue
            time_elapsed = time.time() - timestamp
            if time_elapsed < self.reanalyze_time:
                self.wait_time['reanalyze'] = self.reanalyze_time - time_elapsed
                print_info(f'Time to Reanalyze {sha256} Not Elapsed. Waiting ...', self.logger['reanalyze'], 'yellow')
                time.sleep(self.wait_time['reanalyze'])
            self.api_key_access.acquire()
            print_info(f'SHA256 in Reanalyze Queue: {amount}', self.logger['reanalyze'], 'blue')
            print_info(f'Processing {sha256} ...', self.logger['reanalyze'])
            json_data = self.vt_report(sha256, 'reanalyze')
            amount, sha256, timestamp = self.read_label_queue('dequeue')
            if json_data:
                try:
                    last_analysis_date = int(json_data['data']['attributes']['last_analysis_date'])
                    human_readable_date = epoch_to_human_date(last_analysis_date)
                    is_updated = last_analysis_date > self.deadline
                    color = 'green' if is_updated else 'red'
                    status = 'Updated' if is_updated else 'Out of Date'
                    print_info(f'Last Analysis: {human_readable_date} ({status})', self.logger['reanalyze'], color)
                    self.process_report(sha256, json_data, last_analysis_date, is_updated, 'reanalyze')
                    if not is_updated:
                        self.write_label_queue(sha256, 'reanalyze')
                except Exception as e:
                    print_exception(e, 'Exception Processing Reanalyze', self.logger['reanalyze'])
                    self.write_label_log(sha256, type(e).__name__, 'reanalyze')
            print_info(f'Requests Used: {self.request_number} (Waiting For New Request)', self.logger['reanalyze'])
            time.sleep(self.wait_time['reanalyze'])
            self.api_key_access.release()

    def run_label(self, sha256_list):
        with ThreadPoolExecutor(max_workers = 2) as executor:
            self.thread_report = executor.submit(self.run_report, sha256_list)
            self.thread_reanalyze = executor.submit(self.run_reanalyze)
