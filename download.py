#!/usr/bin/python3
import argparse
import os
import sys
from termcolor import colored
import logging
import requests
from concurrent.futures import ThreadPoolExecutor
from extraction import *

class AndrozooDownloader:
    def __init__(self, args):
        self.api_key = args.androzoo_key
        self.download_dir = args.download_dir
        self.num_parallel_downloads = args.num_parallel_download
        os.makedirs(self.download_dir, exist_ok = True)
        #logging.basicConfig(format = '[%(asctime)s] %(name)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger('DOWNLOAD')
        self.logger.setLevel(logging.INFO)

    def create_downloaded_file(self, apk_file):
        try:
            downloaded_file = apk_file.replace('.apk', '.downloaded')
            if not os.path.exists(downloaded_file):
                with open(downloaded_file, 'x') as file:
                    pass
        except Exception as e:
            print_exception(e, 'Downloaded File', self.logger)

    def download_apk(self, sha256):
        base_url = 'https://androzoo.uni.lu/api/download'
        apk_url = f'{base_url}?apikey={self.api_key}&sha256={sha256}'
        apk_file = os.path.join(self.download_dir, f'{sha256}.apk')

        if os.path.exists(apk_file):
            print_info(f'{sha256} Already Downloaded', self.logger)
            self.create_downloaded_file(apk_file)
        else:
            print_info(f'Downloading {sha256} ...', self.logger)
            response = requests.get(apk_url, stream = True)
            if response.status_code == 200:
                with open(apk_file, 'wb') as f:
                    for chunk in response.iter_content(chunk_size = 8192):
                        f.write(chunk)
                print_info(f'Download of {sha256} Completed', self.logger)
                self.create_downloaded_file(apk_file)
            else:
                print_error(f'When Downloading {sha256}', self.logger)

    def download_in_parallel(self, sha256_list):
        with ThreadPoolExecutor(max_workers = self.num_parallel_downloads) as executor:
            executor.map(self.download_apk, sha256_list)
