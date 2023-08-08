#!/usr/bin/python3
import argparse
import os
import timeit
import time
import pandas as pd
import numpy as np
import sys
from termcolor import colored
import logging
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from download import *
from extraction import *
from label import *
from utils import *

class DefaultHelpParser(argparse.ArgumentParser):
    def error(self, message):
        global logger
        self.print_help()
        print_error(message, logger)
        sys.exit(2)

def parse_args(argv):
    parser = DefaultHelpParser(formatter_class = argparse.RawTextHelpFormatter)
    parser._optionals.title = 'Show Help'

    parser_action = parser.add_argument_group('ADGen Parameters')
    parser_action.add_argument('--file', type = str,
        help = 'File With a List of APKs SHA256 (One Per Line)', required = True)
    parser_action.add_argument('--download', help = 'Download APK files', action = 'store_true')
    parser_action.add_argument('--download_dir', metavar = 'PATH',
        type = str, help = 'Directory to/from Downloads', default = 'adg_download')
    parser_action.add_argument('--androzoo-key', '-azk', metavar = 'KEY',
        type = str, help = 'Androzoo API Key')
    parser_action.add_argument('--num-parallel-download', '-npd', metavar = 'INT',
        type = int, default = 1, help = 'Number of Parallel Downloads')
    parser_action.add_argument('--extraction', help='APK Metadata and Features Extraction', action = 'store_true')
    parser_action.add_argument('--num-parallel-extraction', '-npe', metavar = 'INT',
        type = int, default = 1, help='Number of Parallel Process for Feature Extraction')
    parser_action.add_argument('--label', help = 'VirusTotal Labelling', action = 'store_true')
    parser_action.add_argument('--vt-key', '-vtk', metavar = 'KEY',
        type = str, help = 'VirusTotal\'s API Key')
    parser_action.add_argument('--reanalyze-time', '-rt', metavar = 'INT',
        type = int, help = 'Time to Wait for Reanalysis (in Hours)', default = 24)
    parser_action.add_argument('--output-data', metavar = 'PATH',
        type = str, help = 'Data Output Directory', default = 'adg_data')

    if not argv:
        parser.error('no argument presented')

    args = parser.parse_args(argv)
    #if (args.download or args.label) and not args.file:
        #parser.error('the following arguments are required when --download or --label is set: --file')
    if args.download and not args.androzoo_key:
        parser.error('the following arguments are required when --download is set: --androzoo-key/-ak')
    #if args.extraction and not args.download and not args.download_dir:
        #parser.error('the following arguments are required when --download is set: --androzoo-key/-ak')
    if args.label and not args.vt_key:
        parser.error('the following arguments are required when --label is set: --vt-key/-vtk')
    return args

def generate_apk_file_list(download_dir, sha256_list):
    apk_file_list = [os.path.join(download_dir, f'{sha256}.apk') for sha256 in sha256_list]
    return apk_file_list

def run_download(args, sha256_list):
    global logger
    print_info('Download Process Started', logger)
    apk_downloader = AndrozooDownloader(args)
    apk_downloader.download_in_parallel(sha256_list)
    print_info('Download Process Finished', logger)

def run_extraction(args, sha256_list):
    global logger
    print_info('Extraction Process Started', logger)
    apk_file_list = generate_apk_file_list(args.download_dir, sha256_list)
    apk_extractor = AndroGuardExtractor(args)
    apk_extractor.extraction_in_parallel(apk_file_list)
    print_info('Extraction Process Finished', logger)

def run_label(args, sha256_list):
    global logger
    print_info('Label Process Started', logger)
    apk_labeler = VirusTotalLabeler(args)
    apk_labeler.run_label(sha256_list)
    print_info('Label Process Finished', logger)

if __name__=="__main__":
    global logger
    logging.basicConfig(format = '[%(asctime)s] %(name)s - %(levelname)s - %(message)s', datefmt = '%Y-%m-%d %H:%M:%S')
    logger = logging.getLogger('ADGen')
    args = parse_args(sys.argv[1:])

    if not os.path.exists(args.file):
        print_error(f'Invalid or Non-existent File: {args.file}', logger)
        sys.exit(2)

    sha256_list = load_file(args.file)

    with ThreadPoolExecutor() as executor:
        futures_list = list()
        if args.download:
            futures_list.append(executor.submit(run_download, args, sha256_list))

        if args.extraction:
            futures_list.append(executor.submit(run_extraction, args, sha256_list))

        if args.label:
            futures_list.append(executor.submit(run_label, args, sha256_list))

        for future in as_completed(futures_list):
            pass
