import os
import hashlib
import logging
import zipfile as zp
import json
from concurrent.futures import ThreadPoolExecutor
from os.path import basename, dirname
from androguard.core.bytecodes.apk import APK
from androguard.core.analysis.analysis import ExternalMethod
from androguard.misc import AnalyzeAPK
from androguard import *
from androguard.core.analysis import *
from termcolor import colored
from constants import *
from utils import *
import time

class AndroGuardExtractor:
    def __init__(self, args):
        self.wait_download = args.download
        self.extraction_dir = os.path.join(args.output_data, 'extraction')
        self.num_parallel_extraction = args.num_parallel_extraction
        self.metadata_dir = os.path.join(self.extraction_dir, 'metadata')
        self.features_dir = os.path.join(self.extraction_dir, 'features')
        self.all_apicalls_dir = os.path.join(self.extraction_dir, 'all_apicalls')
        os.makedirs(self.extraction_dir, exist_ok = True)
        os.makedirs(self.metadata_dir, exist_ok = True)
        os.makedirs(self.features_dir, exist_ok = True)
        os.makedirs(self.all_apicalls_dir, exist_ok = True)
        self.logger = logging.getLogger('EXTRACTION')
        self.logger.setLevel(logging.INFO)
        self.agc_logger = logging.getLogger('androguard.core.api_specific_resources')
        self.agc_logger.setLevel(logging.ERROR)
        self.aga_logger = logging.getLogger('androguard.axml')
        self.aga_logger.setLevel(logging.ERROR)

    def get_op_codes(self, dx):
        op_codes_dict = dict()
        for method in dx.get_methods():
            if method.is_external():
                continue
            m = method.get_method()
            for ins in m.get_instructions():
                ins_name = ins.get_name()
                # continous data
                if ins_name not in op_codes_dict:
                    op_codes_dict[ins_name] = 1
                else:
                    op_codes_dict[ins_name] += 1
        return op_codes_dict

    def get_intents(self, app):
        intents = list()
        activities = app.get_activities()
        receivers = app.get_receivers()
        services = app.get_services()

        intent_filters = ['activity', 'receiver', 'service']
        intent_types = [activities, receivers, services]

        for i in range(len(intent_filters)):
            i_filter = intent_filters[i]
            i_type = intent_types[i]
            for item in i_type:
                for action, intent_name in app.get_intent_filters(i_filter, item).items():
                    for intent in intent_name:
                        intents.append(intent)

        intents = [i.split('.')[-1] for i in intents]
        intents = list(filter(lambda i: i in intents_list, intents))
        intents = list(set(intents))
        return intents

    def get_apicalls(self, cg, sha256):
        apicalls_dict = dict()
        common_methods = ['<init>', 'equals', 'hashCode', 'toString', 'clone', 'finalize', 'wait', 'print', 'println']
        # txt file to store the raw methods
        apicalls_file = os.path.join(self.all_apicalls_dir, f'{sha256}.txt')
        with open(apicalls_file, 'w') as file:
            # iterate over CG containing the API Calls
            for node in cg.nodes:
                file.write(f'{str(node)}\n')
                _class = node.class_name
                method = node.name
                if self.is_android_apicall(node) and method not in common_methods:
                    package = _class
                    package = package.split("/")
                    _class = package[-1]
                    _class = _class[:-1]
                    _class = _class.replace("$", ".")
                    del package[-1]
                    package = '.'.join(package)
                    package_class = package + '.' + _class + '.' + method
                    in_android_reference = (package in android_packages) and (_class in android_classes)
                    if in_android_reference:
                        if package_class not in apicalls_dict:
                            apicalls_dict[package_class] = 1
                        else:
                            apicalls_dict[package_class] += 1
        # create zip file
        apicalls_zip = os.path.join(self.all_apicalls_dir, f'{sha256}.zip')
        zip_file = zp.ZipFile(apicalls_zip, 'w', zp.ZIP_LZMA)
        zip_file.write(apicalls_file, basename(apicalls_file))
        zip_file.close()
        # remove txt
        os.remove(apicalls_file)
        return apicalls_dict

    def is_android_apicall(self, class_method):
        if not isinstance(class_method, ExternalMethod):
            return False
        # Packages found at https://developer.android.com/reference/packages.html
        # Updated in 2023-05-06
        api_candidates = ["Landroid/", "Ldalvik/", "Ljava/", "Ljavax/", "Lorg/apache/",
                          "Lorg/json/", "Lorg/w3c/dom/", "Lorg/xml/sax", "Lorg/xmlpull/v1/", "Ljunit/"]
        class_name = class_method.class_name
        for candidate in api_candidates:
            if class_name.startswith(candidate):
                return True
        return False

    def extract_apk_data(self, apk_file):
        sha256 = os.path.splitext(basename(apk_file))[0]
        exists_json_metadata = os.path.exists(os.path.join(self.metadata_dir, f'{sha256}.json'))
        exists_json_features = os.path.exists(os.path.join(self.features_dir, f'{sha256}.json'))
        downloaded_file = apk_file.replace('.apk', '.downloaded')
        if exists_json_metadata and exists_json_features:
            print_info(f'{sha256} Already Processed', self.logger)
            if os.path.exists(downloaded_file):
                os.remove(downloaded_file)
            return

        if not os.path.exists(downloaded_file) and self.wait_download:
            try:
                wait_for_file(downloaded_file)
            except Exception as e:
                print_exception(e, 'Wait For File', self.logger)
        if not os.path.exists(apk_file):
            print_error(f'{sha256} Not Downloaded', self.logger)
            return
        print_info(f'Extracting {sha256}', self.logger)
        try:
            f = open(apk_file, 'rb')
            contents = f.read()
        except Exception as e:
            print_exception(e, 'Error Reading File', self.logger)
            #write_log(sha256, type(e).__name__)
            return

        sha256 = hashlib.sha256(contents).hexdigest()
        sha256 = sha256.upper()
        try:
            app, d, dx = AnalyzeAPK(apk_file)
        except Exception as e:
            print_exception(e, f'Error in AnalyzeAPK {apk_file}', self.logger)
            return

        try:
            app_name = app.get_app_name()
        except Exception as e:
            app_name = ''
            print_exception(e, 'App Name Not Found', self.logger)

        try:
            package = app.get_package()
        except Exception as e:
            package = ''
            print_exception(e, 'Package Not Found', self.logger)

        target_sdk = app.get_effective_target_sdk_version()
        try:
            min_sdk = int(app.get_min_sdk_version())
        except Exception as e:
            min_sdk = 0
            print_exception(e, 'Min SDK Exception', self.logger)

        try:
            permissions = list()
            all_permissions = app.get_permissions()
            for permission in all_permissions:
                p = permission.split('.')[-1]
                if p in android_permissions and p not in permissions:
                    permissions.append(p)
        except Exception as e:
            permissions = list()
            print_exception(e, 'Could Not Extract Permissions', self.logger)

        try:
            activities = app.get_activities()
        except Exception as e:
            activities = list()
            print_exception(e, 'Could Not Extract Activities', self.logger)

        try:
            services = app.get_services()
        except Exception as e:
            services = list()
            print_exception(e, 'Could Not Extract Services', self.logger)

        try:
            receivers = app.get_receivers()
        except Exception as e:
            receivers = list()
            print_exception(e, 'Could Not Extract Receivers', self.logger)

        try:
            providers = app.get_providers()
        except Exception as e:
            providers = list()
            print_exception(e, 'Could Not Extract Providers', self.logger)

        try:
            intents = self.get_intents(app)
        except Exception as e:
            intents = list()
            print_exception(e, 'Could Not Extract Intents', self.logger)

        try:
            opcodes = self.get_op_codes(dx)
        except Exception as e:
            opcodes = dict()
            print_exception(e, 'Could Not Extract OpCodes', self.logger)

        try:
            cg = dx.get_call_graph()
            apicalls = self.get_apicalls(cg, sha256)
        except Exception as e:
            apicalls = dict()
            print_exception(e, 'Could Not Extract API Calls', self.logger)

        metadata = [sha256, app_name, package, target_sdk, min_sdk]
        features = [sha256, permissions, activities, services, receivers, providers, intents, opcodes, apicalls]
        id_metadata = ['SHA256', 'APP_NAME', 'PACKAGE', 'TARGET_API', 'MIN_API']
        id_features = ['SHA256', 'PERMISSIONS', 'ACTIVITIES', 'SERVICES', 'RECEIVERS', 'PROVIDERS', 'INTENTS', 'OPCODES', 'APICALLS']

        try:
            # metadata to .json
            json_data = dict()
            for i in range(len(id_metadata)):
                json_data[id_metadata[i]] = metadata[i]
            json_file = os.path.join(self.metadata_dir, f'{sha256}.json')
            save_as_json(json_data, json_file)

            #features to .json
            json_data = dict()
            for i in range(len(id_features)):
                json_data[id_features[i]] = features[i]
            json_file = os.path.join(self.features_dir, f'{sha256}.json')
            save_as_json(json_data, json_file)
            #write_log(sha256, 'extracted')
            print_info(f'Extraction {sha256} Finished', self.logger)
        except Exception as e:
            print_exception(e, 'Exception Writing JSON Files', self.logger)
            #write_log(sha256, type(e).__name__)
        if os.path.exists(downloaded_file):
            os.remove(downloaded_file)

    def extraction_in_parallel(self, apk_file_list):
        with ThreadPoolExecutor(max_workers = self.num_parallel_extraction) as executor:
            executor.map(self.extract_apk_data, apk_file_list)
