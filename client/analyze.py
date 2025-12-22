from client.log_processor import EvaluationLogProcessor
from client.kc_administrator import KcAdministrator

from collections import namedtuple
import json
import matplotlib.pyplot as plotter
import matplotlib.ticker as ticker
import numpy
import os
import pandas
import re as regex
import seaborn
from secret import client_secrets
#import subprocess

RenamePathPair = namedtuple('RenamePathPair', 'old_file_path new_file_path')

class EvaluationAnalyzer:

    def __init__(
            self,
            login_method = None,
            test_length = None,
            number_of_users_used_in_test = None,
            number_of_test_cycles = None,
            path_to_aggregate_data = None,
            path_to_aggregate_user_time = None,
            printer = print,
            printer_args = [],
            printer_kwargs = {}
            ):
        """
        Instantiates an EvaluationAnalyzer
        """
        if not path_to_aggregate_data:
            self.login_method = login_method \
                if login_method \
                and ("saml" in login_method or "oidc" in login_method) \
                else None
            
            self.test_length = test_length \
                if test_length and isinstance(test_length, int) \
                else None
            
            self.number_of_users_used_in_test = number_of_users_used_in_test \
                if number_of_users_used_in_test \
                and isinstance(number_of_users_used_in_test, int) \
                and number_of_users_used_in_test > 0 \
                and number_of_users_used_in_test <= 1000 \
                else None
            
            self.number_of_test_cycles = number_of_test_cycles \
                if number_of_test_cycles \
                and isinstance(number_of_test_cycles, int) \
                and number_of_test_cycles > 0 \
                else None
            
            self.aggregate_data_dict = \
                self.initialize_aggregate_data_dict()
        else:
            self.login_method, \
            self.test_length, \
            self.number_of_users_used_in_test, \
            self.number_of_test_cycles, \
            self.aggregate_data_dict = EvaluationAnalyzer.get_eval_from_json(
                    path_to_aggregate_data
                    )
        
        if not path_to_aggregate_user_time:
            self.aggregate_user_time_dict = \
                self.initialize_aggreate_user_time_dict()
        else:
            self.aggregate_user_time_dict = \
                EvaluationAnalyzer.get_user_time_from_json(
                    path_to_aggregate_user_time
                )

        self.printer = printer
        self.printer_args = printer_args
        self.printer_kwargs = printer_kwargs

##############################################################################
#             E V A L U A T I O N   L O G   P R O C E S S I N G              #
##############################################################################

    @classmethod
    def get_eval_from_json(
            self,
            path_to_aggregate_data
            ):
        
        with open(path_to_aggregate_data, "r") as json_file:
            aggregate_data_dict = json.load(json_file)

        login_method = aggregate_data_dict["login_method"]
        test_length = aggregate_data_dict["test_length"]
        number_of_users_used_in_test = aggregate_data_dict[
            "number_of_users_used_in_test"
            ]
        number_of_test_cycles = aggregate_data_dict["number_of_test_cycles"]
        
        return (login_method, 
            test_length, 
            number_of_users_used_in_test, 
            number_of_test_cycles, 
            aggregate_data_dict
            )
    
    @classmethod
    def get_user_time_from_json(
            self,
            path_to_aggregate_user_time
            ):
        
        with open(path_to_aggregate_user_time, "r") as json_file:
            aggregate_user_time_dict = json.load(json_file)
        
        return aggregate_user_time_dict


    def initialize_aggregate_data_dict(self):
        
        if not self.login_method \
            or not self.test_length \
            or not self.number_of_users_used_in_test:
            return None

        aggregate_data_dict = {
            "login_method": self.login_method,
            "test_length": self.test_length,
            "number_of_users_used_in_test": self.number_of_users_used_in_test,
            "number_of_test_cycles": self.number_of_test_cycles,
            "data": {}
        }
        
        data = aggregate_data_dict["data"]
        if self.login_method == "oidc":
            for test_user_id in range(1, self.number_of_users_used_in_test+1):
                data[f"t_user_{test_user_id}"] = {
                    "redirect_time": [],
                    "get_access_token_time": [],
                    "decode_id_token_time": [],
                    "complete_login_time": [],
                    "dispatch_time": [],
                    "failed_measurements": 0,
                    "failed_measurement_ids": []
                }
        else:
            for test_user_id in range(1, self.number_of_users_used_in_test+1):
                data[f"t_user_{test_user_id}"] = {
                    "redirect_time": [],
                    "build_auth_time": [],
                    "login_time": [],
                    "acs_dispatch_time": [],
                    "finish_acs_dispatch_time": [],
                    "failed_measurements": 0,
                    "failed_measurement_ids": []
                }

        return aggregate_data_dict
    

    def initialize_aggreate_user_time_dict(self):

        aggregate_user_data_dict = {
            "data": {}
        }

        data = aggregate_user_data_dict["data"]
        for test_user_id in range(1, self.number_of_users_used_in_test+1):
            data[f"t_user_{test_user_id}"] = {
                "total_login_time": [],
                "login_start_time": [],
                "login_finish_time": [],
                "protected_resource": [],
                "failed_measurements": 0,
                "failed_measurement_ids": []
            }

        return aggregate_user_data_dict


    def get_log_key_set(self):
        if self.login_method == "oidc":
            return set(
                [
                    "redirect_time",
                    "pkce_time",
                    "get_access_token_time",
                    "decode_id_token_time",
                    "complete_login_time",
                    "dispatch_time"
                ]
            )
        elif self.login_method == "saml":
            return set(
                [
                    "redirect_time",
                    "build_auth_time",
                    "login_time",
                    "acs_dispatch_time",
                    "finish_acs_dispatch_time"
                ]
            )      


    def populate_aggregate_data_dict(self, log_data, log_file_name):
        data = self.aggregate_data_dict["data"]
        log_key_set = self.get_log_key_set()
        test_users = set(test_user for test_user in log_data.keys())
        for test_user_id in range(1, self.number_of_users_used_in_test+1):
            test_user = f"t_user_{test_user_id}"
            # This is only the case if the user was never redirected.
            if test_user not in test_users:
                data[test_user]["failed_measurements"] += 1
                data[test_user]["failed_measurement_ids"].append(
                    log_file_name
                )
                continue
            
            test_user_keys = set(key for key in log_data[test_user].keys())
            # This happens if the user failed to log in due to some website
            # error or other reasons.
            if not test_user_keys == log_key_set:
                data[test_user]["failed_measurements"] += 1
                data[test_user]["failed_measurement_ids"].append(
                    log_file_name
                )
                continue

            data[test_user]["redirect_time"].append(
                log_data[test_user]["redirect_time"]
                )
            
            if self.login_method == "oidc":
                data[test_user]["get_access_token_time"].append(
                    log_data[test_user]["get_access_token_time"]
                )
                data[test_user]["decode_id_token_time"].append(
                    log_data[test_user]["decode_id_token_time"]
                )
                data[test_user]["complete_login_time"].append(
                    log_data[test_user]["complete_login_time"]
                )
                data[test_user]["dispatch_time"].append(
                    log_data[test_user]["dispatch_time"]
                )
            else:
                data[test_user]["build_auth_time"].append(
                    log_data[test_user]["build_auth_time"]
                )
                data[test_user]["login_time"].append(
                    log_data[test_user]["login_time"]
                )
                data[test_user]["acs_dispatch_time"].append(
                    log_data[test_user]["acs_dispatch_time"]
                )
                data[test_user]["finish_acs_dispatch_time"].append(
                    log_data[test_user]["finish_acs_dispatch_time"]
                )

    def get_user_key_set(self):
        return set(
            [
                "login_start_time",
                "login_finish_time",
                "protected_resource"
            ]
        )
    
    def get_protected_resource_allowed_values(self):
        return set(
            [
                "You won the game!",
                "You lost the game!"
            ]
        )

    def populate_aggregate_user_time_dict(self, user_time_data, log_file_name):
        data = self.aggregate_user_time_dict["data"]
        user_key_set = self.get_user_key_set()
        protected_resource_allowed_values = \
            self.get_protected_resource_allowed_values()
        test_users = set(test_user for test_user in user_time_data.keys())
        for test_user_id in range(1, self.number_of_users_used_in_test+1):
            test_user = f"t_user_{test_user_id}"
            if test_user not in test_users:
                data[test_user]["failed_measurements"] += 1
                data[test_user]["failed_measurement_ids"].append(
                    log_file_name
                )
                continue

            test_user_keys = set(key for key in user_time_data[test_user].keys())
            if not test_user_keys == user_key_set:
                data[test_user]["failed_measurements"] += 1
                data[test_user]["failed_measurement_ids"].append(
                    log_file_name
                )
                continue

            if user_time_data[test_user]["protected_resource"] not in \
                protected_resource_allowed_values:
                data[test_user]["failed_measurements"] += 1
                data[test_user]["failed_measurement_ids"].append(
                    log_file_name
                )
                continue

            data[test_user]["login_start_time"].append(
                user_time_data[test_user]["login_start_time"]
            )
            data[test_user]["login_finish_time"].append(
                user_time_data[test_user]["login_finish_time"]
            )
            data[test_user]["total_login_time"].append(
                user_time_data[test_user]["login_finish_time"] -\
                user_time_data[test_user]["login_start_time"]
            )
            data[test_user]["protected_resource"].append(
                user_time_data[test_user]["protected_resource"]
            )

    def read_serialized_log(self, path_to_json):
        with open(path_to_json, "r") as json_file:
            log_data = json.load(json_file)
        
        return log_data
    

    def read_all_serialized_eval_logs_for_current_eval(self):
        local_json_file_pattern = regex.compile(
            f"{self.login_method}-eval-{self.test_length}-" \
            f"{self.number_of_users_used_in_test}" \
            f"{r'-\d+\.json'}"
            )

        for file_name in os.listdir(client_secrets.LOG_STORAGE_PATH):
            if local_json_file_pattern.match(file_name):
                log_data = self.read_serialized_log(
                    f"{client_secrets.LOG_STORAGE_PATH}/{file_name}"
                )
                self.populate_aggregate_data_dict(log_data, file_name)
                print(file_name)


    def read_all_serialized_user_time_logs_for_current_eval(self):
        local_json_file_pattern = regex.compile(
            f"{self.login_method}-eval-{self.test_length}-" \
            f"{self.number_of_users_used_in_test}-user-time" \
            f"{r'-\d+\.json'}"
            )
        for file_name in os.listdir(client_secrets.LOG_STORAGE_PATH):
            if local_json_file_pattern.match(file_name):
                user_time_data = self.read_serialized_log(
                    f"{client_secrets.LOG_STORAGE_PATH}/{file_name}"
                )
                self.populate_aggregate_user_time_dict(user_time_data, file_name)
                print(file_name)

    # restore aggregate data function
    def res_aggr(self, eval_stor):
        local_json_file_pattern = regex.compile(
            f"{self.login_method}-eval-{self.test_length}-" \
            f"{self.number_of_users_used_in_test}-user-time" \
            f"{r'-\d+\.json'}"
            )
        
        for file_name in os.listdir(f"{client_secrets.LOG_STORAGE_PATH}/{eval_stor}/user-time-data"):
            if local_json_file_pattern.match(file_name):
                user_time_data = self.read_serialized_log(
                    f"{client_secrets.LOG_STORAGE_PATH}/{eval_stor}/user-time-data/{file_name}"
                )
                self.populate_aggregate_user_time_dict(user_time_data, file_name)
                print(file_name)
        
        path_to_aggregate_json = "" \
            f"{client_secrets.LOG_STORAGE_PATH}/{eval_stor}/user-time-data/" \
            f"{self.login_method}-eval-{self.test_length}-" \
            f"{self.number_of_users_used_in_test}-user-time-aggregate.json"
        
        with open(path_to_aggregate_json, "w") as json_file:
            json.dump(self.aggregate_user_time_dict, json_file, indent = 4)


        local_json_file_pattern = regex.compile(
            f"{self.login_method}-eval-{self.test_length}-" \
            f"{self.number_of_users_used_in_test}" \
            f"{r'-\d+\.json'}"
            )

        for file_name in os.listdir(f"{client_secrets.LOG_STORAGE_PATH}/{eval_stor}"):
            if local_json_file_pattern.match(file_name):
                data = self.read_serialized_log(
                    f"{client_secrets.LOG_STORAGE_PATH}/{eval_stor}/{file_name}"
                )
                self.populate_aggregate_data_dict(data, file_name)
                print(file_name)

        path_to_aggregate_json = "" \
            f"{client_secrets.LOG_STORAGE_PATH}/{eval_stor}/" \
            f"{self.login_method}-eval-{self.test_length}-" \
            f"{self.number_of_users_used_in_test}-aggregate.json"

        with open(path_to_aggregate_json, "w") as json_file:
            json.dump(self.aggregate_data_dict, json_file, indent = 4)



    def serialize_aggregate_data_dict(self):
        path_to_aggregate_json = "" \
            f"{client_secrets.LOG_STORAGE_PATH}/" \
            f"{self.login_method}-eval-{self.test_length}-" \
            f"{self.number_of_users_used_in_test}-aggregate.json"
        
        with open(path_to_aggregate_json, "w") as json_file:
            json.dump(self.aggregate_data_dict, json_file, indent = 4)


    def serialize_aggregate_user_time_data_dict(self):
        path_to_aggregate_json = "" \
            f"{client_secrets.LOG_STORAGE_PATH}/" \
            f"{self.login_method}-eval-{self.test_length}-" \
            f"{self.number_of_users_used_in_test}-user-time-aggregate.json"
        
        with open(path_to_aggregate_json, "w") as json_file:
            json.dump(self.aggregate_user_time_dict, json_file, indent = 4)


    # DEPRECATED
    #def get_eval_id_from_folder_name(self, folder_name):
    #    return int(folder_name.split("-")[-1])
    
    def create_eval_storage_folders(self):
        
        subdirectory_list = os.listdir(client_secrets.LOG_STORAGE_PATH)
        storage_directory_pattern = regex.compile(
            f"analyze_evalstorage_{self.login_method}-eval-" \
            f"{self.test_length}-{self.number_of_users_used_in_test}" \
            f"{r'-\d+'}"
            )
        
        evaluation_id = 1
        for subdirectory in subdirectory_list:
            if storage_directory_pattern.match(subdirectory):
                evaluation_id += 1

        # This logic is flawed when different evalstorages are created.
        #*_, last_subdirectory = os.walk(client_secrets.LOG_STORAGE_PATH)
        #last_subdirectory_name = last_subdirectory[0]
        #evaluation_id = 0
        #if "eval" not in last_subdirectory_name:
        #    evaluation_id = 1
        #else:
        #    evaluation_id = self.get_eval_id_from_folder_name(
        #        last_subdirectory_name
        #        )
        #    evaluation_id += 1
        
        storage_directory_name = f"analyze_evalstorage_{self.login_method}-" \
            f"eval-{self.test_length}-{self.number_of_users_used_in_test}-" \
            f"{evaluation_id}"
        
        #self.printer(f"{client_secrets.LOG_STORAGE_PATH}/{storage_directory_name}")

        os.mkdir(
            f"{client_secrets.LOG_STORAGE_PATH}/{storage_directory_name}"
        )
        os.mkdir(
            f"{client_secrets.LOG_STORAGE_PATH}/{storage_directory_name}"\
            "/sp-resmon-data"
        )
        os.mkdir(
            f"{client_secrets.LOG_STORAGE_PATH}/{storage_directory_name}"\
            "/idp-resmon-data"
        )
        os.mkdir(
            f"{client_secrets.LOG_STORAGE_PATH}/{storage_directory_name}"\
            "/user-time-data"
        )

        return storage_directory_name


    def get_path_pairs_for_rename(
            self, 
            storage_directory_name
            ):
        path_pair_list = []
        for name in os.listdir(f"{client_secrets.LOG_STORAGE_PATH}"):
            if not (
                name.endswith(".json") or 
                name.endswith(".log") or 
                name.endswith(".txt")
                ):
                continue
            
            if "eval_info" in name \
                or (not "resmon" in name and not "user" in name):
                path_pair_list.append(
                    RenamePathPair(
                        f"{client_secrets.LOG_STORAGE_PATH}/{name}",
                        f"{client_secrets.LOG_STORAGE_PATH}/" \
                        f"{storage_directory_name}/{name}"
                    )
                )
            elif "sp" in name and not "user" in name:
                path_pair_list.append(
                    RenamePathPair(
                        f"{client_secrets.LOG_STORAGE_PATH}/{name}",
                        f"{client_secrets.LOG_STORAGE_PATH}/" \
                        f"{storage_directory_name}/sp-resmon-data/" \
                        f"{name}"
                    )
                )
            elif "idp" in name and not "user" in name:
                path_pair_list.append(
                    RenamePathPair(
                        f"{client_secrets.LOG_STORAGE_PATH}/{name}",
                        f"{client_secrets.LOG_STORAGE_PATH}/" \
                        f"{storage_directory_name}/idp-resmon-data/" \
                        f"{name}"
                    )
                )
            elif "user" in name:
                path_pair_list.append(
                    RenamePathPair(
                        f"{client_secrets.LOG_STORAGE_PATH}/{name}",
                        f"{client_secrets.LOG_STORAGE_PATH}/" \
                        f"{storage_directory_name}/user-time-data/" \
                        f"{name}"
                    )
                )                

        
        return path_pair_list


    def move_eval_data_to_storage(self):
        storage_directory_name = self.create_eval_storage_folders()
        path_pair_list = self.get_path_pairs_for_rename(
            storage_directory_name
            )
        
        for path_pair in path_pair_list:
            old_file_path, new_file_path = path_pair
            os.rename(old_file_path, new_file_path)


    def get_aggregate_data(self):
        self.read_all_serialized_eval_logs_for_current_eval()
        self.read_all_serialized_user_time_logs_for_current_eval()
        self.serialize_aggregate_data_dict()
        self.serialize_aggregate_user_time_data_dict()
        self.move_eval_data_to_storage()

    @classmethod
    def negligibility_read(self):
        evals = 10
        path = f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_saml-eval-1-1-1"
        ptime_cpu_diffs = {
            "eval_slice": [],
            "nginx": [],
            "gunicorn": []
        }
        ptime_ram_diffs = {
            "eval_slice": {
                "total": [],
                "anon": [],
                "file": [],
                "kernel": [],
            },
            "nginx": {
                "total": [],
                "anon": [],
                "file": [],
                "kernel": [],
            },
            "gunicorn": {
                "total": [],
                "anon": [],
                "file": [],
                "kernel": [],
            }
        }
        ptime_io_diffs = {
            "eval_slice": {},
            "nginx": {},
            "gunicorn": {}
        }
        log_cpu_diffs = {
            "eval_slice": [],
            "nginx": [],
            "gunicorn": []
        }
        log_ram_diffs = {
            "eval_slice": {
                "total": [],
                "anon": [],
                "file": [],
                "kernel": [],
            },
            "nginx": {
                "total": [],
                "anon": [],
                "file": [],
                "kernel": [],
            },
            "gunicorn": {
                "total": [],
                "anon": [],
                "file": [],
                "kernel": [],
            }
        }
        log_io_diffs = {
            "eval_slice": {},
            "nginx": {},
            "gunicorn": {}
        }
        for eval in range(1,evals+1):
            log_file_name = f"saml-eval-1-1-{eval}.log"
            resmon_file_loc = f"sp-resmon-data/saml-eval-1-1-sp-resmon-{eval}.json"
            ptime_sts = 0
            ptime_ets = 0
            log_sts = 0
            log_ets = 0
            with open(f"{path}/{log_file_name}") as log_file:
                for line in log_file:
                    if "START PROCESS TIME" in line:
                        ptime_sts = int(line.split(" ")[-1])
                        continue
                    elif "END PROCESS TIME" in line:
                        ptime_ets = int(line.split(" ")[-1])
                        continue
                    elif "START LOGGING TIME" in line:
                        log_sts = int(line.split(" ")[-1])
                        continue
                    elif "END LOGGING TIME" in line:
                        log_ets = int(line.split(" ")[-1])
                        continue
            timestamps = (ptime_sts, ptime_ets, log_sts, log_ets)
            with open(f"{path}/{resmon_file_loc}", "r") as json_file:
                resmon_data = json.load(json_file)
                eval_slice = resmon_data["eval.slice"]
                nginx = resmon_data["nginx"]
                gunicorn = resmon_data["gunicorn"]
                eval_slice_res_ts = {
                    "cpu_ts": EvaluationAnalyzer.get_ts(eval_slice, "cpu", timestamps),
                    "ram_ts": EvaluationAnalyzer.get_ts(eval_slice, "memory", timestamps),
                    "ios_ts": EvaluationAnalyzer.get_ts(eval_slice, "io", timestamps)
                }
                print(eval_slice_res_ts)
                for device in eval_slice_res_ts["ios_ts"].keys():
                    print(f"DEVICE = {device}")
                    if device not in ptime_io_diffs["eval_slice"].keys():
                        ptime_io_diffs["eval_slice"][device] = {
                            "read": [],
                            "write": [],
                            "rios": [],
                            "wios": []
                        }
                        log_io_diffs["eval_slice"][device] = {
                            "read": [],
                            "write": [],
                            "rios": [],
                            "wios": []
                        }
                EvaluationAnalyzer.populate_ptime_diffs(eval_slice, "eval_slice", eval_slice_res_ts, ptime_cpu_diffs, ptime_ram_diffs, ptime_io_diffs)
                EvaluationAnalyzer.populate_log_diffs(eval_slice, "eval_slice", eval_slice_res_ts, log_cpu_diffs, log_ram_diffs, log_io_diffs)
                
                nginx_res_ts = {
                    "cpu_ts": EvaluationAnalyzer.get_ts(nginx, "cpu", timestamps),
                    "ram_ts": EvaluationAnalyzer.get_ts(nginx, "memory", timestamps),
                    "ios_ts": EvaluationAnalyzer.get_ts(nginx, "io", timestamps)
                }
                for device in nginx_res_ts["ios_ts"].keys():
                    print(f"DEVICE = {device}")
                    if device not in ptime_io_diffs["nginx"].keys():
                        ptime_io_diffs["nginx"][device] = {
                            "read": [],
                            "write": [],
                            "rios": [],
                            "wios": []
                        }
                        log_io_diffs["nginx"][device] = {
                            "read": [],
                            "write": [],
                            "rios": [],
                            "wios": []
                        }

                EvaluationAnalyzer.populate_ptime_diffs(nginx, "nginx", nginx_res_ts, ptime_cpu_diffs, ptime_ram_diffs, ptime_io_diffs)
                EvaluationAnalyzer.populate_log_diffs(nginx, "nginx", nginx_res_ts, log_cpu_diffs, log_ram_diffs, log_io_diffs)

                gunicorn_res_ts = {
                    "cpu_ts": EvaluationAnalyzer.get_ts(gunicorn, "cpu", timestamps),
                    "ram_ts": EvaluationAnalyzer.get_ts(gunicorn, "memory", timestamps),
                    "ios_ts": EvaluationAnalyzer.get_ts(gunicorn, "io", timestamps)
                }
                for device in gunicorn_res_ts["ios_ts"].keys():
                    print(f"DEVICE = {device}")
                    if device not in ptime_io_diffs["gunicorn"].keys():
                        ptime_io_diffs["gunicorn"][device] = {
                            "read": [],
                            "write": [],
                            "rios": [],
                            "wios": []
                        }
                        log_io_diffs["gunicorn"][device] = {
                            "read": [],
                            "write": [],
                            "rios": [],
                            "wios": []
                        }
                EvaluationAnalyzer.populate_ptime_diffs(gunicorn, "gunicorn", gunicorn_res_ts, ptime_cpu_diffs, ptime_ram_diffs, ptime_io_diffs)
                EvaluationAnalyzer.populate_log_diffs(gunicorn, "gunicorn", gunicorn_res_ts, log_cpu_diffs, log_ram_diffs, log_io_diffs)

        diff_dict = {
            "ptime_cpu_diffs": ptime_cpu_diffs,
            "ptime_ram_diffs": ptime_ram_diffs,
            "ptime_io_diffs": ptime_io_diffs,
            "log_cpu_diffs": log_cpu_diffs,
            "log_ram_diffs": log_ram_diffs,
            "log_io_diffs": log_io_diffs
        }

        with open(f"{path}/negligibility.json", "w") as json_file:
            json.dump(diff_dict, json_file, indent = 4)


    @classmethod
    def populate_ptime_diffs(self, cgroup, cgroup_name, cgroup_ts, ptime_cpu_diffs, ptime_ram_diffs, ptime_io_diffs):
        ptime_cpu_diffs[cgroup_name].append(
            cgroup["cpu"]["total_cpu_time"][cgroup_ts["cpu_ts"][1]] - cgroup["cpu"]["total_cpu_time"][cgroup_ts["cpu_ts"][0]]
            )
        ptime_ram_diffs[cgroup_name]["total"].append(
            cgroup["memory"]["total_memory_usage"][cgroup_ts["ram_ts"][1]] - cgroup["memory"]["total_memory_usage"][cgroup_ts["ram_ts"][0]]
            )
        ptime_ram_diffs[cgroup_name]["anon"].append(
            cgroup["memory"]["anonymous_memory"][cgroup_ts["ram_ts"][1]] - cgroup["memory"]["anonymous_memory"][cgroup_ts["ram_ts"][0]]
            )
        ptime_ram_diffs[cgroup_name]["file"].append(
            cgroup["memory"]["file_system_cache_memory"][cgroup_ts["ram_ts"][1]] - cgroup["memory"]["file_system_cache_memory"][cgroup_ts["ram_ts"][0]]
            )
        ptime_ram_diffs[cgroup_name]["kernel"].append(
            cgroup["memory"]["kernel_memory"][cgroup_ts["ram_ts"][1]] - cgroup["memory"]["kernel_memory"][cgroup_ts["ram_ts"][0]]
            )
        for device in cgroup_ts["ios_ts"].keys():
            ptime_io_diffs[cgroup_name][device]["read"].append(
                cgroup["io"][device]["read_bytes"][cgroup_ts["ios_ts"][device][1]] - cgroup["io"][device]["read_bytes"][cgroup_ts["ios_ts"][device][0]]
            )
            ptime_io_diffs[cgroup_name][device]["write"].append(
                cgroup["io"][device]["written_bytes"][cgroup_ts["ios_ts"][device][1]] - cgroup["io"][device]["written_bytes"][cgroup_ts["ios_ts"][device][0]]
            )
            ptime_io_diffs[cgroup_name][device]["rios"].append(
                cgroup["io"][device]["read_io_ops"][cgroup_ts["ios_ts"][device][1]] - cgroup["io"][device]["read_io_ops"][cgroup_ts["ios_ts"][device][0]]
            )
            ptime_io_diffs[cgroup_name][device]["wios"].append(
                cgroup["io"][device]["write_io_ops"][cgroup_ts["ios_ts"][device][1]] - cgroup["io"][device]["write_io_ops"][cgroup_ts["ios_ts"][device][0]]
            )
        
    @classmethod
    def populate_log_diffs(self, cgroup, cgroup_name, cgroup_ts, log_cpu_diffs, log_ram_diffs, log_io_diffs):
        log_cpu_diffs[cgroup_name].append(
            cgroup["cpu"]["total_cpu_time"][cgroup_ts["cpu_ts"][3]] - cgroup["cpu"]["total_cpu_time"][cgroup_ts["cpu_ts"][2]]
            )
        log_ram_diffs[cgroup_name]["total"].append(
            cgroup["memory"]["total_memory_usage"][cgroup_ts["ram_ts"][3]] - cgroup["memory"]["total_memory_usage"][cgroup_ts["ram_ts"][2]]
            )
        log_ram_diffs[cgroup_name]["anon"].append(
            cgroup["memory"]["anonymous_memory"][cgroup_ts["ram_ts"][3]] - cgroup["memory"]["anonymous_memory"][cgroup_ts["ram_ts"][2]]
            )
        log_ram_diffs[cgroup_name]["file"].append(
            cgroup["memory"]["file_system_cache_memory"][cgroup_ts["ram_ts"][3]] - cgroup["memory"]["file_system_cache_memory"][cgroup_ts["ram_ts"][2]]
            )
        log_ram_diffs[cgroup_name]["kernel"].append(
            cgroup["memory"]["kernel_memory"][cgroup_ts["ram_ts"][3]] - cgroup["memory"]["kernel_memory"][cgroup_ts["ram_ts"][2]]
            )
        for device in cgroup_ts["ios_ts"].keys():
            log_io_diffs[cgroup_name][device]["read"].append(
                cgroup["io"][device]["read_bytes"][cgroup_ts["ios_ts"][device][3]] - cgroup["io"][device]["read_bytes"][cgroup_ts["ios_ts"][device][2]]
            )
            log_io_diffs[cgroup_name][device]["write"].append(
                cgroup["io"][device]["written_bytes"][cgroup_ts["ios_ts"][device][3]] - cgroup["io"][device]["written_bytes"][cgroup_ts["ios_ts"][device][2]]
            )
            log_io_diffs[cgroup_name][device]["rios"].append(
                cgroup["io"][device]["read_io_ops"][cgroup_ts["ios_ts"][device][3]] - cgroup["io"][device]["read_io_ops"][cgroup_ts["ios_ts"][device][2]]
            )
            log_io_diffs[cgroup_name][device]["wios"].append(
                cgroup["io"][device]["write_io_ops"][cgroup_ts["ios_ts"][device][3]] - cgroup["io"][device]["write_io_ops"][cgroup_ts["ios_ts"][device][2]]
            )


    @classmethod
    def get_ts(self, cgroup, resource, timestamps):
        if resource == "io":
            dev_ts = {}
            for device in cgroup["io"].keys():
                dev_ptime_sts = next(index for index, value in enumerate(cgroup["io"][device]["timestamps"]) if value > timestamps[0])-1
                dev_ptime_ets = next(index for index, value in enumerate(cgroup["io"][device]["timestamps"]) if value > timestamps[1])+20
                dev_log_sts = next(index for index, value in enumerate(cgroup["io"][device]["timestamps"]) if value > timestamps[2])-1
                #dev_log_ets = next(index for index, value in enumerate(cgroup["io"][device]["timestamps"]) if value > timestamps[3])+20
                # It is assumed, that the log is only really written to file once the redirect ends.
                dev_log_ets = len(cgroup["io"][device]["timestamps"])-1
                dev_ts[device] = [dev_ptime_sts, dev_ptime_ets, dev_log_sts, dev_log_ets]
            return dev_ts
        # 1st Timestamp before the measurement started
        res_ptime_sts = next(index for index, value in enumerate(cgroup[f"{resource}"]["timestamps"]) if value > timestamps[0])-1
        # Last Timestamp that captures the measurement + the measurements of 2 slept seconds
        res_ptime_ets = next(index for index, value in enumerate(cgroup[f"{resource}"]["timestamps"]) if value > timestamps[1])+20
        # 1st Timestamp before the measurement started. There will be overlap
        res_log_sts = next(index for index, value in enumerate(cgroup[f"{resource}"]["timestamps"]) if value > timestamps[2])-1
        # Last Timestamp that captures the measurement + the measurements of 2 slept seconds
        res_log_ets = next(index for index, value in enumerate(cgroup[f"{resource}"]["timestamps"]) if value > timestamps[3])+20
        return [res_ptime_sts, res_ptime_ets, res_log_sts, res_log_ets]


##############################################################################
#                              A N A L Y S I S                               #
##############################################################################
    
    def get_failed_measurement_ids(self, test_user, aggregate_type):
        if aggregate_type == "normal":
            failed_measurements = self.aggregate_data_dict["data"][test_user]\
                ["failed_measurement_ids"]
        else:
            failed_measurements = self.aggregate_user_time_dict["data"]\
                [test_user]["failed_measurement_ids"] 
        ids = []

        for failed_measurement in failed_measurements:
            # Every failed measurement has the following form:
            # <login_method>-eval-<test_time>-<users>-<id>.json
            # For user measurements a user-time is added before the id. This
            # means that this function works for both use cases.
            ids.append(int(failed_measurement.split("-")[-1].split(".")[0]))
        
        return ids


    def get_aggregate_user_data_as_dataframe(self, eval_id):
        user_ids = [
            user_id for user_id in range(
                1, self.number_of_users_used_in_test + 1
                )
            ]
        
        test_ids = [
                [
                test_id for test_id in range(
                    1, self.number_of_test_cycles + 1
                    )
                ] for _ in range(1, self.number_of_users_used_in_test+1)
            ]

        data = self.aggregate_user_time_dict["data"]
        test_user_data = []
        for user_id in range(1, self.number_of_users_used_in_test + 1):
            user_failed_measurements = self.get_failed_measurement_ids(
                f"t_user_{user_id}",
                "user"
                )
            wanted_data = data[f"t_user_{user_id}"]["total_login_time"]
            for failed_measurement_id in user_failed_measurements:
                wanted_data.insert(failed_measurement_id-1, None)

            test_user_data.append(wanted_data)
        
        frame = {
            'users': user_ids,
            'tests': test_ids,
            'measurements': test_user_data,
            'eval': eval_id
            }
        dataframe = pandas.DataFrame(frame)
        #indexed_dataframe = dataframe.set_index('users')
        #exploded_dataframe = indexed_dataframe.explode(
        #    ['tests', 'measurements']
        #    )
        exploded_dataframe = dataframe.explode(
            ['tests', 'measurements']
            )
        return exploded_dataframe


    def get_aggregate_data_as_dataframe(
        self, 
        aggregate_data_key,
        eval_id
        ):
        if self.login_method == "oidc" \
            and not "redirect_time" in aggregate_data_key \
            and not "get_access_token_time" in aggregate_data_key \
            and not "decode_id_token_time" in aggregate_data_key \
            and not "complete_login_time" in aggregate_data_key \
            and not "dispatch_time" in aggregate_data_key:
            return None
        elif self.login_method == "saml" \
            and not "redirect_time" in aggregate_data_key \
            and not "build_auth_time" in aggregate_data_key \
            and not "login_time" in aggregate_data_key \
            and not "acs_dispatch_time" in aggregate_data_key \
            and not "finish_acs_dispatch_time" in aggregate_data_key:
            return None
        
        user_ids = [
            user_id for user_id in range(
                1, self.number_of_users_used_in_test + 1
                )
            ]
        
        test_ids = [
                [
                test_id for test_id in range(
                    1, self.number_of_test_cycles + 1
                    )
                ] for _ in range(1, self.number_of_users_used_in_test+1)
            ]
        
        data = self.aggregate_data_dict["data"]
        test_user_data = []
        for user_id in range(1, self.number_of_users_used_in_test + 1):
            user_failed_measurements = self.get_failed_measurement_ids(
                f"t_user_{user_id}",
                "normal"
                )
            wanted_data = data[f"t_user_{user_id}"][aggregate_data_key]

            for failed_measurement_id in user_failed_measurements:
                wanted_data.insert(failed_measurement_id-1, None)

            test_user_data.append(wanted_data)
        
        frame = {
            'users': user_ids,
            'tests': test_ids,
            'measurements': test_user_data,
            'eval': eval_id,
            'function': aggregate_data_key,
            }
        dataframe = pandas.DataFrame(frame)
        #indexed_dataframe = dataframe.set_index('users')
        #exploded_dataframe = indexed_dataframe.explode(
        #    ['tests', 'measurements']
        #    )
        exploded_dataframe = dataframe.explode(
            ['tests', 'measurements']
            )
        return exploded_dataframe

    # The DataFrame should be indexed by users and should already be exploded
    def plot_by_user(
            self,
            data_frame,
            plot_title,
            plot_type = "box",
            ylim_bottom = None,
            ylim_top = None,
            y_ticks = None
            ):
        #data = self.get_aggregate_data_as_numpy_array(aggregate_data_key)
        #data_frame = self.get_aggregate_data_as_dataframe(
        #    aggregate_data_key
        #    )
        #data_frame_exp = data_frame.explode('Time')
        #seaborn.cubehelix_palette(start=2.0, rot=-1.0, as_cmap=True)
        if plot_type == "box":
            #seaborn.catplot(
            #    data = data_frame,
            #    x = 'users',
            #    y = 'measurements',
            #    hue = 'users',
            #    #palette = seaborn.color_palette("flare", as_cmap=True),
            #    palette = seaborn.light_palette('#9163cb', as_cmap=True),
            #    kind = "box"
            #    ).set(
            #        title = plot_title
            #    )
            ax = seaborn.boxplot(
                data = data_frame,
                x = 'users',
                y = 'measurements',
                hue = 'users',
                #whis = (0,100),
                #palette = seaborn.color_palette("flare", as_cmap=True),
                palette = seaborn.light_palette('#9163cb', as_cmap=True)
                ).set(
                    title = plot_title
                )

        if plot_type == "line":
            seaborn.lineplot(
                data = data_frame,
                x = 'users',
                y = 'measurements',
                estimator="mean",
                errorbar=('pi', 95)#,
                #n_boot=5000,
                #seed=6111612
                ).set(
                    title = plot_title
                )
        #seaborn.set_style("whitegrid")
        #print(data_frame_exp.head())
        plotter.grid(axis='y')
        if ylim_bottom and ylim_top:
            plotter.ylim(ylim_bottom, ylim_top)
            if y_ticks:
                # y_ticks + 1 must be done here, because the endpoint is
                # included. If y_ticks were to be used, the linspace would
                # actually be calculated over 19 values.
                plotter.yticks(
                    numpy.linspace(ylim_bottom, ylim_top, y_ticks+1)
                    )

        plotter.show()
        #plotter.autoscale(tight=True)
        #plotter.autoscale()

    @classmethod
    def compare_measurements_by_user(
            self,
            path_to_aggregates,
            plot_title,
            y_label,
            aggregate_type = None,
            aggregate_data_key = None,
            num_users = None,
            num_cycles = None,
            ylim_bottom = None,
            ylim_top = None,
            y_ticks = None
            ):
        if not aggregate_type \
            or (aggregate_type == "normal" and not aggregate_data_key) \
            or (aggregate_type != "normal" and aggregate_type != "user"):
            print("aggregate type failure")
            return
        
        if aggregate_type == "user" and (not num_users or not num_cycles):
            print("usr or testnum fail")
            return

        data_frames = []
        for path_to_aggregate in path_to_aggregates:
            if aggregate_type == "normal":
                analyzer = EvaluationAnalyzer(
                    path_to_aggregate_data = path_to_aggregate
                    )
            else:
                analyzer = EvaluationAnalyzer(
                    number_of_users_used_in_test=num_users,
                    number_of_test_cycles=num_cycles,
                    path_to_aggregate_user_time=path_to_aggregate
                )
            
            if aggregate_type == "normal":
                eval_id = path_to_aggregate.split("/")[-2].split("_")[-1]
            else:
                eval_id = path_to_aggregate.split("/")[-3].split("_")[-1]
            
            if eval_id in client_secrets.EVAL_ID_LOOKUP.keys():
                eval_id = client_secrets.EVAL_ID_LOOKUP[eval_id]
            if aggregate_type == "normal":
                if not isinstance(aggregate_data_key, list):
                    data_frames.append(
                            analyzer.get_aggregate_data_as_dataframe(
                                aggregate_data_key,
                                eval_id
                            )
                        )
                else:
                    for key in aggregate_data_key:
                        data_frames.append(
                            analyzer.get_aggregate_data_as_dataframe(
                                key,
                                eval_id
                            )
                        )
            else:
                data_frames.append(
                        analyzer.get_aggregate_user_data_as_dataframe(
                            eval_id
                        )
                    )
        
        fig, ax = plotter.subplots()
        concat_data_frame = pandas.concat(data_frames, ignore_index=True)
        #for data_frame in data_frames:
        if not isinstance(aggregate_data_key, list):
            plot_ax = seaborn.lineplot(
                data = concat_data_frame,
                #ax = ax,
                hue = 'eval',
                x = 'users',
                y = 'measurements',
                #palette = seaborn.color_palette("Paired"),
                estimator="mean",
                errorbar=('ci', 95), #ci möglich
                n_boot=5000,
                seed=6111612
                )
        else: 
            plot_ax = seaborn.lineplot(
                data = concat_data_frame,
                #ax = ax,
                hue = 'function',
                x = 'users',
                y = 'measurements',
                #palette = seaborn.color_palette("Paired"),
                estimator="mean",
                errorbar=('ci', 95),
                n_boot=5000,
                seed=6111612
                )
        plot_ax.set(
                title = plot_title
            )
        plot_ax.set_xlabel("User IDs")
        plot_ax.set_ylabel(y_label)
        ax.legend()
        if num_users:
            #print(int(num_users/5)+1)
            ax.xaxis.set_major_locator(ticker.MultipleLocator(10))
            ax.xaxis.set_minor_locator(ticker.MultipleLocator(2))
        else:
            ax.xaxis.set_major_locator(ticker.AutoLocator())
            ax.xaxis.set_minor_locator(ticker.AutoMinorLocator())
        plotter.grid(axis='y')
        if ylim_bottom and ylim_top:
            plotter.ylim(ylim_bottom, ylim_top)
            if y_ticks:
                # y_ticks + 1 must be done here, because the endpoint is
                # included. If y_ticks were to be used, the linspace would
                # actually be calculated over 19 values.
                plotter.yticks(
                    numpy.linspace(ylim_bottom, ylim_top, y_ticks+1)
                    )
        
        plotter.show()

    # This calculates the change rate of a resource over time.
    # For the CPU Resource this function determines where the CPU Time has
    # grown.
    # For the Memory Resource this determines how much memory has been
    # allocated or freed per measurement
    # For the IO Resource this determines how when IO Operations have been
    # done.
    @classmethod
    def get_delta(self, measurements):
        delta_time = [0]
        for index in range(1, len(measurements)):
            delta_time.append(measurements[index] - measurements[index-1])

        return delta_time

    # This calculates the total usage of the resource or the total time it
    # has been used.
    # For the CPU Resource this function determines the total growth of the
    # CPU Usage
    # For the Memory Resource this function determines the total memory usage
    # For the IO Resource this function determines the total amount of bytes
    # read or written.
    # Minor measurements are not included in the above statements.
    # This functions normalizes timestamps to start from 0.
    @classmethod
    def get_total(self, measurements):
        total_time = []
        for index in range(0, len(measurements)):
            total_time.append(measurements[index] - measurements[0])

        return total_time

    # measurements are to be given in ns
    @classmethod
    def get_percentage_diff(self, measurements, timestamps):
        percentages = [0]
        for index in range(1, len(measurements)):
            percentages.append(((measurements[index] - measurements[index-1])/(timestamps[index] - timestamps[index-1]))*100)
        return percentages

    @classmethod
    def get_resource_measurement_as_dataframe(
        self,
        path_to_measurement,
        cgroup,
        resource,
        variable,
        method = None,
        normalize_timestamps = False,
        io_device = None,
        eval_id = None,
        unit = None
        ):
        #print(f"{cgroup}, {resource}, {variable}")
        with open(path_to_measurement, "r") as json_file:
            measurement_dict = json.load(json_file)
            #print(measurement_dict[cgroup][resource][variable][0])

        if method == "perc" and resource != "cpu":
            print("percentage only available for cpu")
            return

        if not io_device:
            resource_dict = measurement_dict[cgroup][resource]
        else:
            resource_dict = measurement_dict[cgroup][resource][io_device]
                        
        # TEMPORARY. This has already been fixed.
        #timestamps = list(map(int, resource_dict['timestamps']))
        # Timestamps as seconds.
        timestamps = resource_dict['timestamps']
        variable_values = resource_dict[variable]

        if not method:
            usage = variable_values
        elif method == "total":
            usage = self.get_total(variable_values)
        elif method == "delta":
            usage = self.get_delta(variable_values)
        elif method == "perc":
            variable_values = list(
                map(lambda x: x * 1000, variable_values)
            )
            usage = self.get_percentage_diff(variable_values, timestamps)
        else:
            return
        
        if unit and unit == "GB":
            usage = list(
                map(lambda x: x / 1000000000, usage)
                )
        elif unit and unit == "MB":
            usage = list(
                map(lambda x: x / 1000000, usage)
                )
        elif unit and unit == "KB":
            usage = list(
                map(lambda x: x / 1000, usage)
                )

        if resource == "cpu" and method != "perc":
            usage = list(
                    map(lambda x: x / 1000000, usage)
                    )
        

        #y_name = f"Total {resource} time" if time_method == "total" \
        #    else f"{resource} time delta"
        if "saml" in path_to_measurement:
            login_method = "SAML 2.0"
        elif "oidc" in path_to_measurement:
            login_method = "OIDC"


        if normalize_timestamps:
            timestamps = self.get_total(timestamps)
        timestamps = list(
            map(lambda x: x / 1000000000, timestamps)
            )
        
        idp_cgroups = set(["docker", "keycloak", "postgres", "caddy"])
        sp_cgroups = set(["eval.slice", "nginx", "gunicorn"])
        if cgroup in sp_cgroups:
            measured_system = "SP"
        elif cgroup in idp_cgroups:
            measured_system = "IdP"
        else:
            measured_system = None

        frame = {
            'protocol': login_method,
            'timestamps': timestamps,
            'resource_measurements': usage,
            'eval': eval_id,
            'system': measured_system,
            'variable_name': variable,
            'unit': "Sekunden" if (resource == "cpu" and method != "perc") \
                else "Prozent" if resource == "cpu" \
                else "IO-Operationen" if (variable == "read_io_ops" or variable == "write_io_ops") \
                else unit
            }
        data_frame = pandas.DataFrame(frame)
        print(data_frame.head())
        return data_frame
    
    def plot_resource_measurement(
            self,
            data_frame,
            plot_title,
            y_label,
            ylim_bottom = None,
            ylim_top = None,
            y_ticks = None
            ):

        #data_frame_exp = data_frame.explode('Time')
        #seaborn.cubehelix_palette(start=2.0, rot=-1.0, as_cmap=True)
        plot_ax = seaborn.lineplot(
            data = data_frame,
            x = 'timestamps',
            y = 'resource_measurements',
            #hue = 'Time',
            #palette = seaborn.color_palette("flare", as_cmap=True),
            #palette = seaborn.light_palette('#9163cb', as_cmap=True),
            #kind = "box"
            )
        plot_ax.set(
                title = plot_title
            )
        plot_ax.set_xlabel("Time in seconds")
        plot_ax.set_ylabel(y_label)
        #seaborn.set_style("whitegrid")
        #print(data_frame_exp.head())
        plotter.gcf().axes[0].yaxis.get_major_formatter().set_scientific(False)
        plotter.grid(axis='y')
        if ylim_bottom and ylim_top:
            plotter.ylim(ylim_bottom, ylim_top)
            if y_ticks:
                # y_ticks + 1 must be done here, because the endpoint is
                # included. If y_ticks were to be used, the linspace would
                # actually be calculated over 19 values.
                plotter.yticks(
                    numpy.linspace(ylim_bottom, ylim_top, y_ticks+1)
                    )

        plotter.show()
        #plotter.autoscale(tight=True)
        #plotter.autoscale()

    @classmethod
    def get_highest_unit(self,
        path_to_measurements,
        cgroup = None,
        resource = None,
        variable = None,
        method = None,
        normalize_timestamps = False,
        io_device = None):

        data_frames = []
        for path_to_measurement in path_to_measurements:
            with open(path_to_measurement, "r") as json_file:
                measurement_dict = json.load(json_file)

            if not io_device:
                resource_dict = measurement_dict[cgroup][resource]
            else:
                resource_dict = measurement_dict[cgroup][resource][io_device]

            timestamps = resource_dict['timestamps']
            variable_values = resource_dict[variable]
            if normalize_timestamps:
                timestamps = self.get_total(timestamps)
            timestamps = list(
                map(lambda x: x / 1000000000, timestamps)
                )
            if not method:
                usage = variable_values
            elif method == "total":
                usage = self.get_total(variable_values)

            is_gb = False
            is_mb = False
            is_kb = False
            for value in usage:
                if value / 1000 > 1:
                    print(f"{value} is kb")
                    is_kb = True
                if value / 1000000 > 1:
                    print(f"{value} is mb")
                    is_mb = True
                if value / 1000000000 > 1:
                    print(f"{value} is gb")
                    is_gb = True

        unit = "GB" if is_gb else "MB" if is_mb else "KB" if is_kb else "Byte"
        return unit

    # For this to work it is expected that the given data is extracted from
    # the same cgroup and the same variable.
    @classmethod
    def compare_resource_measurements(
        self,
        path_to_measurements,
        plot_title,
        y_label,
        cgroup = None,
        resource = None,
        variable = None,
        method = None,
        normalize_timestamps = False,
        io_device = None,
        plot_type = "line",
        ylim_bottom = None,
        ylim_top = None,
        y_ticks = None
        ):
        
        data_frames = []
        unit = None
        if resource == "memory" or (resource == "io" and (variable != "read_io_ops" and variable != "write_io_ops")):
            unit = EvaluationAnalyzer.get_highest_unit(
                        path_to_measurements,
                        cgroup=cgroup,
                        resource = resource,
                        variable = variable,
                        method = method,
                        normalize_timestamps = normalize_timestamps,
                        io_device = io_device
                        )

        for path_to_measurement in path_to_measurements:

            eval_id = path_to_measurement.split("/")[-3].split("_")[-1]
            print(eval_id)
            if eval_id in client_secrets.EVAL_ID_LOOKUP.keys():
                    eval_id = client_secrets.EVAL_ID_LOOKUP[eval_id]
            data_frames.append(
                EvaluationAnalyzer.get_resource_measurement_as_dataframe(
                    path_to_measurement,
                    cgroup,
                    resource,
                    variable,
                    method=method,
                    normalize_timestamps=normalize_timestamps,
                    io_device=io_device,
                    eval_id=eval_id,
                    unit=unit
                )
            )
            
        #print(max([len(data_frame['timestamps']) for data_frame in data_frames]))
        fig, ax = plotter.subplots()
        concat_data_frame = pandas.concat(data_frames, ignore_index=True)
        if not unit:
            unit = data_frames[0].get('unit')[0] 
        #print(pandas.cut(concat_data_frame['timestamps'], max([len(data_frame['timestamps']) for data_frame in data_frames])+1))
        #for data_frame in data_frames:
        if plot_type == "line":
            plot_ax = seaborn.lineplot(
                data = concat_data_frame,
                #ax = ax,
                #hue = 'protocol',
                hue = 'eval',
                #hue = 'system',
                #hue = 'variable_name',
                #hue = concat_data_frame['eval'] + ", " + concat_data_frame['variable_name'],
                x = 'timestamps',
                y = 'resource_measurements',
                )
        elif plot_type == "scatter":
            seconds = max([len(data_frame['timestamps']) for data_frame in data_frames])+1
            concat_data_frame['timestamp_bins'] = pandas.cut(concat_data_frame['timestamps'], seconds, labels = [f'{i}' for i in range(0,seconds)])

            plot_ax = seaborn.boxplot(
                data = concat_data_frame,
                #ax = ax,
                #hue = 'protocol',
                hue = 'eval',
                #hue = 'system',
                #hue = 'variable_name',
                #hue = concat_data_frame['eval'] + ", " + concat_data_frame['variable_name'],
                x = 'timestamp_bins',
                y = 'resource_measurements',
                ) 
        plot_ax.set(
                title = plot_title
            )
        plot_ax.set_xlabel("Zeit in Sekunden")
        ax.xaxis.set_major_locator(ticker.AutoLocator())
        ax.xaxis.set_minor_locator(ticker.AutoMinorLocator())
        plot_ax.set_ylabel(f"{y_label}{" " if unit != "IO-Operationen" else ""}{unit}")
        ax.legend()
        plotter.gcf().axes[0].yaxis.get_major_formatter().set_scientific(False)
        plotter.grid(axis='y')
        if ylim_bottom and ylim_top:
            plotter.ylim(ylim_bottom, ylim_top)
            if y_ticks:
                # y_ticks + 1 must be done here, because the endpoint is
                # included. If y_ticks were to be used, the linspace would
                # actually be calculated over 19 values.
                plotter.yticks(
                    numpy.linspace(ylim_bottom, ylim_top, y_ticks+1)
                    )
        
        plotter.show()

if __name__ == "__main__":
    
    #processor = EvaluationLogProcessor()
    """
    sp_record_data = processor.transform_resmon_record_into_dict(
            "sp",
            f"{client_secrets.LOG_STORAGE_PATH}/oidc-eval-30-60-sp-resmon-5.txt"
            )
    processor.serialize_data_into_json(sp_record_data, f"{client_secrets.LOG_STORAGE_PATH}/oidc-eval-30-60-sp-resmon-5.txt")
    processor.process_test_log(
        "saml",
        10,
        100
    )

    processor.process_resmon_records(
        "saml",
        10,
        100
    )
    """
    #admin = KcAdministrator()
    #admin.logout_all_kc_sessions(number_of_users_to_logout = 60)

#    processor.process_test_log("saml", 300, 10)
#    fetch_and_store_log("saml", 300, 10)
#    serialize_saml_log_into_json(
#        f"{client_secrets.LOG_STORAGE_PATH}/saml-eval-300-10-1.log"
#        )

    #analyzer = EvaluationAnalyzer(
    #    path_to_aggregate_data = f"{client_secrets.LOG_STORAGE_PATH}/" \
    #        "analyze_evalstorage_oidc-eval-30-30-1/" \
    #        "oidc-eval-30-30-aggregate.json"
    #    )
    #analyzer.get_aggregate_data_as_numpy_array("redirect_time")
    #analyzer.plot_for_all_users("redirect_time")
    #analyzer = EvaluationLogProcessor()
    #analyzer.restore_resource("analyze_evalstorage_oidc-eval-30-60-1", "oidc", 30, 60)
    #EvaluationAnalyzer.negligibility_read()
    
    analyzer = EvaluationAnalyzer(
        login_method = "saml",
        test_length = 30,
        number_of_users_used_in_test = 60,
        number_of_test_cycles = 100
    )
    #analyzer.get_aggregate_data()
    analyzer.res_aggr("analyze_evalstorage_saml-eval-30-60-10")
    
    
    #path_to_aggregate_data = f"{client_secrets.LOG_STORAGE_PATH}/" \
    #"analyze_evalstorage_oidc-eval-30-60-6/" \
    #"oidc-eval-30-60-aggregate.json"
    #path_to_aggregate_user_data = f"{client_secrets.LOG_STORAGE_PATH}/" \
    #"analyze_evalstorage_oidc-eval-30-60-6/user-time-data/" \
    #"oidc-eval-30-60-user-time-aggregate.json"
    #analyzer = EvaluationAnalyzer(
    #    path_to_aggregate_data=path_to_aggregate_data,
    #    path_to_aggregate_user_time = path_to_aggregate_user_data
    #    )
    #df = analyzer.get_aggregate_user_data_as_dataframe(
    #    "saml-eval-30-60-5"
    #)
    #analyzer.plot_by_user(df, "user time", plot_type="line")
    #"""
    EvaluationAnalyzer.compare_measurements_by_user(
        [
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_oidc-eval-10-100-1/oidc-eval-10-100-aggregate.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_oidc-eval-10-100-2/oidc-eval-10-100-aggregate.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_oidc-eval-150-300-1/oidc-eval-150-300-aggregate.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_oidc-eval-150-300-2/oidc-eval-150-300-aggregate.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_oidc-eval-150-300-3/oidc-eval-150-300-aggregate.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_oidc-eval-30-60-1/oidc-eval-30-60-aggregate.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_oidc-eval-30-60-10/oidc-eval-30-60-aggregate.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_oidc-eval-30-60-11/oidc-eval-30-60-aggregate.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_oidc-eval-30-60-12/oidc-eval-30-60-aggregate.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_oidc-eval-30-60-13/oidc-eval-30-60-aggregate.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_oidc-eval-30-60-14/oidc-eval-30-60-aggregate.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_oidc-eval-30-60-2/oidc-eval-30-60-aggregate.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_oidc-eval-30-60-3/oidc-eval-30-60-aggregate.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_oidc-eval-30-60-4/oidc-eval-30-60-aggregate.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_oidc-eval-30-60-5/oidc-eval-30-60-aggregate.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_oidc-eval-30-60-6/oidc-eval-30-60-aggregate.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_oidc-eval-30-60-7/oidc-eval-30-60-aggregate.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_oidc-eval-30-60-8/oidc-eval-30-60-aggregate.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_oidc-eval-30-60-9/oidc-eval-30-60-aggregate.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_saml-eval-1-1-1/saml-eval-1-1-aggregate.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_saml-eval-10-100-1/saml-eval-10-100-aggregate.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_saml-eval-10-100-2/saml-eval-10-100-aggregate.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_saml-eval-10-100-3/saml-eval-10-100-aggregate.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_saml-eval-10-100-4/saml-eval-10-100-aggregate.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_saml-eval-120-240-1/saml-eval-120-240-aggregate.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_saml-eval-150-300-1/saml-eval-150-300-aggregate.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_saml-eval-150-300-2/saml-eval-150-300-aggregate.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_saml-eval-150-300-3/saml-eval-150-300-aggregate.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_saml-eval-30-60-1/saml-eval-30-60-aggregate.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_saml-eval-30-60-2/saml-eval-30-60-aggregate.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_saml-eval-30-60-3/saml-eval-30-60-aggregate.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_saml-eval-30-60-4/saml-eval-30-60-aggregate.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_saml-eval-30-60-5/saml-eval-30-60-aggregate.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_saml-eval-30-60-6/saml-eval-30-60-aggregate.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_saml-eval-30-60-7/saml-eval-30-60-aggregate.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_saml-eval-30-60-8/saml-eval-30-60-aggregate.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_saml-eval-30-60-9/saml-eval-30-60-aggregate.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_saml-eval-30-60-10/saml-eval-30-60-aggregate.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_oidc-eval-10-100-1/user-time-data/oidc-eval-10-100-user-time-aggregate.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_oidc-eval-10-100-2/user-time-data/oidc-eval-10-100-user-time-aggregate.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_oidc-eval-150-300-1/user-time-data/oidc-eval-150-300-user-time-aggregate.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_oidc-eval-150-300-2/user-time-data/oidc-eval-150-300-user-time-aggregate.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_oidc-eval-150-300-3/user-time-data/oidc-eval-150-300-user-time-aggregate.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_oidc-eval-30-60-1/user-time-data/oidc-eval-30-60-user-time-aggregate.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_oidc-eval-30-60-10/user-time-data/oidc-eval-30-60-user-time-aggregate.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_oidc-eval-30-60-11/user-time-data/oidc-eval-30-60-user-time-aggregate.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_oidc-eval-30-60-12/user-time-data/oidc-eval-30-60-user-time-aggregate.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_oidc-eval-30-60-13/user-time-data/oidc-eval-30-60-user-time-aggregate.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_oidc-eval-30-60-14/user-time-data/oidc-eval-30-60-user-time-aggregate.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_oidc-eval-30-60-2/user-time-data/oidc-eval-30-60-user-time-aggregate.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_oidc-eval-30-60-3/user-time-data/oidc-eval-30-60-user-time-aggregate.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_oidc-eval-30-60-4/user-time-data/oidc-eval-30-60-user-time-aggregate.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_oidc-eval-30-60-5/user-time-data/oidc-eval-30-60-user-time-aggregate.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_oidc-eval-30-60-6/user-time-data/oidc-eval-30-60-user-time-aggregate.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_oidc-eval-30-60-7/user-time-data/oidc-eval-30-60-user-time-aggregate.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_oidc-eval-30-60-8/user-time-data/oidc-eval-30-60-user-time-aggregate.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_oidc-eval-30-60-9/user-time-data/oidc-eval-30-60-user-time-aggregate.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_saml-eval-1-1-1/user-time-data/saml-eval-1-1-user-time-aggregate.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_saml-eval-10-100-1/user-time-data/saml-eval-10-100-user-time-aggregate.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_saml-eval-10-100-2/user-time-data/saml-eval-10-100-user-time-aggregate.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_saml-eval-10-100-3/user-time-data/saml-eval-10-100-user-time-aggregate.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_saml-eval-10-100-4/user-time-data/saml-eval-10-100-user-time-aggregate.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_saml-eval-120-240-1/user-time-data/saml-eval-120-240-user-time-aggregate.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_saml-eval-150-300-1/user-time-data/saml-eval-150-300-user-time-aggregate.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_saml-eval-150-300-2/user-time-data/saml-eval-150-300-user-time-aggregate.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_saml-eval-150-300-3/user-time-data/saml-eval-150-300-user-time-aggregate.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_saml-eval-30-60-1/user-time-data/saml-eval-30-60-user-time-aggregate.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_saml-eval-30-60-2/user-time-data/saml-eval-30-60-user-time-aggregate.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_saml-eval-30-60-3/user-time-data/saml-eval-30-60-user-time-aggregate.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_saml-eval-30-60-4/user-time-data/saml-eval-30-60-user-time-aggregate.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_saml-eval-30-60-5/user-time-data/saml-eval-30-60-user-time-aggregate.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_saml-eval-30-60-6/user-time-data/saml-eval-30-60-user-time-aggregate.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_saml-eval-30-60-7/user-time-data/saml-eval-30-60-user-time-aggregate.json",
            f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_saml-eval-30-60-8/user-time-data/saml-eval-30-60-user-time-aggregate.json",
            f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_saml-eval-30-60-9/user-time-data/saml-eval-30-60-user-time-aggregate.json",
            f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_saml-eval-30-60-10/user-time-data/saml-eval-30-60-user-time-aggregate.json"
            #f"{client_secrets.LOG_STORAGE_PATH}/" \
            #"analyze_evalstorage_oidc-eval-30-60-6/user-time-data/" \
            #"oidc-eval-30-60-user-time-aggregate.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/" \
            #"analyze_evalstorage_oidc-eval-30-60-5/user-time-data/" \
            #"oidc-eval-30-60-user-time-aggregate.json",
        ],
        #"Durchschnittliche Login-Zeit eines Nutzers bei Verwendung von OIDC oder SAML in einem Extended-Mittellast-Szenario", # Titel
        #"Durchschnittliche Verarbeitungszeit der für den Login-Prozess relevanten Funktionen von SAML 2.0",
        "", # Für kleine Abbildung nutzen.
        "Login-Zeit in Sekunden", # y Label
        #"Verarbeitungszeit in Sekunden",
        aggregate_type="user",
        #aggregate_data_key = [
        #    "redirect_time",
        #    #"pkce_time",
        #    #"get_access_token_time", #OIDC
        #    #"decode_id_token_time",
        #    #"complete_login_time",
        #    #"dispatch_time"#,
        #    #"build_auth_time", #SAML
        #    #"login_time",
        #    #"acs_dispatch_time",
        #    #"finish_acs_dispatch_time"
        #    ],
        num_users=60,
        num_cycles=100
        )
    
    combine = [f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_oidc-eval-150-300-3/idp-resmon-data/oidc-eval-150-300-idp-resmon-{i}.json" for i in range(1,101)] + \
              [f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_saml-eval-150-300-3/idp-resmon-data/saml-eval-150-300-idp-resmon-{i}.json" for i in range(1,101)]
    #for i in range(1,101):
    EvaluationAnalyzer.compare_resource_measurements(
        #[
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_ -eval- - - / -resmon-data/ -eval- - - -resmon- .json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_oidc-eval-10-100-2/sp-resmon-data/oidc-eval-10-100-sp-resmon-{i}.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_saml-eval-10-100-4/sp-resmon-data/saml-eval-10-100-sp-resmon-{i}.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_oidc-eval-10-100-2/idp-resmon-data/oidc-eval-10-100-idp-resmon-42.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_saml-eval-10-100-4/idp-resmon-data/saml-eval-10-100-idp-resmon-42.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_oidc-eval-30-60-6/idp-resmon-data/oidc-eval-30-60-idp-resmon-{i}.json" for i in range(1,101)
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_saml-eval-30-60-5/idp-resmon-data/saml-eval-30-60-idp-resmon-{i}.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_oidc-eval-30-60-6/idp-resmon-data/oidc-eval-30-60-idp-resmon-42.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_saml-eval-30-60-5/idp-resmon-data/saml-eval-30-60-idp-resmon-42.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_saml-eval-30-60-5/sp-resmon-data/saml-eval-30-60-sp-resmon-64.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_oidc-eval-30-60-9/idp-resmon-data/oidc-eval-30-60-idp-resmon-64.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_oidc-eval-150-300-3/idp-resmon-data/oidc-eval-150-300-idp-resmon-64.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_oidc-eval-150-300-2/sp-resmon-data/oidc-eval-150-300-sp-resmon-{i}.json",
            #f"{client_secrets.LOG_STORAGE_PATH}/analyze_evalstorage_saml-eval-150-300-2/sp-resmon-data/saml-eval-150-300-sp-resmon-{i}.json"
        #],
        combine,
        "Vergleich der aktiven RAM-Nutzung von SAML 2.0 und OIDC für das Keycloak-IdM", #Titel sonst
        #f"Vergleich der totalen geschriebenen Daten auf der Festplatte 202:0 von SAML 2.0 und OIDC für den Gunicorn-Server", #Titel

        #"CPU-Nutzung in", #y label
        "Aktive RAM-Nutzung in",
        #"Gelesene Daten in",
        #"Geschriebene Daten in",
        #"Anzahl der Write-",
        #"Anzahl der Read-",

        #cgroups=["keycloak", "gunicorn"], #cgroup liste

        cgroup = "gunicorn", # simple cgroup
        #cgroup = "keycloak",

        #resource="cpu",
        resource="memory", #resource
        #resource="io",

        #variables=["total_memory_usage", "anonymous_memory", "file_system_cache_memory", "kernel_memory"],
        #variables=["written_bytes", "write_io_ops"],

        #variable="total_cpu_time", #welche variable der resource
        variable="total_memory_usage",
        #variable="read_bytes",
        #variable="written_bytes",
        #variable="write_io_ops",
        #variable="read_io_ops",

        #method = "perc", #total delta oder perc oder none
        method = None,
        #method = "total",
        normalize_timestamps= True,
        #io_device="202:0",
        #io_device="253:0",
        #io_device="252:0",
        plot_type="scatter"
    )
    #"""
    #analyzer.res_aggr("analyze_evalstorage_oidc-eval-30-60-6")
    #y_name = f"Total {resource} time" if time_method == "total" \
    #    else f"{resource} time delta"
    #y_name = "unknown"
    #resource_frame = analyzer.get_resource_measurement_as_dataframe(
    #    f"{client_secrets.LOG_STORAGE_PATH}/" \
    #    "analyze_evalstorage_oidc-eval-120-240-1/" \
    #    "idp-resmon-data/oidc-eval-120-240-idp-resmon-5.json",
    #    "keycloak",
    #    "memory",
    #    "total_memory_usage",
    #    y_name,
    #    method = None,
    #    normalize_timestamps=True
    #)
    #second_resource_frame = analyzer.get_resource_measurement_as_dataframe(
    #    f"{client_secrets.LOG_STORAGE_PATH}/" \
    #    "analyze_evalstorage_oidc-eval-15-30-1/" \
    #    "sp-resmon-data/oidc-eval-15-30-sp-resmon-5.json",
    #    "nginx",
    #    "cpu",
    #    "total_cpu_time",
    #    y_name,
    #    method = "delta",
    #    normalize_timestamps=True
    #)

    #analyzer.plot_resource_measurement(
    #    resource_frame,
    #    "RAM usage of Keycloak", 
    #    y_name
    #    )
    

    # TODO: Normalize timestamps.
    #analyzer.overlay_resource_measurement_plots(
    #    [resource_frame, second_resource_frame],
    #    "Total CPU usage of Nginx",
    #    y_name
    #)
    #"""
    
    #analyzer.plot_for_all_users(
    #    "redirect_time",
    #    "Time of the redirect function per user",
    #    ylim_bottom = 0.0025,
    #    ylim_top = 0.0035,
    #    y_ticks = 20
    #    )
