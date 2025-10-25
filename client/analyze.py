from client.log_processor import EvaluationLogProcessor

import json
import matplotlib
import numpy
import os
import re as regex
from secret import client_secrets
import subprocess

class EvaluationAnalyzer:

    def __init__(
            self,
            login_method,
            test_length,
            number_of_users_used_in_test,
            number_of_test_cycles,
            printer = print,
            printer_args = [],
            printer_kwargs = {}
            ):
        """
        Instantiates an EvaluationAnalyzer
        """
        self.login_method = login_method \
            if "saml" in login_method or "oidc" in login_method \
            else None
        self.test_length = test_length \
            if isinstance(test_length, int) \
            else None
        self.number_of_users_used_in_test = number_of_users_used_in_test \
            if isinstance(number_of_users_used_in_test, int) \
            and number_of_users_used_in_test > 0 \
            and number_of_users_used_in_test <= 1000 \
            else None
        self.number_of_test_cycles = number_of_test_cycles \
            if isinstance(number_of_test_cycles, int) \
            and number_of_test_cycles > 0 \
            else None
        self.aggregate_data_dict = self.initialize_aggregate_data_dict()

        self.printer = printer
        self.printer_args = printer_args
        self.printer_kwargs = printer_kwargs


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
                    "complete_login_time": [],
                    "dispatch_time": []
                }
        else:
            for test_user_id in range(1, self.number_of_users_used_in_test+1):
                data[f"t_user_{test_user_id}"] = {
                    "redirect_time": [],
                    "acs_dispatch_time": [],
                    "finish_acs_dispatch_time": []
                }

        return aggregate_data_dict


    def populate_aggregate_data_dict(self, log_data):
        data = self.aggregate_data_dict["data"]
        for test_user in log_data.keys():
            data[test_user]["redirect_time"].append(
                log_data[test_user]["redirect_time"]
                )
            
            if self.login_method == "oidc":
                data[test_user]["complete_login_time"].append(
                    log_data[test_user]["complete_login_time"]
                )
                data[test_user]["dispatch_time"].append(
                    log_data[test_user]["dispatch_time"]
                )
            else:
                data[test_user]["acs_dispatch_time"].append(
                    log_data[test_user]["acs_dispatch_time"]
                )
                data[test_user]["finish_acs_dispatch_time"].append(
                    log_data[test_user]["finish_acs_dispatch_time"]
                )


    def read_serialized_log(self, path_to_json):
        with open(path_to_json, "r") as json_file:
            log_data = json.load(json_file)
        
        return log_data


    def read_all_serialized_logs_for_current_eval(
            self#,
            #number_of_test_cycles
            ):
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
                self.populate_aggregate_data_dict(log_data)
    
    
    def serialize_aggregate_data_dict(self):
        path_to_aggregate_json = "" \
            f"{client_secrets.LOG_STORAGE_PATH}/" \
            f"{self.login_method}-eval-{self.test_length}-" \
            f"{self.number_of_users_used_in_test}-aggregate.json"
        
        with open(path_to_aggregate_json, "w") as json_file:
            json.dump(self.aggregate_data_dict, json_file, indent = 4)


    def get_eval_id_from_folder_name(self, folder_name):
        return int(folder_name.split("-")[-1])

    
    def create_eval_storage_folder(self):
        
        *_, last_subdirectory = os.walk(client_secrets.LOG_STORAGE_PATH)
        last_subdirectory_name = last_subdirectory[0]
        evaluation_id = 0
        if "eval" not in last_subdirectory_name:
            evaluation_id = 1
        else:
            evaluation_id = self.get_eval_id_from_folder_name(
                last_subdirectory_name
                )
            evaluation_id += 1
        
        storage_directory_name = f"analyze_evalstorage_{self.login_method}-" \
            f"eval-{self.test_length}-{self.number_of_users_used_in_test}-" \
            f"{evaluation_id}"
        
        self.printer(f"{client_secrets.LOG_STORAGE_PATH}/{storage_directory_name}")

        os.mkdir(
            f"{client_secrets.LOG_STORAGE_PATH}/{storage_directory_name}"
        )

        return storage_directory_name


    def get_renaming_tuples(
            self, 
            storage_directory_name
            ):
        file_tuple_list = []
        for name in os.listdir(f"{client_secrets.LOG_STORAGE_PATH}"):
            if not (name.endswith(".json") or name.endswith(".log")):
                continue
        
            file_tuple_list.append(
                (
                    f"{client_secrets.LOG_STORAGE_PATH}/{name}",
                    f"{client_secrets.LOG_STORAGE_PATH}/" \
                    f"{storage_directory_name}/{name}"
                )
            )
        
        return file_tuple_list


    #def get_paths_to_place_eval_files_in(
    #        self,
    #        eval_file_names,
    #        storage_directory_name
    #        ):
    #    
    #    new_eval_file_names = []
    #    for file in eval_file_names:
    #        split_file = file.split("/")
    #        split_file[-1] = f"{storage_directory_name}/{split_file[-1]}"
    #        new_eval_file_names.append("/".join(split_file))
    #    
    #    return new_eval_file_names


    def move_eval_data_to_storage(self):
        storage_directory_name = self.create_eval_storage_folder()
        file_tuple_list = self.get_renaming_tuples(storage_directory_name)
        #new_files = self.get_paths_to_place_eval_files_in(
        #    storage_directory_name,
        #    old_files
        #)
        
        for file_tuple in file_tuple_list:
            os.rename(file_tuple[0], file_tuple[1])

        #subprocess.run(
        #    [
        #        "move", 
        #        f"{client_secrets.LOG_STORAGE_PATH}/*.log",
        #        f"{client_secrets.LOG_STORAGE_PATH}/{storage_directory_name}"
        #    ]
        #)



    def get_aggregate_data(self):
        self.read_all_serialized_logs_for_current_eval()
        self.serialize_aggregate_data_dict()
        self.move_eval_data_to_storage()




if __name__ == "__main__":
    #processor = EvaluationLogProcessor()
    #processor.process_test_log("saml", 300, 10)
    #fetch_and_store_log("saml", 300, 10)
    #serialize_saml_log_into_json(
    #    f"{client_secrets.LOG_STORAGE_PATH}/saml-eval-300-10-1.log"
    #    )

    analyzer = EvaluationAnalyzer("saml", 300, 10, 9)
    analyzer.get_aggregate_data()