from client.log_processor import EvaluationLogProcessor

from collections import namedtuple
import json
import matplotlib.pyplot as plotter
import numpy
import os
import re as regex
from secret import client_secrets
import subprocess

RenamePathPair = namedtuple('RenamePathPair', 'old_file_path new_file_path')

class EvaluationAnalyzer:

    def __init__(
            self,
            login_method = None,
            test_length = None,
            number_of_users_used_in_test = None,
            number_of_test_cycles = None,
            path_to_aggregate_data = None,
            printer = print,
            printer_args = [],
            printer_kwargs = {}
            ):
        """
        Instantiates an EvaluationAnalyzer
        """
        if not path_to_aggregate_data:
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

        self.printer = printer
        self.printer_args = printer_args
        self.printer_kwargs = printer_kwargs

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


    def read_all_serialized_logs_for_current_eval(self):
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
        
        subdirectory_list = os.listdir(client_secrets.LOG_STORAGE_PATH)
        storage_directory_pattern = regex.compile(
            f"analyze_evalstorage_{self.login_method}-eval-" \
            f"{self.test_length}-{self.number_of_users_used_in_test}-" \
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
        
        self.printer(f"{client_secrets.LOG_STORAGE_PATH}/{storage_directory_name}")

        os.mkdir(
            f"{client_secrets.LOG_STORAGE_PATH}/{storage_directory_name}"
        )

        return storage_directory_name


    def get_path_pair_for_rename(
            self, 
            storage_directory_name
            ):
        path_pair_list = []
        for name in os.listdir(f"{client_secrets.LOG_STORAGE_PATH}"):
            if not (name.endswith(".json") or name.endswith(".log")):
                continue
        
            path_pair_list.append(
                RenamePathPair(
                    f"{client_secrets.LOG_STORAGE_PATH}/{name}",
                    f"{client_secrets.LOG_STORAGE_PATH}/" \
                    f"{storage_directory_name}/{name}"
                )
            )
        
        return path_pair_list


    def move_eval_data_to_storage(self):
        storage_directory_name = self.create_eval_storage_folder()
        path_pair_list = self.get_path_pair_for_rename(storage_directory_name)
        
        for path_pair in path_pair_list:
            old_file_path, new_file_path = path_pair
            os.rename(old_file_path, new_file_path)


    def get_aggregate_data(self):
        self.read_all_serialized_logs_for_current_eval()
        self.serialize_aggregate_data_dict()
        self.move_eval_data_to_storage()


    def get_aggregate_data_as_numpy_array(
            self, 
            aggregate_data_key
            ):
        
        # If there is no return here, we can assume that the supplied key is
        # correct and that we can access it.
        if self.login_method == "oidc" \
            and not "redirect_time" in aggregate_data_key \
            and not "complete_login_time" in aggregate_data_key \
            and not "dispatch_time" in aggregate_data_key:
            return None
        elif self.login_method == "saml" \
            and not "redirect_time" in aggregate_data_key \
            and not "acs_dispatch_time" in aggregate_data_key \
            and not "finish_acs_dispatch_time" in aggregate_data_key:
            return None
        
        test_user_data_as_numpy_arrays = []

        data = self.aggregate_data_dict["data"]
        for user_id in range(1, self.number_of_users_used_in_test + 1):
            test_user_data_as_numpy_arrays.append(
                numpy.array(data[f"t_user_{user_id}"][aggregate_data_key])
            )
        
        return test_user_data_as_numpy_arrays
    

    def plot_for_all_users(self, aggregate_data_key):
        data = self.get_aggregate_data_as_numpy_array(aggregate_data_key)
        print(len(data))
        plotter.autoscale(tight=True)
        plotter.xlabel("Test Instance")
        plotter.ylabel("Time")
        user_ids = [
            user_id for user_id in range(
                1, self.number_of_users_used_in_test + 1
                )
            ]
        
        test_ids = [
            test_id for test_id in range(1, self.number_of_test_cycles + 1)
            ]
        
        for user_id in user_ids:
            plotter.plot(test_ids, data[user_id-1], 'ro')

        plotter.grid()
        plotter.show()


    def plot_by_user(self, user_id, aggregate_data_key):
        data = self.get_aggregate_data_as_numpy_array(aggregate_data_key)[
            user_id-1
            ]
        #figure = plotter.figure()
        test_ids = [
            test_id for test_id in range(1, self.number_of_test_cycles + 1)
            ]
        plotter.autoscale(tight=True)
        plotter.xlabel("Test Instance")
        plotter.ylabel("Time")
        plotter.plot(test_ids, data, 'ro')
        
        plotter.grid()
        plotter.show()

    def plot_by_test(self, test_id):
        pass


if __name__ == "__main__":
#    processor = EvaluationLogProcessor()
#    processor.process_test_log("saml", 300, 10)
#    fetch_and_store_log("saml", 300, 10)
#    serialize_saml_log_into_json(
#        f"{client_secrets.LOG_STORAGE_PATH}/saml-eval-300-10-1.log"
#        )

    analyzer = EvaluationAnalyzer(
        path_to_aggregate_data = f"{client_secrets.LOG_STORAGE_PATH}/" \
            "analyze_evalstorage_oidc-eval-30-30-1/" \
            "oidc-eval-30-30-aggregate.json"
        )
    analyzer.get_aggregate_data_as_numpy_array("redirect_time")
    analyzer.plot_for_all_users("redirect_time")