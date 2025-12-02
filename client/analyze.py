from client.log_processor import EvaluationLogProcessor

from collections import namedtuple
import json
import matplotlib.pyplot as plotter
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
                    "dispatch_time": []
                }
        else:
            for test_user_id in range(1, self.number_of_users_used_in_test+1):
                data[f"t_user_{test_user_id}"] = {
                    "redirect_time": [],
                    "build_auth_time": [],
                    "login_time": [],
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
                data[test_user]["get_access_token_time"].append(
                    log_data[test_user]["get_access_token_time_time"]
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
                    log_data[test_user]["build_auth_time_time"]
                )
                data[test_user]["login_time"].append(
                    log_data[test_user]["login_time_time"]
                )
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
                self.populate_aggregate_data_dict(log_data)
    
    
    def serialize_aggregate_data_dict(self):
        path_to_aggregate_json = "" \
            f"{client_secrets.LOG_STORAGE_PATH}/" \
            f"{self.login_method}-eval-{self.test_length}-" \
            f"{self.number_of_users_used_in_test}-aggregate.json"
        
        with open(path_to_aggregate_json, "w") as json_file:
            json.dump(self.aggregate_data_dict, json_file, indent = 4)

    # DEPRECATED
    #def get_eval_id_from_folder_name(self, folder_name):
    #    return int(folder_name.split("-")[-1])
    
    def create_eval_storage_folders(self):
        
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
            
            if not "resmon" in name:
                path_pair_list.append(
                    RenamePathPair(
                        f"{client_secrets.LOG_STORAGE_PATH}/{name}",
                        f"{client_secrets.LOG_STORAGE_PATH}/" \
                        f"{storage_directory_name}/{name}"
                    )
                )
            elif "sp" in name:
                path_pair_list.append(
                    RenamePathPair(
                        f"{client_secrets.LOG_STORAGE_PATH}/{name}",
                        f"{client_secrets.LOG_STORAGE_PATH}/" \
                        f"{storage_directory_name}/sp-resmon-data/" \
                        f"{name}"
                    )
                )
            elif "idp" in name:
                path_pair_list.append(
                    RenamePathPair(
                        f"{client_secrets.LOG_STORAGE_PATH}/{name}",
                        f"{client_secrets.LOG_STORAGE_PATH}/" \
                        f"{storage_directory_name}/idp-resmon-data/" \
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
        self.serialize_aggregate_data_dict()
        self.move_eval_data_to_storage()

##############################################################################
#                              A N A L Y S I S                               #
##############################################################################
    
    def get_aggregate_data_as_dataframe(
        self, 
        aggregate_data_key
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
        
        uids = [
            user_id for user_id in range(
                1, self.number_of_users_used_in_test + 1
                )
            ]
        
        data = self.aggregate_data_dict["data"]
        test_user_data = []
        for user_id in range(1, self.number_of_users_used_in_test + 1):
            test_user_data.append(
                numpy.array(data[f"t_user_{user_id}"][aggregate_data_key])
            )
        frame = {'User IDs': uids, 'Time': test_user_data}
        dataframe = pandas.DataFrame(frame)
        return dataframe


    def plot_for_all_users(
            self,
            aggregate_data_key,
            plot_title,
            ylim_bottom = None,
            ylim_top = None,
            y_ticks = None
            ):
        #data = self.get_aggregate_data_as_numpy_array(aggregate_data_key)
        data_frame = self.get_aggregate_data_as_dataframe(
            aggregate_data_key
            )
        data_frame_exp = data_frame.explode('Time')
        #seaborn.cubehelix_palette(start=2.0, rot=-1.0, as_cmap=True)
        seaborn.catplot(
            data = data_frame_exp,
            x = 'User IDs',
            y = 'Time',
            hue = 'User IDs',
            #palette = seaborn.color_palette("flare", as_cmap=True),
            palette = seaborn.light_palette('#9163cb', as_cmap=True),
            kind = "box"
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

    # This calculates the change rate of a resource over time.
    # For the CPU Resource this function determines where the CPU Time has
    # grown.
    # For the Memory Resource this determines how much memory has been
    # allocated or freed per measurement
    # For the IO Resource this determines how when IO Operations have been
    # done.
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
    def get_total(self, measurements):
        total_time = []
        for index in range(0, len(measurements)):
            total_time.append(measurements[index] - measurements[0])

        return total_time


    def get_resource_measurement_as_dataframe(
        self,
        path_to_measurement,
        cgroup,
        resource,
        variable,
        y_name,
        method = "total",
        io_device = None
        ):

        with open(path_to_measurement, "r") as json_file:
            measurement_dict = json.load(json_file)

        if not io_device:
            resource_dict = measurement_dict[cgroup][resource]
        else:
            resource_dict = measurement_dict[cgroup][resource][io_device]
        # TEMPORARY. This has already been fixed.
        timestamps = list(map(int, resource_dict['timestamps']))
        # Timestamps as seconds.
        timestamps = list(
            map(lambda x: x / 1000000000, timestamps)
            )
        variable_values = resource_dict[variable]
        if method == "total":
            usage = self.get_total(variable_values)
        elif method == "delta":
            usage = self.get_delta(variable_values)
        else:
            return
        #y_name = f"Total {resource} time" if time_method == "total" \
        #    else f"{resource} time delta"
        print(timestamps)
        print(usage)
        frame = {'Time': timestamps, f'{y_name}': usage}
        dataframe = pandas.DataFrame(frame)
        return dataframe
    
    def plot_resource_measurement(
            self,
            data_frame,
            plot_title,
            y_name,
            ylim_bottom = None,
            ylim_top = None,
            y_ticks = None
            ):

        #data_frame_exp = data_frame.explode('Time')
        #seaborn.cubehelix_palette(start=2.0, rot=-1.0, as_cmap=True)
        seaborn.lineplot(
            data = data_frame,
            x = 'Time',
            y = f'{y_name}',
            #hue = 'Time',
            #palette = seaborn.color_palette("flare", as_cmap=True),
            #palette = seaborn.light_palette('#9163cb', as_cmap=True),
            #kind = "box"
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






if __name__ == "__main__":
#    processor = EvaluationLogProcessor()
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

    #analyzer = EvaluationAnalyzer(
    #    "oidc",
    #    60,
    #    60,
    #    100
    #)  
    analyzer = EvaluationAnalyzer(
        path_to_aggregate_data = f"{client_secrets.LOG_STORAGE_PATH}/" \
            "analyze_evalstorage_saml-eval-60-60-1/" \
            "saml-eval-60-60-aggregate.json"
        )
    #y_name = f"Total {resource} time" if time_method == "total" \
    #    else f"{resource} time delta"
    y_name = "RAM change rate"
    resource_frame = analyzer.get_resource_measurement_as_dataframe(
        f"{client_secrets.LOG_STORAGE_PATH}/" \
        "analyze_evalstorage_saml-eval-5-5-1/" \
        "sp-resmon-data/saml-eval-5-5-sp-resmon-2.json",
        "nginx",
        "io",
        "written_bytes",
        y_name,
        method = "delta",
        io_device = "202:0"
    )

    analyzer.plot_resource_measurement(
        resource_frame,
        "RAM change rate of Nginx", 
        y_name
        )

    #analyzer.plot_for_all_users(
    #    "redirect_time",
    #    "Time of the redirect function per user",
    #    ylim_bottom = 0.0025,
    #    ylim_top = 0.0035,
    #    y_ticks = 20
    #    )
