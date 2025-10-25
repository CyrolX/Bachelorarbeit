import json
import os
import re as regex
from secret import client_secrets
import subprocess

class EvaluationLogProcessor:

    def __init__(
            self,
            printer = print,
            printer_args = [],
            printer_kwargs = {}
            ):
        """
        Instantiates a KcAdministrator
        """
        self.printer = printer
        self.printer_args = printer_args
        self.printer_kwargs = printer_kwargs


    def is_ssh_agent_setup(self):
        # If the ssh-agent service isn't running, this will return with code 2.
        ssh_add_list_process = subprocess.run(["ssh-add", "-l"])
        if ssh_add_list_process.returncode != 0:
            return False
        
        # We can only check the ouput of ssh-add when the command can be suc-
        # cessfully run.
        ssh_add_list_output = subprocess.check_output(["ssh-add", "-l"])
        if client_secrets.WORKSTATION_NAME_AS_BYTES \
            not in ssh_add_list_output:
            # In this case our key hasn't been added to the ssh-agent which
            # means it isn't setup properly.
            return False
        return True


    def setup_ssh_agent(self):
        start_service_process = subprocess.run(
                [
                "powershell", 
                "-command", 
                "Start-Service ssh-agent"
                ]
            )
        if start_service_process.returncode != 0:
            self.printer("[DEBUG | processor.setup] Couldn't start service")

        # This will prompt for the key passcode
        ssh_add_process = subprocess.run(["ssh-add"])
        if ssh_add_process.returncode != 0:
            self.printer(
                "[DEBUG | processor.setup] Couldn't add keys to agent"
                )
        
        self.printer(
            "[DEBUG | processor.setup] Agent setup. Remember to stop the " \
            "ssh-agent service in an Admin Powershell once finished!"
            )


    def get_path_to_log_on_server(self, login_method):
        log_name = f"{login_method}-eval.log"
        return f"{client_secrets.LOG_STORAGE_PATH_AT_ORIGIN}/{log_name}"


    def fetch_and_store_log(
            self, 
            login_method,
            test_length,
            number_of_users_used_in_test
            ):
        # This pattern is used on all local log files to filter out all the
        # log files, who were created during a test using the supplied login
        # method, as well as the supplied number of users and the supplied
        # test length.
        local_log_file_pattern = regex.compile(
            f"{login_method}-eval-{test_length}-" \
            f"{number_of_users_used_in_test}" \
            f"{r'-\d+\.log'}"
            )

        # We want to save our log in the following pattern:

        # {login_method}-eval-{test_length}-{num_users}-{id}.log

        # For this we need to know how many logs, who are using the supplied
        # login method, the supplied number of users and the supplied test_
        # length, already exist, so that we do not overwrite any existing log
        # files.
        id_for_next_log = 1
        for file_name in os.listdir(client_secrets.LOG_STORAGE_PATH):
            if local_log_file_pattern.match(file_name):
                id_for_next_log += 1
        
        local_log_file_name = f"{login_method}-eval-{test_length}-" \
            f"{number_of_users_used_in_test}-{id_for_next_log}.log"
        
        path_to_log = "" \
            f"{client_secrets.LOG_STORAGE_PATH}/{local_log_file_name}"
        
        # This will ask for a password, as I can't pass a password to scp or
        # ssh via options. There are security risks involved in doing so, as
        # the password isn't encoded on the command line and is clearly visi-
        # le in the shell history or something.

        path_to_log_on_server = self.get_path_to_log_on_server(login_method)
        subprocess.run(
            [
            "scp", 
            f"{client_secrets.CONNECTION}:{path_to_log_on_server}",
            path_to_log
            ],
        )

        # We return the path to the log here to use it later on.
        return path_to_log


    def get_eval_time_from_line(self, line):
        return float(line.split(" ")[-1].rstrip())


    def transform_oidc_log_into_dict(self, oidc_log):
        # Ordering in the log cannot be guaranteed, so multiple counter var-
        # iables are necessary to almost correctly keep track of the data for
        # the user.
        #
        # I say "almost" here, because of the following case:
        # 1. "t_user_1" is redirected, but "complete_login" takes ages
        # 2. Now "t_user_2" is redirected and "complete_login" runs insanely
        #    fast for some reason.
        # 3. The "complete_login" time for "t_user_2" is now above the "com-
        #    plete_login" time for "t_user_1"
        # In this scenario the "complete_login" time of "t_user_2" would be
        # written into the data of "t_user_1". This is not ideal but shouldn't
        # really matter.
        log_data = {}
        redirect_current_test_user_id = 0
        complete_login_current_test_user_id  = 0
        dispatch_current_test_user_id = 0
        for line in oidc_log:
            if "INFO" not in line:
                # In this case we read a DEBUG line, which is of no importance
                continue
            if "redirect" in line:
                # Every encountered redirect means that we are looking at a
                # new user.
                redirect_current_test_user_id += 1
                log_data[f"t_user_{redirect_current_test_user_id}"] = {
                    "redirect_time": self.get_eval_time_from_line(line)
                }
                # We are done with this line
                continue
            if "complete_login" in line:
                complete_login_current_test_user_id += 1
                user = log_data[
                    f"t_user_{complete_login_current_test_user_id}"
                    ]
                # This expands the user data by "complete_login_time" in log_
                # data, because we didn't copy the user from log_data by val-
                # ue, but by reference. 
                user["complete_login_time"] = \
                    self.get_eval_time_from_line(line)
                # We are done with this line
                continue
            if "dispatch" in line:
                dispatch_current_test_user_id += 1
                user = log_data[
                    f"t_user_{dispatch_current_test_user_id}"
                    ]
                user["dispatch_time"] = \
                    self.get_eval_time_from_line(line)
        
        return log_data


    def transform_saml_log_into_dict(self, saml_log):
        # Ordering in the log cannot be guaranteed, so multiple counter vari-
        # ables are necessary to almost correctly keep track of the data for
        # the user.
        #
        # I say "almost" here, because of the following case:
        # 1. "t_user_1" is redirected, but "dispatch" in the ACSView takes
        #    ages
        # 2. Now "t_user_2" is redirected and "dispatch" in the ACSView runs
        #    insanely fast for some reason.
        # 3. The "dispatch" time for "t_user_2" is now above the "dispatch"
        #    time for "t_user_1"
        # In this scenario the "dispatch" time of "t_user_2" would be written
        # into the data of "t_user_1". This is not ideal but shouldn't really
        # matter.
        log_data = {}
        redirect_current_test_user_id = 0
        acs_dispatch_current_test_user_id  = 0
        fin_acs_dispatch_current_test_user_id = 0
        for line in saml_log:
            if "INFO" not in line:
                # In this case we read a DEBUG line, which is of no importance
                continue
            if "redirect" in line:
                # Every encountered redirect means that we are looking at a
                # new user.
                redirect_current_test_user_id += 1
                log_data[f"t_user_{redirect_current_test_user_id}"] = {
                    "redirect_time": self.get_eval_time_from_line(line)
                }
                # We are done with this line
                continue
            if "dispatch" in line and ".ACSView" in line:
                acs_dispatch_current_test_user_id += 1
                user = log_data[
                    f"t_user_{acs_dispatch_current_test_user_id}"
                    ]
                # This expands the user data by "acs_dispatch_time" in log-
                # _data, because we didn't copy the user from log_data by val-
                # ue, but byreference. 
                user["acs_dispatch_time"] = \
                    self.get_eval_time_from_line(line)
                # We are done with this line
                continue
            if "dispatch" in line and ".FinishACSView" in line:
                fin_acs_dispatch_current_test_user_id += 1
                user = log_data[
                    f"t_user_{fin_acs_dispatch_current_test_user_id}"
                    ]
                user["finish_acs_dispatch_time"] = \
                    self.get_eval_time_from_line(line)

        return log_data


    def change_file_extension_in_path(self, path_to_log, new_extension):
        return '.'.join([path_to_log.split(".")[0], new_extension])


    def serialize_log_data_into_json(self, log_data, path_to_log):
        path_to_log_json = self.change_file_extension_in_path(
            path_to_log, 
            "json"
            )
        with open(path_to_log_json, "w") as json_file:
            json.dump(log_data, json_file, indent = 4)


    def is_serialized(self, path_to_log):
        return os.path.isfile(
            self.change_file_extension_in_path(path_to_log, "json")
            )


    def is_login_method_valid(self, login_method):
        return login_method == "oidc" or login_method == "saml"


    def is_number_of_users_valid(self, number_of_users):
        return (number_of_users > 0) and (number_of_users <= 1000)


    def clear_log_on_server(self, login_method):
        path_to_log_on_server = self.get_path_to_log_on_server(login_method)
        subprocess.run(
            [
            "ssh",
            client_secrets.CONNECTION,
            f"truncate -s 0 {path_to_log_on_server}"
            ]
        )


    def process_test_log(
            self,
            login_method,
            test_length,
            number_of_users_used_in_test
            ):

        if not self.is_login_method_valid(login_method):
            return
        
        if not self.is_number_of_users_valid(number_of_users_used_in_test):
            return

        # In order for processing to go smoothly, we need an SSH-Agent to re-
        # member our login data to the Service.
        if not self.is_ssh_agent_setup():
            self.setup_ssh_agent()

        # We now know that the login method is valid and the number of users
        # used makes sense, so we can now fetch the logs.
        path_to_log = self.fetch_and_store_log(
            login_method, 
            test_length, 
            number_of_users_used_in_test
            )

        # We only need to serialize a log once. The current implementation
        # would however doesn't allow a comparison of the file that is to be
        # downloaded with the last file that has been downloaded. Maybe in the
        # future this could be implemented, but for now this check is unneces-
        # sary. I will leave the code in just in case.
        if self.is_serialized(path_to_log):
            return
        
        log_file = open(path_to_log)
        log_data = {}
        if login_method == "oidc":
            log_data = self.transform_oidc_log_into_dict(log_file)
        elif login_method == "saml":
            log_data = self.transform_saml_log_into_dict(log_file)
        log_file.close()

        self.serialize_log_data_into_json(log_data, path_to_log)

        self.clear_log_on_server(login_method)