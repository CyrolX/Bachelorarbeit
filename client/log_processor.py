import json
import os
import re as regex
from secret import client_secrets
import signal
import subprocess

class EvaluationLogProcessor:

    def __init__(
            self,
            printer = print,
            printer_args = [],
            printer_kwargs = {}
            ):
        """
        Instantiates an EvaluationLogProcessor
        """
        self.printer = printer
        self.printer_args = printer_args
        self.printer_kwargs = printer_kwargs

##############################################################################
#                               U T I L I T Y                                #
##############################################################################

    def is_ssh_agent_setup(self):
        # If the ssh-agent service isn't running, this will return with code
        # 2.
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


    # This function has been changed so it can also be used by the resmon
    # record processing logic
    def change_file_extension_in_path(self, path, new_extension):
        return '.'.join([path.split(".")[0], new_extension])


    # This function has been changed so it can also be used by the resmon
    # record processing logic
    def serialize_data_into_json(self, data, path):
        path_to_json = self.change_file_extension_in_path(
            path, 
            "json"
            )
        with open(path_to_json, "w") as json_file:
            json.dump(data, json_file, indent = 4)


    # This function has been changed so it can also be used by the resmon
    # record processing logic
    def is_serialized(self, path):
        return os.path.isfile(
            self.change_file_extension_in_path(path, "json")
            )
    
##############################################################################
#             E V A L U A T I O N   L O G   P R O C E S S I N G              #
##############################################################################

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


    def is_login_method_valid(self, login_method):
        return login_method == "oidc" or login_method == "saml"


    def is_number_of_users_valid(self, number_of_users):
        return (number_of_users > 0) and (number_of_users <= 1000)


    def clear_log_on_server(self, login_method):
        path_to_log_on_server = self.get_path_to_log_on_server(login_method)
        with subprocess.Popen(
            f"ssh {client_secrets.CONNECTION} truncate -s 0 " \
            f"{path_to_log_on_server}", \
            stdout = subprocess.PIPE, \
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP \
            ) as process:
            try:
                out, err = process.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                process.send_signal(signal.CTRL_BREAK_EVENT)
                process.kill()
                out, err = process.communicate()

        # YOU WERE THE CHOSEN ONE!
        #subprocess.run(
        #    [
        #    "ssh",
        #    client_secrets.CONNECTION,
        #    f"truncate -s 0 {path_to_log_on_server}"
        #    ]
        #)


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
        # however doesn't allow a comparison of the content of the file that
        # is to be downloaded with the content of the last file that has been
        # downloaded. Maybe in the future this could be implemented, but for
        # now this check is unnecessary. I will leave the code in just in
        # case.
        if self.is_serialized(path_to_log):
            return
        
        # This is not good for particularly large log files, as we write the
        # entire log file into memory here. This will be changed in the future
        log_file_lines = []
        with open(path_to_log) as log_file:
            log_file_lines = log_file.readlines()
        
        log_data = {}
        if login_method == "oidc":
            log_data = self.transform_oidc_log_into_dict(log_file_lines)
        elif login_method == "saml":
            log_data = self.transform_saml_log_into_dict(log_file_lines)

        self.serialize_data_into_json(log_data, path_to_log)

        self.clear_log_on_server(login_method)

##############################################################################
#       R E S O U R C E   M O N I T O R   L O G   P R O C E S S I N G        #
##############################################################################

    def fetch_and_store_resource_measurements(
            self, 
            login_method,
            test_length,
            number_of_users_used_in_test,
            origin
            ):

        local_record_file_pattern = regex.compile(
            f"{login_method}-eval-{test_length}-" \
            f"{number_of_users_used_in_test}-{origin}-resmon" \
            f"{r'-\d+\.txt'}"
            )

        # We want to save our log in the following pattern:
        # {login_method}-eval-{test_length}-{num_users}-resmon-{id}.log
        id_for_next_record = 1
        for file_name in os.listdir(client_secrets.LOG_STORAGE_PATH):
            if local_record_file_pattern.match(file_name):
                id_for_next_record += 1
        
        local_record_file_name = f"{login_method}-eval-{test_length}-" \
            f"{number_of_users_used_in_test}-{origin}-resmon-" \
            f"{id_for_next_record}.txt"
        
        path_to_record = "" \
            f"{client_secrets.LOG_STORAGE_PATH}/{local_record_file_name}"

        if origin == "sp":
            path_to_record_on_server = "" \
                f"{client_secrets.LOG_STORAGE_PATH_AT_ORIGIN}/" \
                "resource_usage.txt"
            connection = client_secrets.CONNECTION
        elif origin == "idp":
            path_to_record_on_server = "" \
                f"{client_secrets.LOG_STORAGE_PATH_AT_IDP}/" \
                "resource_usage.txt"
            connection = client_secrets.IDP_CONNECTION
        else:
            self.printer(f"[DEBUG] Origin {origin} doesn't exist.")
            return

        subprocess.run(
            [
            "scp", 
            f"{connection}:{path_to_record_on_server}",
            path_to_record
            ],
        )

        # We return the path to the log here to use it later on.
        return path_to_record

    def append_to_record_data(self, record_data, data, owner):
        # data follows the following pattern:
        # cpu, ram, in, out
        # CPU is given as CPU Time
        record_data[f'{owner}.cpu'].append(int(data[0]))
        # RAM is given in Bytes
        record_data[f'{owner}.ram'].append(int(data[1]))
        # int(data) if data != str else 0 works, because the first statement
        # is executed only if the conditional evaluates to True.
        # I/O is given in Bytes.
        record_data[f'{owner}.io.in'].append(
            int(data[2]) if data[2] != '-' else 0, 
            )
        record_data[f'{owner}.io.out'].append(  
            int(data[3]) if data[3] != '-' else 0
            )

    #TODO: Write to file.
    def transform_sp_resmon_record_into_dict(self, resmon_record):
        sp_record_data = {
            'timestamps': [],
            'eval.slice.cpu': [],
            'eval.slice.ram': [],
            'eval.slice.io.in': [],
            'eval.slice.io.out': [],
            'gunicorn.cpu': [],
            'gunicorn.ram': [],
            'gunicorn.io.in': [],
            'gunicorn.io.out': [],
            'nginx.cpu': [],
            'nginx.ram': [],
            'nginx.io.in': [],
            'nginx.io.out': [],
        }

        with open(resmon_record) as record:
            # The line containing the timestamp follows the structure:
            # timestamp:{timestamp}
            # Every other line follows the following structure:
            # cgroup, tasks, cpu, ram, in, out
            for line in record:
                if "timestamp" in line:
                    sp_record_data["timestamps"].append(
                        int(line.rstrip().split(":")[1])
                    )
                    continue
                # If the line doesn't contain the timestamp it will be filled
                # with spaces so we remove them here.
                line = regex.split(' +', line.rstrip())
                if "gunicorn" in line[0]:
                    self.append_to_record_data(
                        sp_record_data,
                        line[2:],
                        'gunicorn'
                        )
                elif "nginx" in line[0]:
                    self.append_to_record_data(
                        sp_record_data,
                        line[2:],
                        'nginx'
                        )
                else:
                    self.append_to_record_data(
                        sp_record_data,
                        line[2:],
                        'eval.slice'
                        )
        
        return sp_record_data
    

    def transform_idp_resmon_record_into_dict(self, resmon_record):
        idp_record_data = {
            'timestamps': [],
            'docker.cpu': [],
            'docker.ram': [],
            'docker.io.in': [],
            'docker.io.out': [],
            'keycloak.cpu': [],
            'keycloak.ram': [],
            'keycloak.io.in': [],
            'keycloak.io.out': [],
            'postgres.cpu': [],
            'postgres.ram': [],
            'postgres.io.in': [],
            'postgres.io.out': [],
            'caddy.cpu': [],
            'caddy.ram': [],
            'caddy.io.in': [],
            'caddy.io.out': [],
        }

        keycloak_container_id = None
        postgres_container_id = None
        caddy_container_id = None


        with open(resmon_record) as record:
            for line_number, line in enumerate(record):
                if line_number <= 2:
                    if "keycloak" in line:
                        keycloak_container_id = line.split(" ")[0]
                        continue
                    elif "postgres" in line:
                        postgres_container_id = line.split(" ")[0]
                        continue
                    elif "caddy" in line:
                        caddy_container_id = line.split(" ")[0]
                        continue
                line = regex.split(' +', line.rstrip())
                if keycloak_container_id in line[0]:
                    self.append_to_record_data(
                        idp_record_data,
                        line[2:],
                        'keycloak'
                        )
                elif postgres_container_id in line[0]:
                    self.append_to_record_data(
                        idp_record_data,
                        line[2:],
                        'postgres'
                        )
                elif caddy_container_id in line[0]:
                    self.append_to_record_data(
                        idp_record_data,
                        line[2:],
                        'caddy'
                        )
                else:
                    self.append_to_record_data(
                        idp_record_data,
                        line[2:],
                        'docker'
                        )


    def clear_resmon_record(self, origin):
        if origin == "sp":
            path_to_record_on_server = "" \
                f"{client_secrets.LOG_STORAGE_PATH_AT_ORIGIN}/" \
                "resource_usage.txt"
            connection = client_secrets.CONNECTION
        elif origin == "idp":
            path_to_record_on_server = "" \
                f"{client_secrets.LOG_STORAGE_PATH_AT_IDP}/" \
                "resource_usage.txt"
            connection = client_secrets.IDP_CONNECTION
        else:
            self.printer(f"[DEBUG] Origin {origin} doesn't exist.")
            return
        with subprocess.Popen(
            f"ssh {connection} truncate -s 0 {path_to_record_on_server}",
            stdout = subprocess.PIPE,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP
            ) as process:
            try:
                out, err = process.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                process.send_signal(signal.CTRL_BREAK_EVENT)
                process.kill()
                out, err = process.communicate()


    def process_resmon_records(
            self,
            login_method,
            test_length,
            number_of_users_used_in_test
            ):
        
        path_to_record = self.fetch_and_store_resource_measurements(
            login_method,
            test_length,
            number_of_users_used_in_test,
            "sp"
            )
        sp_record_data = self.transform_sp_resmon_record_into_dict(
            path_to_record
            )
        self.serialize_data_into_json(sp_record_data, path_to_record)
        self.clear_resmon_record("sp")

        path_to_record = self.fetch_and_store_resource_measurements(
            login_method,
            test_length,
            number_of_users_used_in_test,
            "idp"
            )
        idp_record_data = self.transform_idp_resmon_record_into_dict(
            path_to_record
            )
        self.serialize_data_into_json(idp_record_data, path_to_record)
        self.clear_resmon_record("idp")