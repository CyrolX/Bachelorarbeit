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
        

    def process_ssh_command(self, connection, command, return_out = False):
        with subprocess.Popen(
            f"ssh {connection} {command}",
            stdout = subprocess.PIPE, 
            creationflags=subprocess.CREATE_NO_WINDOW
            ) as process:
            try:
                out, err = process.communicate(timeout=10)
                if return_out:
                    return out
            except subprocess.TimeoutExpired:
                process.send_signal(signal.CTRL_BREAK_EVENT)
                process.kill()
                out, err = process.communicate()
                if return_out:
                    return out


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
        access_current_test_user_id = 0
        decode_current_test_user_id = 0
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
            if "get_access_token" in line:
                access_current_test_user_id += 1
                user = log_data[
                    f"t_user_{access_current_test_user_id}"
                    ]
                
                user["get_access_token_time"] = \
                    self.get_eval_time_from_line(line)
                continue
            if "_decode_id_token" in line:
                decode_current_test_user_id += 1
                user = log_data[
                    f"t_user_{decode_current_test_user_id}"
                    ]
                
                user["decode_id_token_time"] = \
                    self.get_eval_time_from_line(line)
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
        build_auth_current_test_user_id = 0
        login_current_test_user_id = 0
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
            if "build_auth" in line:
                build_auth_current_test_user_id += 1
                user = log_data[
                    f"t_user_{build_auth_current_test_user_id}"
                    ]
                user["build_auth_time"] = \
                    self.get_eval_time_from_line(line)
            if "login" in line:
                login_current_test_user_id += 1
                user = log_data[
                    f"t_user_{build_auth_current_test_user_id}"
                    ]
                user["login_time"] = \
                    self.get_eval_time_from_line(line)
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
        command = f"\"truncate -s 0 {path_to_log_on_server}\""
        self.process_ssh_command(client_secrets.CONNECTION, command)

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


    def initialize_basic_resource_dict(self):
        # The 'io' entry is empty and is expanded according to the used hard
        # drives.
        basic_resource_dict = {
                'cpu': {
                    'timestamps': [],
                    'total_cpu_time': [],
                    'user_space_cpu_time': [],
                    'kernel_cpu_time': [],
                    'run_periods': [],
                    'throttled_periods': [],
                    'total_throttled_time': []
                },
                'memory': {
                    'timestamps': [],
                    'anonymous_memory': [],
                    'file_system_cache_memory': [],
                    'kernel_memory': []
                },
                'io' : {}
            }
        
        return basic_resource_dict
        
    # It is expected, that hdd_identifier is supplied in MAJ:MIN form.
    def get_hdd_info(self, hdd_owner, hdd_identifier):
        command = "\"lsblk -io KNAME,MAJ:MIN,SIZE | " \
            f"grep '{hdd_identifier}'\""
        
        if hdd_owner == "sp":
            connection = client_secrets.CONNECTION
        elif hdd_owner == "idp":
            connection = client_secrets.IDP_CONNECTION

        hdd_info = self.process_ssh_command(
            connection,
            command,
            return_out = True
            )
        
        hdd_info = regex.split(' +', hdd_info.decode('utf-8').rstrip())
        # This is a list containing the hdd device name at index 0, the ID at
        # index 1 and the size at index 2.
        return hdd_info
    
    # It is expected, that the hdd_identifiers are supplied in MAJ:MIN form
    def get_hdd_dict(self, hdd_owner, hdd_identifier):

        hdd_info = self.get_hdd_info(hdd_owner, hdd_identifier)
        # We assume no bytes are ever discarded and as such exclude
        # discarded_bytes
        hdd_dict = {
            'name': hdd_info[0],
            'size': hdd_info[2],
            'timestamps': [],
            'read_bytes': [],
            'written_bytes': [],
            'read_io_ops': [],
            'write_io_ops': []
        }
        
        return hdd_dict


    def read_cpu_entry(self, record_entry, record_data):
        # The first line must be processed separately to obtain the cgroup.
        split_line = record_entry[0].split(" ")
        cgroup = split_line[0]
        timestamp = split_line[2]
        # Only with the cgroup can we get the correct dict_entry out of the
        # record_data
        cpu_data = record_data[cgroup]['cpu']
        cpu_data['timestamps'].append(int(timestamp))
        # We need to be careful here, as throttling could lead to an empty
        # record entry.
        if len(record_entry) == 1:
            cpu_data['total_cpu_time'].append(0)
            cpu_data['user_space_cpu_time'].append(0)
            cpu_data['kernel_cpu_time'].append(0)
            cpu_data['run_periods'].append(0)
            cpu_data['throttled_periods'].append(0)
            cpu_data['total_throttled_time'].append(0)
            return
        # The structure of the record is known, which is why there is no need
        # for a for loop here.
        split_line = record_entry[1].split(" ")
        cpu_data['total_cpu_time'].append(int(split_line[1]))
        split_line = record_entry[2].split(" ")
        cpu_data['user_space_cpu_time'].append(int(split_line[1]))
        split_line = record_entry[3].split(" ")
        cpu_data['kernel_cpu_time'].append(int(split_line[1]))
        # The fourth line contains core_sched.force_idle_usec and is ignored.
        if len(record_entry) > 5:
            split_line = record_entry[5].split(" ")
            cpu_data['run_periods'].append(int(split_line[1]))
            split_line = record_entry[6].split(" ")
            cpu_data['throttled_periods'].append(int(split_line[1]))
            split_line = record_entry[7].split(" ")
            cpu_data['total_throttled_time'].append(int(split_line[1]))
            # Line 9 and 10 contain nr_bursts and burst_usec and are ignored.
        else:
            # If there aren't more than 5 lines, we get no run_periods etc.
            # Just in case we get them we record 0 here. This is done so that
            # the timestamps continue to index the entire measurement.
            cpu_data['run_periods'].append(0)
            cpu_data['throttled_periods'].append(0)
            cpu_data['total_throttled_time'].append(0)

    def read_memory_entry(self, record_entry, record_data):
        split_line = record_entry[0].split(" ")
        cgroup = split_line[0]
        timestamp = split_line[2]

        memory_data = record_data[cgroup]['memory']
        memory_data['timestamps'].append(int(timestamp))

        # We need to be careful here, as throttling could lead to an empty
        # record entry.
        if len(record_entry) == 1:
            memory_data['anonymous_memory'].append(0)
            memory_data['file_system_cache_memory'].append(0)
            memory_data['kernel_memory'].append(0)
            return
        # The structure of the record is known, which is why there is no need
        # for a for loop here.
        split_line = record_entry[1].split(" ")
        memory_data['anonymous_memory'].append(int(split_line[1]))
        split_line = record_entry[2].split(" ")
        memory_data['file_system_cache_memory'].append(int(split_line[1]))
        split_line = record_entry[3].split(" ")
        memory_data['kernel_memory'].append(int(split_line[1]))

    def read_io_entry(self, data_owner, record_entry, record_data):
        # In this case no hard drive is present in the record.
        if len(record_entry) == 1:
            return
        
        split_line = record_entry[0].split(" ")
        cgroup = split_line[0]
        timestamp = split_line[2]

        io_data = record_data[cgroup]['io']
        # The structure of the record is unknown, which is why a for loop is
        # used here.
        record_entry = record_entry[1:]
        for line in record_entry:
            # Every line follows the following format:
            # <id> <rbytes>=<num> <wbytes>=<num> <rios>=<num> <wios>=<num> \
            # <dbytes>=<num> <dios>=<num>
            split_line = line.split(" ")
            # If an ID is unknown, create a dictionary entry for it.
            if split_line[0] not in io_data.keys():
                io_data[split_line[0]] = self.get_hdd_dict(
                    data_owner, 
                    split_line[0]
                    )
            # Every line has a different hard drive associated with it, which
            # is why we assign in the loop.
            hdd_data = io_data[split_line[0]]
            hdd_data['timestamps'].append(int(timestamp))
            hdd_data['read_bytes'].append(int(split_line[1].split("=")[1]))
            hdd_data['written_bytes'].append(int(split_line[2].split("=")[1]))
            hdd_data['read_io_ops'].append(int(split_line[3].split("=")[1]))
            hdd_data['write_io_ops'].append(int(split_line[4].split("=")[1]))
            

    #TODO: Write to file.
    def transform_resmon_record_into_dict(
            self,
            data_owner,
            resmon_record
            ):
        
        if data_owner == "sp":
            record_data = {
                'eval.slice' : self.initialize_basic_resource_dict(),
                'nginx': self.initialize_basic_resource_dict(),
                'gunicorn': self.initialize_basic_resource_dict()
            }
        elif data_owner == "idp":
            record_data = {
                'docker' : self.initialize_basic_resource_dict(),
                'keycloak': self.initialize_basic_resource_dict(),
                'postgres': self.initialize_basic_resource_dict(),
                'caddy': self.initialize_basic_resource_dict()
            }

        with open(resmon_record) as record:
            record_entry = []
            entry_type = None
            for line in record:
                if not line:
                    break
                # The first line always follows the following pattern:
                # <cgroup> <entry_type> <timestamp_in_nanoseconds>
                # This check also checks if this is the first line of the
                # entry.
                if not entry_type:
                    entry_type = line.split(" ")[1]
                elif '+---+' in line and entry_type == "cpu":
                    self.read_cpu_entry(
                        record_entry,
                        record_data
                        )
                    # Cleaning up for the next entry.
                    record_entry = []
                    entry_type = None
                    continue
                elif '+---+' in line and entry_type == "memory":
                    self.read_memory_entry(
                        record_entry,
                        record_data
                        )
                    record_entry = []
                    entry_type = None
                    continue
                elif '+---+' in line:
                    self.read_io_entry(
                        data_owner,
                        record_entry,
                        record_data
                        )
                    record_entry = []
                    entry_type = None
                    continue

                record_entry.append(line.rstrip())
        
        return record_data


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
        
        command = f"\"truncate -s 0 {path_to_record_on_server}\""
        self.process_ssh_command(connection, command)


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
        sp_record_data = self.transform_resmon_record_into_dict(
            "sp",
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
        idp_record_data = self.transform_resmon_record_into_dict(
            "idp",
            path_to_record
            )
        self.serialize_data_into_json(idp_record_data, path_to_record)
        self.clear_resmon_record("idp")