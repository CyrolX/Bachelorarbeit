import json
import matplotlib
import numpy
import os
import re as regex
from secret import client_secrets
import subprocess


def fetch_and_store_log(
        login_method,
        test_length,
        number_of_users_used_in_test
        ):
    log_name_on_server = f"{login_method}-eval.log"
    # This pattern is used on all local log files to filter out all the log
    # files, who were created during a test using the supplied login method,
    # as well as the supplied number of users and the supplied test length.
    local_log_file_pattern = regex.compile(
        f"{login_method}-eval-{test_length}-{number_of_users_used_in_test}" \
        f"{r'-\d+\.log'}"
        )

    # We want to save our log in the following pattern:

    # {login_method}-eval-{test_length}-{num_users}-{id}.log

    # For this we need to know how many logs, who are using the supplied login
    # method, the supplied number of users and the supplied test_length, al-
    # ready exist, so that we do not overwrite any existing log files.
    id_for_next_log = 1
    for file_name in os.listdir(client_secrets.LOG_STORAGE_PATH):
        if local_log_file_pattern.match(file_name):
            id_for_next_log += 1
    
    local_log_file_name = f"{login_method}-eval-{test_length}-" \
        f"{number_of_users_used_in_test}-{id_for_next_log}.log"
    
    path_to_log = f"{client_secrets.LOG_STORAGE_PATH}/{local_log_file_name}"
    
    # This will ask for a password, as I can't pass a password to scp or ssh
    # via options. There are security risks involved in doing so, as the pass-
    # word isn't encoded on the command line and is clearly visible in the
    # shell history or something.
    subprocess.run(
        [
        "scp", 
        f"{client_secrets.CONNECTION}/{log_name_on_server}",
        path_to_log
        ],
    )

    # We return the path to the log here to use it later on.
    return path_to_log


def get_eval_time_from_line(line):
    return float(line.split(" ")[-1].rstrip())


def transform_oidc_log_into_dict(oidc_log):
    # Ordering in the log cannot be guaranteed, so multiple counter variables
    # are necessary to almost correctly keep track of the data for the user.
    #
    # I say "almost" here, because of the following case:
    # 1. "t_user_1" is redirected, but "complete_login" takes ages
    # 2. Now "t_user_2" is redirected and "complete_login" runs insanely fast
    #    for some reason.
    # 3. The "complete_login" time for "t_user_2" is now above the "complete-
    #    _login" time for "t_user_1"
    # In this scenario the "complete_login" time of "t_user_2" would be writ-
    # ten into the data of "t_user_1". This is not ideal but shouldn't really
    # matter.
    log_data = {}
    redirect_current_test_user_id = 0
    complete_login_current_test_user_id  = 0
    dispatch_current_test_user_id = 0
    for line in oidc_log:
        if not "INFO" in line:
            # In this case we read a DEBUG line, which is of no importance
            continue
        if "redirect" in line:
            # Every encountered redirect means that we are looking at a new
            # user.
            redirect_current_test_user_id += 1
            log_data[f"t_user_{redirect_current_test_user_id}"] = {
                "redirect_time": get_eval_time_from_line(line)
            }
            # We are done with this line
            continue
        if "complete_login" in line:
            complete_login_current_test_user_id += 1
            user = log_data[f"t_user_{complete_login_current_test_user_id}"]
            # This expands the user data by "complete_login_time" in log_data,
            # because we didn't copy the user from log_data by value, but by
            # reference. 
            user["complete_login_time"] = get_eval_time_from_line(line)
            # We are done with this line
            continue
        if "dispatch" in line:
            dispatch_current_test_user_id += 1
            user = log_data[f"t_user_{dispatch_current_test_user_id}"]
            user["dispatch_time"] = get_eval_time_from_line(line)
    
    return log_data


def transform_saml_log_into_dict(saml_log):
    # Ordering in the log cannot be guaranteed, so multiple counter variables
    # are necessary to almost correctly keep track of the data for the user.
    #
    # I say "almost" here, because of the following case:
    # 1. "t_user_1" is redirected, but "dispatch" in the ACSView takes ages
    # 2. Now "t_user_2" is redirected and "dispatch" in the ACSView runs in-
    #    sanely fast for some reason.
    # 3. The "dispatch" time for "t_user_2" is now above the "dispatch" time
    #     for "t_user_1"
    # In this scenario the "dispatch" time of "t_user_2" would be written into
    # the data of "t_user_1". This is not ideal but shouldn't really matter.
    log_data = {}
    redirect_current_test_user_id = 0
    acs_dispatch_current_test_user_id  = 0
    fin_acs_dispatch_current_test_user_id = 0
    for line in saml_log:
        if not "INFO" in line:
            # In this case we read a DEBUG line, which is of no importance
            continue
        if "redirect" in line:
            # Every encountered redirect means that we are looking at a new
            # user.
            redirect_current_test_user_id += 1
            log_data[f"t_user_{redirect_current_test_user_id}"] = {
                "redirect_time": get_eval_time_from_line(line)
            }
            # We are done with this line
            continue
        if "dispatch" in line and ".ACSView" in line:
            acs_dispatch_current_test_user_id += 1
            user = log_data[f"t_user_{acs_dispatch_current_test_user_id}"]
            # This expands the user data by "acs_dispatch_time" in log_data,
            # because we didn't copy the user from log_data by value, but by
            # reference. 
            user["acs_dispatch_time"] = get_eval_time_from_line(line)
            # We are done with this line
            continue
        if "dispatch" in line and ".FinishACSView" in line:
            fin_acs_dispatch_current_test_user_id += 1
            user = log_data[f"t_user_{fin_acs_dispatch_current_test_user_id}"]
            user["finish_acs_dispatch_time"] = get_eval_time_from_line(line)

    return log_data


def change_file_extension_in_path(path_to_log, new_extension):
    return '.'.join([path_to_log.split(".")[0], new_extension])


def serialize_log_data_into_json(log_data, path_to_log):
    path_to_log_json = change_file_extension_in_path(path_to_log, "json")
    with open(path_to_log_json, "w") as json_file:
        json.dump(log_data, json_file, indent = 4)


def is_serialized(path_to_log):
    return os.path.isfile(change_file_extension_in_path(path_to_log, "json"))


def is_login_method_valid(login_method):
    return login_method == "oidc" or login_method == "saml"


def is_number_of_users_valid(number_of_users):
    return (number_of_users > 0) and (number_of_users <= 1000)


def process_test_log(login_method, test_length, number_of_users_used_in_test):
    
    if not is_login_method_valid(login_method):
        return
    
    if not is_number_of_users_valid(number_of_users_used_in_test):
        return

    # We now know that the login method is valid and the number of users used
    # makes sense, so we can now fetch the logs.
    path_to_log = fetch_and_store_log(
        login_method, 
        test_length, 
        number_of_users_used_in_test
        )

    # We only need to serialize a log once. The current implementation would
    # however doesn't allow a comparison of the file that is to be downloaded
    # with the last file that has been downloaded. Maybe in the future this
    # could be implemented, but for now this check is unnecessary. I will
    # leave the code in just in case.
    if is_serialized(path_to_log):
        return
    
    log_file = open(path_to_log)
    log_data = {}
    if login_method == "oidc":
        log_data = transform_oidc_log_into_dict(log_file)
    elif login_method == "saml":
        log_data = transform_saml_log_into_dict(log_file)
    log_file.close()

    serialize_log_data_into_json(log_data, path_to_log)


if __name__ == "__main__":
    process_test_log("saml", 300, 10)
    #fetch_and_store_log("saml", 300, 10)
    #serialize_saml_log_into_json(
    #    f"{client_secrets.LOG_STORAGE_PATH}/saml-eval-300-10-1.log"
    #    )