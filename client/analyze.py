import json
import matplotlib
import numpy
import os
import re as regex
from secret import client_secrets
import subprocess

OIDC_EVAL_TAGS = ["redirect", "complete_login", "dispatch"]


def fetch_and_store_log(
        login_method,
        test_length,
        number_of_users_used_in_test
        ):
    # We can't fetch logs that do not exist.
    if not (login_method == "oidc" or login_method == "saml"):
        return
    
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
    
    # This will ask for a password, as I can't pass a password to scp or ssh
    # via options. There are security risks involved in doing so, as the pass-
    # word isn't encoded on the command line and is clearly visible in the
    # shell history or something.
    command_return = subprocess.run(
            [
            "scp", 
            f"{client_secrets.CONNECTION}/{log_name_on_server}",
            f"{client_secrets.LOG_STORAGE_PATH}/{local_log_file_name}"
            ],
        )


def serialize_oidc_log_into_json(path_to_oidc_log):
    # Replaces the file extension .log with .json
    path_to_oidc_log_json = '.'.join([path_to_oidc_log.split(".")[0], "json"])
    # The log only needs to be serialized once, so we check if it has already
    # been serialized, and return if thats the case.
    if os.path.isfile(path_to_oidc_log_json):
        return
    # We don't use with here to save on indents.
    oidc_log = open(path_to_oidc_log, "r")
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
        # As the evaluation time can always be found at the end of the line,
        # we split it here to access said end.
        split_line = line.split(" ")
        if "redirect" in line:
            # Every encountered redirect means that we are looking at a new
            # user.
            redirect_current_test_user_id += 1
            log_data[f"t_user_{redirect_current_test_user_id}"] = {
                "redirect_time": float(split_line[-1].rstrip())
            }
            # We are done with this line
            continue
        if "complete_login" in line:
            complete_login_current_test_user_id += 1
            user = log_data[f"t_user_{complete_login_current_test_user_id}"]
            # This expands the user data by "complete_login_time" in log_data,
            # because we didn't copy the user from log_data by value, but by
            # reference. 
            user["complete_login_time"] = float(split_line[-1].rstrip())
            # We are done with this line
            continue
        if "dispatch" in line:
            dispatch_current_test_user_id += 1
            user = log_data[f"t_user_{dispatch_current_test_user_id}"]
            user["dispatch_time"] = float(split_line[-1].rstrip())
    
    oidc_log.close()
    
    # Serialize the log data.
    with open(path_to_oidc_log_json, "w") as json_file:
        json.dump(log_data, json_file, indent = 4, )


def serialize_saml_log_into_json(path_to_saml_log):
    # Replaces the file extension .log with .json
    path_to_saml_log_json = '.'.join([path_to_saml_log.split(".")[0], "json"])
    # The log only needs to be serialized once, so we check if it has already
    # been serialized, and return if thats the case.
    if os.path.isfile(path_to_saml_log_json):
        return
    # We don't use with here to save on indents.
    saml_log = open(path_to_saml_log, "r")
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
        # As the evaluation time can always be found at the end of the line,
        # we split it here to access said end.
        split_line = line.split(" ")
        if "redirect" in line:
            # Every encountered redirect means that we are looking at a new
            # user.
            redirect_current_test_user_id += 1
            log_data[f"t_user_{redirect_current_test_user_id}"] = {
                "redirect_time": float(split_line[-1].rstrip())
            }
            # We are done with this line
            continue
        if "dispatch" in line and ".ACSView" in line:
            acs_dispatch_current_test_user_id += 1
            user = log_data[f"t_user_{acs_dispatch_current_test_user_id}"]
            # This expands the user data by "acs_dispatch_time" in log_data,
            # because we didn't copy the user from log_data by value, but by
            # reference. 
            user["acs_dispatch_time"] = float(split_line[-1].rstrip())
            # We are done with this line
            continue
        if "dispatch" in line and ".FinishACSView" in line:
            fin_acs_dispatch_current_test_user_id += 1
            user = log_data[f"t_user_{fin_acs_dispatch_current_test_user_id}"]
            user["finish_acs_dispatch_time"] = float(split_line[-1].rstrip())
    
    saml_log.close()
    
    # Serialize the log data.
    with open(path_to_saml_log_json, "w") as json_file:
        json.dump(log_data, json_file, indent = 4, )


if __name__ == "__main__":
    fetch_and_store_log("saml", 300, 10)
    serialize_saml_log_into_json(
        f"{client_secrets.LOG_STORAGE_PATH}/saml-eval-300-10-1.log"
        )