import matplotlib
import numpy

OIDC_EVAL_TAGS = ["redirect", "complete_login", "dispatch"]


def process_oidc_log_into_json(path_to_oidc_log):
    log_data = {}

    # We don't use with here to save indents.
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
            redirect_current_test_user_id += 1
            log_data[f"t_user_{redirect_current_test_user_id}"] = {
                "redirect_time": split_line[-1]
            }
            # We are done with this line
            continue
        if "complete_login" in line:
            complete_login_current_test_user_id += 1
            user = log_data[f"t_user_{complete_login_current_test_user_id}"]
            # This expands the user data by "complete_login_time" in log_data,
            # because we didn't copy the user from log_data by value, but by
            # reference. 
            user["complete_login_time"] = split_line[-1]
            # We are done with this line
            continue
        if "dispatch" in line:
            dispatch_current_test_user_id += 1
            user = log_data[f"t_user_{dispatch_current_test_user_id}"]
            user["dispatch_time"] = split_line[-1]
    
    oidc_log.close()
            




if __name__ == "__main__":
    pass