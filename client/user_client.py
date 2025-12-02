from client.analyze import EvaluationAnalyzer
from client.kc_administrator import KcAdministrator
from client.log_processor import EvaluationLogProcessor
from client.resource_monitor import ResourceMonitor
import configparser
from enum import Enum
import os
from secret import client_secrets
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.wait import WebDriverWait
from selenium.common.exceptions import TimeoutException
import selenium.webdriver.support.expected_conditions as EC
import subprocess
import signal
import sys
import threading
import time

PROTECTED_APP_URL = "https://vm097.rz.uni-osnabrueck.de/protected_app"
TERMINAL_SIZE = os.get_terminal_size()
EvalState = Enum('EvalState', [
                    ('POLL_SUCCESS', 0), 
                    ('POLL_FAILURE', 1), 
                    ('EVAL_START_SUCCESS', 2), 
                    ('EVAL_START_FAILURE', 3)
                ])


def print_nice(text, top_line = False):
    """
    Prints the given text to the console with separation lines to make it more
    discernable from other printed text.

    :param text: The text to be printed to the console
    
    :param top_line: Normally the separation line is only printed under the
        text. When printing the first message, it may make sense to print an
        other line at the top. It may be more performant to remove this behavi
        our altogether and just call print_nice without any text instead of
        checking top_line on every call. Defaults to False.
    """
    if top_line:
        print(f"+{(TERMINAL_SIZE.columns - 2) * "-"}+")
    
    print(f"+ {text}")
    print(f"+{(TERMINAL_SIZE.columns - 2) * "-"}+")


def webbrowser_login(login_method, username, kc_admin):
    """
    Simulates a login from a user through a webbrowser. This fits the Webbrow
    ser-Flow for SAML and the standard flow for OIDC.

    :param login_method: Gathered from command line arguments. Either saml,
        oidc or None.
    """

    if not login_method:
        print_nice("[ERROR] No login method provided.", top_line = True)
        return

    # Works only because the login URLs are the same.
    login_url = f"https://vm097.rz.uni-osnabrueck.de/accounts/{login_method}"\
        "/keycloak/login/?process=login"
    
    # Chrome is used only because it was the first option. This can be expan-
    # ded in the future to include more Webbrowsers.
    options = webdriver.ChromeOptions()
    options.add_argument("--no-sandbox")
    options.add_argument("--headless=new")
    options.add_argument("--log-level=3")
    driver = webdriver.Chrome(options = options)
    # The Webdriver will wait for at max 10 seconds before a request is deemed
    # to be lost. every 100th of a second it is checked if there was an up-
    # date.
    wait = WebDriverWait(driver = driver, timeout = 20, poll_frequency = 0.01)

    # Route to the login_url which will instantaneously redirect us to Key-
    # cloak as configured.
    driver.get(login_url)
    # Wait until the redirect was successful and the Keycloak page is loaded
    # sufficiently
    wait.until(EC.presence_of_element_located((By.ID, "username")))
    # Saved for line 115, where we wait until the URL changes from this URL.
    last_url = driver.current_url
    #print_nice(f"[DEBUG] WEBDRIVER URL: {driver.current_url}")
    username_input_field = driver.find_element(by=By.ID, value="username")
    password_input_field = driver.find_element(by=By.ID, value="password")
    login_button = driver.find_element(by=By.ID, value="kc-login")
    username_input_field.send_keys(username)
    password_input_field.send_keys(
        kc_admin.get_test_user_password(username = username)
        )
    login_button.click()
    
    # If the URL changes, we most likely have been authenticated correctly and
    # have been redirected to /accounts/profile
    wait.until(EC.url_changes(last_url))
    #print_nice(f"[DEBUG] WEBDRIVER URL: {driver.current_url}")
    last_url = driver.current_url

    # Route to /protected_app, for which we need to be authenticated to par-
    # take in the game.
    driver.get(PROTECTED_APP_URL)
    # A wait is necessary here as well, as we can't get the page source cor-
    # rectly if we don't wait.
    wait.until(EC.url_changes(last_url))
    #print_nice(f"[DEBUG] WEBDRIVER URL: {driver.current_url}")
    #print_nice(driver.page_source)
    # Not really necessary. I just left it in for the irrational fear of cook-
    # ies being saved in between calls of client.py
    driver.delete_all_cookies()
    # This may fix a lot of bugs
    driver.quit()


def poll_websites_before_eval(login_method):
    # Polling the websites before starting the eval is important in the sense
    # that it ruins the first measurement otherwise. 
    sp_main_page = "https://vm097.rz.uni-osnabrueck.de/"
    # We poll the login page of the login method we are about to use specifi-
    # cally here.
    idp_page = f"https://vm097.rz.uni-osnabrueck.de/accounts/{login_method}"\
        "/keycloak/login/?process=login"
    options = webdriver.ChromeOptions()
    options.add_argument("--no-sandbox")
    options.add_argument("--headless=new")
    options.add_argument("--log-level=3")
    driver = webdriver.Chrome(options = options)
    wait = WebDriverWait(driver = driver, timeout = 10, poll_frequency = 0.01)
    sp_attempts = 0
    while sp_attempts < 3:
        try:
            driver.get(sp_main_page)
            wait.until(EC.presence_of_element_located((By.ID, "summary")))
            print_nice("[DEBUG | poll] Polling of SP ended")
            break
        except TimeoutException:
            print_nice("[WARN | poll] Polling of SP ended in Timeout")
            sp_attempts += 1
    if sp_attempts == 3:
        print_nice(
            "[ERROR | poll] Polling of SP failed completely. Eval corruption"\
            " highly likely."
            )
        driver.quit()
        return EvalState.POLL_FAILURE

    idp_attempts = 0
    while idp_attempts < 3:
        try:
            driver.get(idp_page)
            wait.until(EC.url_changes(idp_page))
            print_nice("[DEBUG | poll] Polling IdP " \
                       f"now at {driver.current_url}")
            wait.until(EC.presence_of_element_located((By.ID, "username")))
            print_nice("[DEBUG | poll] Polling of IdP ended")
            break
        except TimeoutException:
            print_nice("[WARN | poll] Polling of IdP ended in Timeout")
            sp_attempts += 1
    if idp_attempts == 3:
        print_nice(
            "[ERROR | poll] Polling of IdP failed completely. Eval " \
            "corruption highly likely."
            )
        driver.quit()
        return EvalState.POLL_FAILURE
    
    driver.quit()
    # Bugfix: We need to clear the log for the specified login_method here,
    # as we polled the login methods login page and as such created an entry
    # in the log. This will then break the analyzer.
    print_nice("[DEBUG | poll] Cleaning up log")
    log_deleter = EvaluationLogProcessor(print_nice)
    log_deleter.clear_log_on_server(login_method)
    print_nice("[DEBUG | poll] Log cleanup done")
    return EvalState.POLL_SUCCESS


def evaluate_login_method(
        login_method,
        evaluation_method,
        eval_time_seconds,
        number_of_users,
        resource_monitor : ResourceMonitor
        ):

    if not (evaluation_method == "browser"):
        print_nice(
            f"[FATAL | eval] Eval method {evaluation_method} is not sup" \
            "ported.",
            top_line = True
            )
        return EvalState.EVAL_START_FAILURE

    # Evaluate over 5 minutes.
    login_interval = get_login_interval(eval_time_seconds, number_of_users)
    print_nice(f"[DEBUG | eval] Login Interval: {login_interval}")
    login_threads = []
    print_nice(f"[DEBUG | eval] Starting resmon")
    resource_monitor.start_resource_monitoring()
    print_nice(f"[DEBUG | eval] Polling websites")

    eval_start_attempts = 0
    while eval_start_attempts < 3:
        if poll_websites_before_eval(login_method) == EvalState.POLL_SUCCESS:
            print_nice(f"[DEBUG | eval] Polling successful")
            break
        elif eval_start_attempts < 3:
            reset_state()
            eval_start_attempts += 1
            print_nice("[WARN | eval] Polling failed. Attempts left: " \
                       f"{3 - eval_start_attempts}"
                       )
        else:
            print_nice("[FATAL | eval] Eval start failed.")
            return EvalState.EVAL_START_FAILURE
    print_nice(f"[DEBUG | eval] Starting eval")
    kc_admin = KcAdministrator(print_nice)
    #time.sleep(5)
    for user_number in range(1, number_of_users+1):
        login_thread = threading.Thread(
            target = webbrowser_login,
            args = (login_method, f"t_user_{user_number}", kc_admin)
        )
        login_threads.append(login_thread)
        login_threads[user_number-1].start()
        time.sleep(login_interval)
    
    for login_thread in login_threads:
        login_thread.join()

    print_nice(f"[DEBUG | eval] Eval concluded. Terminating resmon.")
    resource_monitor.terminate_monitors()
    print_nice(f"[DEBUG | eval] Resmon terminated. Logging out users.")
    kc_admin.logout_all_kc_sessions(number_of_users)
    print_nice(f"[DEBUG | eval] Users logged out. Resetting state.")
    reset_state()
    print_nice(f"[DEBUG | eval] State reset. Ending Evaluation")
    return EvalState.EVAL_START_SUCCESS


def get_login_interval(eval_time_seconds, number_of_users):
    return eval_time_seconds / number_of_users

# This is not well made at the moment. My SSH-Agent logic is in the log_pro-
# cessor.py file, while I may need to use it here. Yet invoking anything with
# the log processor would just look weird. Perhaps I will just move the SSH-
# Agent logic over to the user_client itself. For the moment this has to do.
def reset_state():
    print_nice(f"[DEBUG | reset] Resetting SP.")
    with subprocess.Popen(
        f"ssh {client_secrets.CONNECTION} " \
        f"\"{client_secrets.SCRIPT_PATH_AT_ORIGIN}/restart_service.sh\"",
        stdout = subprocess.PIPE, \
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP \
        ) as process:
        try:
            out, err = process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            process.send_signal(signal.CTRL_BREAK_EVENT)
            process.kill()
            out, err = process.communicate()
    print_nice(f"[DEBUG | reset] SP reset. Resetting IdP")
    with subprocess.Popen(
        f"ssh {client_secrets.IDP_CONNECTION} " \
        f"\"{client_secrets.SCRIPT_PATH_AT_IDP}/restart_idp.sh\"",
        stdout = subprocess.PIPE, \
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP \
        ) as process:
        try:
            out, err = process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            process.send_signal(signal.CTRL_BREAK_EVENT)
            process.kill()
            out, err = process.communicate()
    print_nice(f"[DEBUG | reset] IdP reset.")


if __name__ == "__main__":
    config = configparser.ConfigParser()
    config.read(client_secrets.TEST_CONFIG_PATH)
    test_config = config["test.config"]
    print_nice(
        f"[DEBUG | config] Config parsing started.",
        top_line=True
        )
    
    login_method = test_config["login_method"]
    print_nice(f"[DEBUG | config] login_method: {login_method}")
    if login_method != "oidc" and login_method != "saml":
        print_nice(
            f"[FATAL | main] Supplied login_method ({login_method}) is " \
            "neither 'oidc' or 'saml'. login_method must be 'oidc' or " \
            "'saml'.",
            top_line = True
            )
        sys.exit(1)

    evaluation_method = test_config["evaluation_method"]
    print_nice(f"[DEBUG | config] evaluation_method: {evaluation_method}")
    if evaluation_method != "browser" and evaluation_method != "eclient":
        print_nice(
            f"[FATAL | main] Supplied evaluation_method (" \
            f"{evaluation_method}) is neither 'browser' or 'eclient'. evalu" \
            "ation_method must be 'browser' or 'eclient'.",
            top_line = True
            )
        sys.exit(1)
    # The configparser getters are no good in my opinion.
    try:
        number_of_users = int(test_config["number_of_users"])
        print_nice(f"[DEBUG | config] number_of_users: {number_of_users}")
        if number_of_users > 1000 or number_of_users < 1:
            print_nice(
                "[FATAL | main] Supplied number_of_users (" \
                f"{number_of_users}) is out of scope. number_of_users must " \
                "be between 1 and 1000 inclusive.",
                top_line = True
                )
            sys.exit(1)
        eval_time_seconds = int(test_config["eval_time_seconds"])
        print_nice(f"[DEBUG | config] eval_time_seconds: {eval_time_seconds}")
        if eval_time_seconds < 1:
            print_nice(
                f"[FATAL | main] Supplied eval_time ({eval_time_seconds}) " \
                "is out of scope. eval_time must be 1 or greater.",
                top_line = True
                )
            sys.exit(1)
        eval_test_cycles = int(test_config["eval_test_cycles"])
        print_nice(f"[DEBUG | config] eval_test_cycles: {eval_test_cycles}")
        if eval_test_cycles < 1:
            print_nice(
                f"[FATAL | main] Supplied eval_cycles ({eval_test_cycles}) " \
                "is out of scope. eval_cycles must be 1 or greater.",
                top_line = True
                )
            sys.exit(1)
        ram_limit = int(test_config["ram_limit"])
        print_nice(f"[DEBUG | config] ram_limit: {ram_limit}")
        # Do not allow anything less than 100 MB and nothing over 2 GiB. Page
        # size at the VM is 4096 Byte, meaning a 100 MB RAM Limit is basically
        # equal to a 99.999744 MB limit. The maximum amount of memory that is
        # allowed in a run is always one page, or 4096 Bytes, more than the
        # given limit. This means that the upper limit needs to be one page
        # less than the maximum available memory.
        if ram_limit < 99999744 or ram_limit > 2147479552:
            print_nice(
                f"[FATAL | main] Supplied ram_limit ({ram_limit}) is out of "\
                "scope. ram_limit must be between 99999744 and 2147483648 " \
                "inclusive.",
                top_line = True
                )
            sys.exit(1)
        cpu_limit = float(test_config["cpu_limit"])
        print_nice(f"[DEBUG | config] cpu_limit: {cpu_limit}")
        # A minimum of 10% CPU usage should be allowed
        if cpu_limit < 0.1 or cpu_limit > 1.0:
            print_nice(
                f"[FATAL | main] Supplied cpu_limit ({cpu_limit}) is out of "\
                "scope. cpu_limit must be between 0.1 and 1.0 inclusive. Be "\
                "aware of conversion errors.",
                top_line = True
                )
            sys.exit(1)
        idp_ram_limit = int(test_config["idp_ram_limit"])
        print_nice(f"[DEBUG | config] idp_ram_limit: {idp_ram_limit}")
        # Do not allow anything less than 750 MB and nothing over 4 GiB. Page
        # size at the IdP is 4096 Byte, meaning a 100 MB RAM Limit is basic-
        # ally equal to a 749.998080 MB limit. This program adds one page of
        # memory to the given limit, so the upper limit must be one page less
        # than the true upper limit
        if idp_ram_limit < 749998080 or idp_ram_limit > 4294963200:
            print_nice(
                f"[FATAL | main] Supplied idp_ram_limit ({idp_ram_limit}) is"\
                " out of scope. idp_ram_limit must be between 749998080 and "\
                "4294963200 inclusive.",
                top_line = True
                )
            sys.exit(1)
        idp_cpu_limit = float(test_config["idp_cpu_limit"])
        print_nice(f"[DEBUG | config] idp_cpu_limit: {idp_cpu_limit}")
        # A minimum of 10% CPU usage should be allowed
        if idp_cpu_limit < 0.1 or cpu_limit > 1.0:
            print_nice(
                f"[FATAL | main] Supplied idp_cpu_limit ({idp_cpu_limit}) is"\
                "out of scope. idp_cpu_limit must be between 0.1 and 1.0 " \
                "inclusive. Be aware of conversion errors.",
                top_line = True
                )
            sys.exit(1)
    except ValueError:
        print_nice(
            "[FATAL | main] A supplied number is not in its correct form. " \
            "number_of_users, eval_time_seconds, eval_test_cycles and " \
            "ram_limit must be integers. cpu_load must be a float.",
            top_line = True
            )
        sys.exit(1)

    print_nice(f"[DEBUG | config] Config successfully loaded.")

    log_processor = EvaluationLogProcessor(print_nice)
    resource_monitor = ResourceMonitor(
        cpu_limit,
        ram_limit,
        idp_ram_limit,
        idp_cpu_limit,
        print_nice
        )
    
    print_nice(f"[DEBUG | config] Setting up resource limits.")
    resource_monitor.setup_resource_limits()
    print_nice(f"[DEBUG | config] Resource limits set up.")
    # In case something went wrong.
    #log_processor.clear_log_on_server(login_method)
    #log_processor.clear_resmon_record("sp")
    #log_processor.clear_resmon_record("idp")

    has_failed_once = False
    missing_cycles = 0

    for cycle in range(1, eval_test_cycles + 1):
        is_start_successful = evaluate_login_method(
            login_method,
            evaluation_method,
            eval_time_seconds,
            number_of_users,
            resource_monitor
            )
        if is_start_successful == EvalState.EVAL_START_SUCCESS:
            log_processor.process_resmon_records(
                login_method,
                eval_time_seconds,
                number_of_users
            )
            log_processor.process_test_log(
                login_method,
                eval_time_seconds,
                number_of_users
            )
        else:
            print_nice(f"[ERROR | main] Eval cycle '{cycle}' didn't pass")
            missing_cycles += 1
            has_failed_once = True

    if not has_failed_once:   
        analyzer = EvaluationAnalyzer(
            login_method,
            eval_time_seconds,
            number_of_users,
            eval_test_cycles
            )
        
        analyzer.get_aggregate_data()
    else:
        print_nice(f"[INFO | main] Missing '{missing_cycles}' cycles to " \
                   "create aggregate data."
                   )

    #kc_admin = KcAdministrator(print_nice)
    #webbrowser_login(login_method, "t_user_611", kc_admin)
    #kc_admin.logout_all_kc_sessions()
else:
    print(f"[ERROR | main] MISMATCH: {__name__} != __main__")