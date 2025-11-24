from client.kc_administrator import KcAdministrator
from client.log_processor import EvaluationLogProcessor
from client.analyze import EvaluationAnalyzer
import configparser
import os
from secret import client_secrets
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.wait import WebDriverWait
import selenium.webdriver.support.expected_conditions as EC
import subprocess
import signal
import sys
import threading
import time

PROTECTED_APP_URL = "https://vm097.rz.uni-osnabrueck.de/protected_app"
TERMINAL_SIZE = os.get_terminal_size()


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
    driver = webdriver.Chrome(options = options)
    # The Webdriver will wait for at max 10 seconds before a request is deemed
    # to be lost. every 100th of a second it is checked if there was an up-
    # date.
    wait = WebDriverWait(driver = driver, timeout = 10, poll_frequency = 0.01)

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


def evaluate_login_method(
        login_method,
        evaluation_method,
        eval_time_seconds,
        number_of_users
        ):

    if not (evaluation_method == "browser"):
        print_nice(
            f"[ERROR | eval] Eval method {evaluation_method} is not sup" \
            "ported.",
            top_line = True
            )
        return
    
    kc_admin = KcAdministrator(print_nice)

    # Evaluate over 5 minutes.
    login_interval = get_login_interval(eval_time_seconds, number_of_users)
    print_nice(f"[DEBUG | eval] Login Interval: {login_interval}")
    login_threads = []
    print_nice(f"[DEBUG | eval] Starting eval")
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

    print_nice(f"[DEBUG | eval] Eval concluded. Logging out users.")
    kc_admin.logout_all_kc_sessions(number_of_users)
    print_nice(f"[DEBUG | eval] Users logged out. Resetting state.")
    reset_state()
    print_nice(f"[DEBUG | eval] Users logged out. Resetting state.")


def get_login_interval(eval_time_seconds, number_of_users):
    return eval_time_seconds / number_of_users

# This is not well made at the moment. My SSH-Agent logic is in the log_pro-
# cessor.py file, while I need to use it here. Yet invoking anything with the
# log processor would just look weird. Perhaps I will just move the SSH-Agent
# logic over to the user_client itself. For the moment this has to do.
def reset_state():
    with subprocess.Popen(
        f"ssh {client_secrets.CONNECTION} ./reset_service.sh",
        stdout = subprocess.PIPE, \
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP \
        ) as process:
        try:
            out, err = process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            process.send_signal(signal.CTRL_BREAK_EVENT)
            process.kill()
            out, err = process.communicate()


if __name__ == "__main__":
    config = configparser.ConfigParser()
    config.read(client_secrets.TEST_CONFIG_PATH)
    test_config = config["test.config"]
    login_method = test_config["login_method"] \
        if test_config["login_method"] == "oidc" \
        or test_config["login_method"] == "saml" \
        else None
    evaluation_method = test_config["evaluation_method"] \
        if test_config["evaluation_method"] == "browser" \
        or test_config["evaluation_method"] == "eclient" \
        else None
    # The configparser getters are no good in my opinion.
    if test_config["number_of_users"].isdecimal():
        number_of_users = int(test_config["number_of_users"])
        number_of_users = None if number_of_users > 1000 \
            or number_of_users < 0 \
            else number_of_users
    else:
        number_of_users = None

    if test_config["eval_time_seconds"].isdecimal():
        eval_time_seconds = int(test_config["eval_time_seconds"])
        eval_time_seconds = None if eval_time_seconds < 0 \
            else eval_time_seconds
    else:
        eval_time_seconds = None

    if test_config["eval_test_cycles"].isdecimal():
        eval_test_cycles = int(test_config["eval_test_cycles"])
        eval_test_cycles = None if eval_test_cycles < 0 \
            else eval_test_cycles
    else:
        eval_test_cycles = None
    
    if not (
        login_method \
        and evaluation_method \
        and number_of_users \
        and eval_test_cycles
        ):
        print_nice(
            "[INFO | main] No evaluation will take place.",
            top_line = True
            )
        sys.exit(0)

    log_processor = EvaluationLogProcessor(print_nice)

    for cycle in range(1, eval_test_cycles + 1):
        evaluate_login_method(
            login_method,
            evaluation_method,
            eval_time_seconds,
            number_of_users
            )
        log_processor.process_test_log(
            login_method,
            eval_time_seconds,
            number_of_users
        )
        
    analyzer = EvaluationAnalyzer(
        login_method,
        eval_time_seconds,
        number_of_users,
        eval_test_cycles
        )
    
    analyzer.get_aggregate_data()

    #kc_admin = KcAdministrator(print_nice)
    #webbrowser_login(login_method, "t_user_611", kc_admin)
    #kc_admin.logout_all_kc_sessions()
else:
    print(f"[ERROR | main] MISMATCH: {__name__} != __main__")