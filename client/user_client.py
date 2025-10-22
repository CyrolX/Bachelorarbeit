import argparse
from client.kc_administrator import KcAdministrator
import os
#from secret import client_secrets
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.wait import WebDriverWait
import selenium.webdriver.support.expected_conditions as EC

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
    print_nice(f"[DEBUG] WEBDRIVER URL: {driver.current_url}")

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
    print_nice(f"[DEBUG] WEBDRIVER URL: {driver.current_url}")
    last_url = driver.current_url

    # Route to /protected_app, for which we need to be authenticated to par-
    # take in the game.
    driver.get(PROTECTED_APP_URL)
    # A wait is necessary here as well, as we can't get the page source cor-
    # rectly if we don't wait.
    wait.until(EC.url_changes(last_url))
    print_nice(f"[DEBUG] WEBDRIVER URL: {driver.current_url}")
    print_nice(driver.page_source)
    # Not really necessary. I just left it in for the irrational fear of cook-
    # ies being saved in between calls of client.py
    driver.delete_all_cookies()


def evaluate_login_method(login_method, evaluation_method, number_of_users):

    if not (evaluation_method == "browser"):
        print_nice(
            f"[ERROR | eval] Eval method {evaluation_method} is not sup" \
            "ported.",
            top_line = True
            )
    
    pass
    


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    login_method_group = parser.add_mutually_exclusive_group()
    login_method_group.add_argument(
        "--oidc",
        help = "Use OIDC to login",
        action = "store_true"
        )
    login_method_group.add_argument(
        "--saml",
        help = "Use SAML to login",
        action = "store_true"
        )
    evaluation_method_group = parser.add_mutually_exclusive_group()
    evaluation_method_group.add_argument(
        "--browser",
        help = "Evaluate the Webbrowser Login Flow",
        action = "store_const",
        const = "browser_eval"
    )
    evaluation_method_group.add_argument(
        "--eclient",
        help = "Evaluate the Login Flow for enhanced clients",
        action = "store_const",
        const = "eclient_eval"
    )
    parser.add_argument(
        "--num_users",
        help = "The amount of users to be logged in using the specified " \
            "method and flow.",
        action = "store"
    )
    args = parser.parse_args()

    login_method = "oidc" if args.oidc else "saml" if args.saml else None
    evaluation_method = "browser_eval" if args.browser \
        else "eclient_eval" if args.eclient \
        else None
    number_of_users = args.num_users if isinstance(args.num_users, int) \
        and args.num_users <= 1000 \
        and args.num_users > 0 \
        else None
    
    if not login_method or not evaluation_method or not number_of_users:
        print_nice(
            "[INFO | main] No evaluation will take place.",
            top_line = True
            )
    else:
        evaluate_login_method(
            login_method,
            evaluation_method,
            number_of_users
            )

    #kc_admin = KcAdministrator(print_nice)
    #webbrowser_login(login_method, "t_user_611", kc_admin)
    #kc_admin.logout_all_kc_sessions()
else:
    print(f"[ERROR | main] MISMATCH: {__name__} != __main__")