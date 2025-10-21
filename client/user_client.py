#from .testing_logs import run_me

import argparse
from client.kc_administrator import KcAdministrator
import os
#import requests
from secret import client_secrets#, logger_define_test
#import secrets
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.wait import WebDriverWait
import selenium.webdriver.support.expected_conditions as EC
#from time import sleep

ATTEMPT_OIDC_LOGIN_URL = 'https://vm097.rz.uni-osnabrueck.de/accounts/oidc/keycloak/login/?process=login'
ATTEMPT_SAML_LOGIN_URL = 'https://vm097.rz.uni-osnabrueck.de/accounts/saml/keycloak/login/?process=login'
PROTECTED_APP_URL = 'https://vm097.rz.uni-osnabrueck.de/protected_app'
#ADMIN_LOGIN_URL = 'https://172.17.22.64/admin'
TERMINAL_SIZE = os.get_terminal_size()


def print_nice(text, top_line = False):
    """
    Prints the given text to the console with separation lines to make it more
    discernable from other printed text.

    :param text: The text to be printed to the console
    
    :param top_line: Normally the separation line is only printed under the text.
        When printing the first message, it may make sense to print another line
        at the top. It may be more performant to remove this behaviour altogether
        and just call print_nice without any text instead of checking top_line
        on every call. Defaults to False.
    """
    if top_line:
        print(f'+{(TERMINAL_SIZE.columns - 2) * "-"}+')
    
    print(f'+ {text}')
    print(f'+{(TERMINAL_SIZE.columns - 2) * "-"}+')


def webbrowser_login(login_method):
    """
    Simulates a login from a user through a webbrowser. This fits the Webbrowser-Flow
    for SAML and the standard flow for OIDC.

    :param login_method: Gathered from command line arguments. Either saml, oidc or
        None.
    """

    if not login_method:
        print_nice("[ERROR] No login method provided.", top_line = True)
        return

    # Works only because the login URLs are the same.
    login_url = f'https://vm097.rz.uni-osnabrueck.de/accounts/{login_method}/keycloak/login/?process=login'
    
    # Chrome is used only because it was the first option. This can be expanded in
    # the future to include more Webbrowsers.
    options = webdriver.ChromeOptions()
    options.add_argument("--no-sandbox")
    options.add_argument("--headless=new")
    driver = webdriver.Chrome(options = options)
    # The Webdriver will wait for at max 10 seconds before a request is deemed to be
    # lost. every 100th of a second it is checked if there was an update.
    wait = WebDriverWait(driver = driver, timeout = 10, poll_frequency = 0.01)

    #print_nice(f'[DEBUG] COOKIES: {driver.get_cookies()}')

    # This is to show that we are not authenticated yet.
    driver.get(PROTECTED_APP_URL)
    # As we are working with a webbrowser, we need to wait until the page is loaded
    # correctly until we can do actions on the website, like printing the source etc.
    wait.until(EC.presence_of_element_located((By.TAG_NAME, 'p')))
    print_nice(f'[DEBUG] WEBDRIVER URL: {driver.current_url}')
    # Should contain "Not Authenticated"
    print_nice(driver.page_source)

    # Route to the login_url which will instantaneously redirect us to Keycloak as
    # configured.
    driver.get(login_url)

    # Wait until the redirect was successful and the Keycloak page is loaded suf-
    # ficiently
    wait.until(EC.presence_of_element_located((By.ID, 'username')))
    # Saved for line 115, where we wait until the URL changes from this URL.
    last_url = driver.current_url
    print_nice(f'[DEBUG] WEBDRIVER URL: {driver.current_url}')

    username_input_field = driver.find_element(by=By.ID, value="username")
    password_input_field = driver.find_element(by=By.ID, value="password")
    login_button = driver.find_element(by=By.ID, value="kc-login")
    username_input_field.send_keys("testuser2")
    password_input_field.send_keys(client_secrets.TEST_USER_PASSWORD)
    login_button.click()
    
    # If the URL changes, we most likely have been authenticated correctly and have
    # been redirected to /accounts/profile
    wait.until(EC.url_changes(last_url))
    print_nice(f'[DEBUG] WEBDRIVER URL: {driver.current_url}')
    last_url = driver.current_url

    # Route to /protected_app, for which we need to be authenticated to partake in
    # the game.
    driver.get(PROTECTED_APP_URL)
    # A wait is necessary here as well, as we can't get the page source correctly
    # if we don't wait.
    wait.until(EC.url_changes(last_url))
    print_nice(f'[DEBUG] WEBDRIVER URL: {driver.current_url}')
    print_nice(driver.page_source)
    # Not really necessary. I just left it in for the irrational fear of cookies
    # being saved in between calls of client.py
    driver.delete_all_cookies()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    login_method_group = parser.add_mutually_exclusive_group()
    login_method_group.add_argument("--oidc", help = "Use OIDC to login", action = 'store_true')
    login_method_group.add_argument("--saml", help = "Use SAML to login", action = 'store_true')
    args = parser.parse_args()

    login_method = 'oidc' if args.oidc else 'saml' if args.saml else None
    #webbrowser_login(login_method)
    kc_admin = KcAdministrator(print_nice)
    #kc_admin.create_test_users()
    kc_admin.logout_all_kc_sessions()
    # Tested if the logger is created once or multiple times. It is created once.
    #logger_define_test.oidc_logger.debug("I am here")
    #logger_define_test.saml_logger.debug("I am here")
    #logger_define_test.oidc_logger.debug("I am here")
    #logger_define_test.saml_logger.debug("I am here")
    #run_me()
else:
    print(f'[ERR] MISMATCH: {__name__} != __main__')