import os
import requests
#from requests_html import HTMLSession
from secret import client_secrets

ATTEMPT_OIDC_LOGIN_URL = 'https://vm097.rz.uni-osnabrueck.de/accounts/saml/keycloak/login/?process=login'
ATTEMPT_SAML_LOGIN_URL = 'https://vm097.rz.uni-osnabrueck.de/accounts/saml/keycloak/login/?process=login'
ADMIN_LOGIN_URL = 'https://172.17.22.64/admin'
TERMINAL_SIZE = os.get_terminal_size()

def print_nice(text, top_line = False):
    if top_line:
        print(f'+{(TERMINAL_SIZE.columns - 2) * "-"}+')
    
    print(f'+ {text}')
    print(f'+{(TERMINAL_SIZE.columns - 2) * "-"}+')

def main():
    # Requests Session um Cookies zu speichern
    client = requests.session()
    # Routing auf die Admin-Page um uns dort einzuloggen
    #route_response = client.get(ADMIN_LOGIN_URL)
    #print_nice(f'[DEBUG] COOKIES_BEFORE_GET: {client.cookies}', top_line = True)
    #print_nice(f'[DEBUG] HEADERS: {client.headers}')
    route_response = client.get(ATTEMPT_OIDC_LOGIN_URL)

    # Der Referer wird von requests nicht automatisch gesetzt und wird benö-
    # tigt, um CSRF-Tokens verifizieren zu können.
    client.headers.update({'referer': route_response.url})

    #print_nice(f'[DEBUG] COOKIES_AFTER_GET: {client.cookies}', top_line = True)
    #print_nice(f'[DEBUG] HEADERS: {client.headers}')
    #print_nice(route_response.url)

    csrf_token = client.cookies['csrftoken']
    redirect_response = client.post(route_response.url, data={'csrfmiddlewaretoken': csrf_token}, allow_redirects = True, verify = True)

    #print_nice(f'[DEBUG] COOKIES_AFTER_REDIRECT: {client.cookies}')
    #print_nice(f'[DEBUG] HEADERS: {client.headers}')
    #print_nice(f'[DEBUG] REDIRECT_RESPONSE RESPONSE_CODE: {redirect_response}')
    #print_nice(f'[DEBUG] REDIRECT_RESPONSE RESPONSE_STATUS: {redirect_response.status_code}')
    #print_nice(f'[DEBUG] REDIRECT_RESPONSE RESPONSE_URL: {redirect_response.url}')
    #print_nice(redirect_response.text)

    csrf_token = client.cookies['csrftoken']
    # Die folgenden Cookies werden während des Redirects gesetzt und werden bei
    # der Login-Anfrage mit übergeben. Es gibt auch noch den 'KC_AUTH_SESSION_
    # HASH'-Cookie, dieser scheint allerdings nicht benötigt zu werden.
    auth_session_id = client.cookies['AUTH_SESSION_ID']
    keycloak_restart = client.cookies['KC_RESTART']
    session_id = client.cookies['sessionid']
    
    # Die folgenden Daten erlauben das Anmelden über OpenID Connect. SAML funk-
    # tioniert hier noch nicht, da wir mit der aktuellen Methode einen Enhanced
    # Client beobachten. Da der Protokollablauf für einen Enhanced Client aller-
    # dings ein anderer ist, funktioniert der Login aktuell nur für OIDC einiger-
    # maßen.
    test_user_login_data = {
        'username':'testuser2', 
        'password': client_secrets.TEST_USER_PASSWORD, 
        'csrfmiddlewaretoken': csrf_token,
        'AUTH_SESSION_ID': auth_session_id,
        # 'KC_AUTH_SESSION_HASH': keycloak_auth_session_hash,
        'KC_RESTART': keycloak_restart,
        'sessionid': session_id,
        'client_id': 'test1' # OIDC ONLY
        #'client_id': 'test-saml-1' # Funktioniert nicht
        }
    
    #login_request = requests.Request('POST', redirect_response.url, headers=client.headers, data=test_user_login_data)
    #print_nice(get_POST_string(login_request.prepare()))

    login_response = client.post(redirect_response.url, data=test_user_login_data)

    #print_nice(f'[DEBUG] COOKIES_AFTER_LOGIN: {client.cookies}')
    #print_nice(f'[DEBUG] LOGIN_RESPONSE RESPONSE_STATUS: {login_response.status_code}')
    #print_nice(f'[DEBUG] LOGIN_RESPONSE RESPONSE_URL {login_response.url}')
    print_nice(login_response.text)

    #print_nice(f'[DEBUG] {client.cookies}', top_line = True)

    #print(route_response.url)
    #print_nice(route_response.history)
    #print_nice(route_response.text)

    # Es wird ein Cross-Site-Request-Forgery-Token benötigt, um uns einzuloggen.
    # Dieser wird bei jeder Request (Ob GET oder POST) neu generiert und muss
    # entsprechend, sollten im Folgenden weitere Aktionen gewünscht sein, nach je-
    # der Request neu abgefragt werden.
    #csrf_token = client.cookies['csrftoken']
    #admin_login_data = {'username':'m611', 'password': client_secrets.ADMIN_PASSWORD, 'csrfmiddlewaretoken':csrf_token}
    # Django hat eine gewisse Eigenheit was seine automatisch generierte Admin-
    # Login-Seite angeht. Es ist wichtig auf /admin zu routen, wodurch man bei
    # /admin/login/?next=/admin/ landet. Am einfachsten ist es hier einfach die
    # URL der Response nach dem Routing auf die Admin-Page zu wählen.
    #login_response = client.post(route_response.url, data = admin_login_data)

    #print_nice(login_response.text)
    #print_nice(f'[DEBUG] {client.cookies}')

    # Hierdurch wird die Login-Session sogesehen terminiert.
    #client.cookies.clear()
    #print_nice(f'[DEBUG] {client.cookies}')
    #print_nice('TERMINATING')
    #test = requests.get('http://172.17.22.64/protected_app')
    #print(test.text)

if __name__ == '__main__':
    main()
else:
    print(f'[ERR] MISMATCH: {__name__} != __main__')