import os
import requests

ADMIN_LOGIN_URL = 'http://172.17.22.64/admin'
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
    route_response = client.get(ADMIN_LOGIN_URL)

    print_nice(f'[DEBUG] {client.cookies}', top_line = True)

    # Es wird ein Cross-Site-Request-Forgery-Token benötigt, um uns einzuloggen.
    # Dieser wird bei jeder Request (Ob GET oder POST) neu generiert und muss
    # entsprechend, sollten im Folgenden weitere Aktionen gewünscht sein, nach je-
    # der Request neu abgefragt werden.
    csrf_token = client.cookies['csrftoken']
    admin_login_data = {'username':'m611', 'password':'', 'csrfmiddlewaretoken':csrf_token}
    # Django hat eine gewisse Eigenheit was seine automatisch generierte Admin-
    # Login-Seite angeht. Es ist wichtig auf /admin zu routen, wodurch man bei
    # /admin/login/?next=/admin/ landet. Am einfachsten ist es hier einfach die
    # URL der Response nach dem Routing auf die Admin-Page zu wählen.
    login_response = client.post(route_response.url, data = admin_login_data)

    print_nice(login_response.text)
    print_nice(f'[DEBUG] {client.cookies}')

    # Hierdurch wird die Login-Session sogesehen terminiert.
    client.cookies.clear()
    print_nice(f'[DEBUG] {client.cookies}')
    print_nice('TERMINATING')
    #test = requests.get('http://172.17.22.64/protected_app')
    #print(test.text)

if __name__ == '__main__':
    main()
else:
    print(f'[ERR] MISMATCH: {__name__} != __main__')