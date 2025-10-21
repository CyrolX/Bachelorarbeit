import keycloak
from secret import kc_admin_secrets

class KcAdministrator:
    """
    This class is used to build, delete and logout test users on the Keycloak
    instance for my bachelor thesis

    :param printer: A function that can print text to the console. Defaults to
        print

    :param printer_args: Positional Arguments for the supplied printing func
        tion
    
    :param printer_kwargs: Keyword Arguments for the supplied printing func
        tion
    """

    _kc_admin = keycloak.KeycloakAdmin(
            server_url = kc_admin_secrets.KEYCLOAK_URL,
            username = kc_admin_secrets.KEYCLOAK_ADMIN_USERNAME,
            password = kc_admin_secrets.KEYCLOAK_ADMIN_PASSWORD,
            realm_name = kc_admin_secrets.KEYCLOAK_REALM,
            user_realm_name = kc_admin_secrets.KEYCLOAK_USER_REALM
        )
    

    def __init__(
            self,
            printer = print,
            printer_args = [],
            printer_kwargs = {}
            ):
        """
        Instantiates a KcAdministrator
        """
        self.printer = printer
        self.printer_args = printer_args
        self.printer_kwargs = printer_kwargs


    def build_uid_to_uname_lookup_dict(self, user_list):
        """
        Generates a dictionary, which has User-IDs as keys and usernames as
        values. Each User-ID has their respective username as a value

        :param user_list: A list of UserRepresentations (See https://www.key
            cloak.org/docs-api/latest/rest-api/index.html#UserRepresentation)
            for more information on how a UserRepresentation can look like)

        :return: A dictionary containing pairs of User-ID and username, with
            the keys being the User-ID and the values being their respective
            username
        """
        lookup = {}

        for user_representation in user_list:
            lookup = {
                user_representation['id']: user_representation['username']
            }
        
        return lookup


    def fetch_uids_from_user_list(self, user_list):
        """
        Fetches the User-ID for each UserRepresentation in the user_list

        :param user_list: A list of UserRepresentations (See https://www.key
            cloak.org/docs-api/latest/rest-api/index.html#UserRepresentation)
            for more information on how a UserRepresentation can look like)
        
        :return: A list containing all User-IDs contained inside the UserRe-
            presentations of the user_list
        """
        return [
            user_representation['id'] for user_representation in user_list
            ]


    def get_user_list(self, username = "t_user"):
        """
        Gets a list of UserRepresentations from the Keycloak instance

        :param username: Filter for the API-Call. Only UserRepresentations con
            taining the supplied username somewhere inside its username field
            are returned. Defaults to "t_user"
        
        :return: A list of UserRepresentations, including only those that con
            tain the supplied username somewhere inside their username field
        """
        return self._kc_admin.get_users(
            query = {"username": username}
            )


    def _print_user_list(self, username = "t_user"):
        """
        Private debug function, that prints out the contents of the user list
        of the Keycloak Instance

        :param username: Filter for get_user_list. get_user_list only returns
            UserRepresentations containing the supplied username somewhere in
            side its username field. Defaults to "t_user"
        """
        user_list = self.get_user_list(username)
        self.printer(user_list, *self.printer_args, **self.printer_kwargs)


    def _print_sessions(self, user_ids):
        """
        Private debug function, that prints out all the currently active ses
        sions for all supplied User-IDs

        :param user_ids: A list containing the User-IDs, whose active session
            are to be checked
        """
        sessions = {}
        for user_id in user_ids:
            sessions[user_id] = self._kc_admin.get_sessions(user_id)
        self.printer(sessions)


    def create_test_users(self):
        """
        Creates 1000 test users for the Keycloak instance
        """
        # For more information on UserRepresentation or CredentialRepresenta-
        # tion see the following links:
        # TODO: Input links
        user_representation_base = {
            "username": "",
            "enabled": True,
            "credentials": [
                {
                    "userLabel": "Password",
                    "temporary": False,
                    "type": "password",
                    "value": ""
                }
            ]
        }

        for i in range(1, 1001):
            # Using .copy() here is important, as dictionaries, as well as
            # lists, are copied by reference. a = {'a': 1}, b = a and then
            # b['a'] = 2 would lead to 'a' being set to 2 in a too.
            new_user = user_representation_base.copy()
            new_user['username'] = f"t_user_{i}"
            new_user['credentials'][0]['value'] = \
                kc_admin_secrets.TEST_USER_PASSWORDS[f"t_user_{i}"]
            self._kc_admin.create_user(new_user)
        

    def delete_test_users(self):
        """
        Deletes the 1000 test users.
        """
        keycloak_admin = self._kc_admin
        user_list = self.get_user_list()
        user_ids = self.fetch_uids_from_user_list(user_list)

        for user_id in user_ids:
            keycloak_admin.delete_user(user_id)


    def logout_all_kc_sessions(self):
        """
        Clears all active sessions for all test users.
        """
        user_list = self.get_user_list()
        self.printer(user_list, *self.printer_args, **self.printer_kwargs)

        # Only really important for debugging / logging purposes.
        uid_to_uname_lookup = self.build_uid_to_uname_lookup_dict(user_list)
        self.printer(uid_to_uname_lookup)

        # In order to clear all sessions we need to first get all uids from
        # the user_list.
        user_ids = self.fetch_uids_from_user_list(user_list)
        self.printer(user_ids, *self.printer_args, **self.printer_kwargs)

        # Clears all sessions of all known users of the current realm.
        for user_id in user_ids:
            self._kc_admin.user_logout(user_id)
        self.printer(
            f"[DEBUG] User {uid_to_uname_lookup[user_id]} logged out.",
            *self.printer_args,
            **self.printer_kwargs
            )
