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
        values. Each User-ID has their respective username as a value. To get
        an ID from a username, use get_uid_from_uname()

        :param user_list: A list of UserRepresentations (See https://www.key
            cloak.org/docs-api/latest/rest-api/index.html#UserRepresentation)
            for more information on how a UserRepresentation can look like)

        :return: A dictionary containing pairs of User-ID and username, with
            the keys being the User-ID and the values being their respective
            username
        """
        lookup = {}

        # user was originally user_representation as this was a more accurate
        # name. It was changed because it was too long.
        for user in user_list:
            lookup[user['id']] = user['username']
        
        
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


    def get_user_list(self, username = "t_user_"):
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
    

    def _is_uid_locally_known(self, user_id):
        return user_id in kc_admin_secrets.TEST_USER_PASSWORDS

        
    def get_uid_from_uname(self, username, uid_to_uname_lookup):
        if username in uid_to_uname_lookup.values():
            return list(uid_to_uname_lookup.keys())[
                list(uid_to_uname_lookup.values()).index(username)
                ]
        else:
            return None 


    def get_test_user_password(self, username = "t_user_1", user_id = None):
        """
        Fetches the password for the given test user. Either username or user_
        id must be supplied. By extension this function also checks if the

        :param username: The username of the test user, whose password is to
            be returned

        :param user_id: The User-ID of the test user, whose password is to be
            returned
        
        :return: The password for the given user. Returns None if the user
            doesn't exist or if the user doesn't have a locally known password
        """

        # This can be changed so that we do not get the user list containing
        # all test users. As get_user_password and all the other functions in
        # this class are used for the sole purpose of doing stuff with test
        # users though, it isn't done here.
        user_list = self.get_user_list()
        uid_to_uname_lookup = self.build_uid_to_uname_lookup_dict(user_list)

        if not username and not user_id:
            self.printer(
                f"[DEBUG | get_pass]: username {username} and user_id " \
                f"{user_id} are None",
                *self.printer_args,
                **self.printer_kwargs
                )
            return None
        # A specific validity check of the uid isn't necessary here, as all
        # the proof of validity stems from it being contained in the passwords
        # dictionary.
        if not username and self._is_uid_locally_known(user_id):
            self.printer(
                f"[DEBUG | get_pass]: username {username} is None and user" \
                f"_id {user_id} is known. SUCCESS!",
                *self.printer_args,
                **self.printer_kwargs
                )
            return kc_admin_secrets.TEST_USER_PASSWORDS[user_id]
        # If we got to this point, we know that either there wasn't a username
        # nor a User-ID, or that there was a User-ID, which was invalid, which
        # is why we immediately return None here, if user_id is not None.
        if not username and user_id:
            self.printer(
                f"[DEBUG | get_pass]: username {username} is None and user_" \
                f"id {user_id} is unknown.", 
                *self.printer_args,
                **self.printer_kwargs
                )
            return None
        # If we got past this point it means that we have a username but no
        # User-ID, or we got both.
        if not user_id:
            self.printer(
                f"[DEBUG | get_pass]: username {username} is not None and " \
                f"user_id {user_id} is None. Fetching user_id.",
                *self.printer_args,
                **self.printer_kwargs
                )
            user_id = self.get_uid_from_uname(username, uid_to_uname_lookup)
            self.printer(
                f"[DEBUG | get_pass]: user_id is now {user_id} ",
                *self.printer_args,
                **self.printer_kwargs
                )
        # The User-ID could still be None or locally unknown, which is why we
        # need to check the following case.
        if not self._is_uid_locally_known(user_id):
            self.printer(
                f"[DEBUG | get_pass]: username {username} is not None and " \
                f"user_id {user_id} is unknown.",
                *self.printer_args,
                **self.printer_kwargs
                )
            return None
        # We still have to test the following condition in case we originally
        # got username and User-ID
        if not uid_to_uname_lookup[user_id] == username:
            self.printer(
                f"[DEBUG | get_pass]: username {username} is not None and " \
                f"user_id {user_id} is not None, yet username and user_id " \
                "do not match.",
                *self.printer_args,
                **self.printer_kwargs
                )
            return None
        # We now are sure, that the User-ID is locally known, and matches the
        # given username. We can now return the password.
        self.printer(
            f"[DEBUG | get_pass]: username {username} is not None and user_" \
            f"id {user_id} is not None. Everything is in order, returning " \
            f"password: {kc_admin_secrets.TEST_USER_PASSWORDS[user_id]}",
            *self.printer_args,
            **self.printer_kwargs
            )
        return kc_admin_secrets.TEST_USER_PASSWORDS[user_id]


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
