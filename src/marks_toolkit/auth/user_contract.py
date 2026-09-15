from flask_login import UserMixin


class AuthUser(UserMixin):
    """
    Base authentication user contract.

    Concrete user implementations are expected to provide:

    - id
    - auth_id
    - email
    - username
    - password_hash

    The permanent database ID and rotating authentication ID
    intentionally serve different purposes.
    """

    id = None
    auth_id = None
    email = None
    username = None
    password_hash = None

    def get_id(self):
        """
        Flask-Login uses this value to identify the authenticated
        browser session.

        We deliberately use auth_id rather than the permanent
        database ID so authentication state can be invalidated by
        rotating auth_id.
        """

        if self.auth_id is None:
            return None

        return str(self.auth_id)