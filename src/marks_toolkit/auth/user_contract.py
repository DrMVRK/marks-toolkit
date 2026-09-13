from abc import ABC
from flask_login import UserMixin


class AuthUser(UserMixin, ABC):

    def get_id(self):
        return str(self.auth_id)
