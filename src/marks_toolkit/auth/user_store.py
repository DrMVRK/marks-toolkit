from abc import ABC, abstractmethod


class UserStore(ABC):

    @abstractmethod
    def find_by_identity(self, identity):
        pass

    @abstractmethod
    def find_by_auth_id(self, auth_id):
        pass

    @abstractmethod
    def identity_exists(self, email, username):
        pass

    @abstractmethod
    def create_user(self, email, username, password_hash):
        pass

    @abstractmethod
    def rotate_auth_id(self, user):
        pass

    @abstractmethod
    def update_password(self, user, password_hash):
        pass