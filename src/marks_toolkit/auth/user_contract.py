from abc import ABC, abstractmethod

class AuthUser(ABC):

    @property
    @abstractmethod
    def auth_id(self):
        pass

    @property
    @abstractmethod
    def password_hash(self):
        pass

    @property
    @abstractmethod
    def is_active(self):
        pass