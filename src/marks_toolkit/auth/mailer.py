from abc import ABC, abstractmethod


class Mailer(ABC):

    @abstractmethod
    def send_password_reset(self, email, reset_url):
        pass


class ConsoleMailer(Mailer):

    def send_password_reset(self, email, reset_url):
        print(f"Password reset for {email}: {reset_url}")