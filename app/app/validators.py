import re
from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _

class CustomPasswordValidator:
    def validate(self, password, user=None):
        # Flagi dla każdego warunku
        has_min_length = len(password) >= 10
        has_uppercase = bool(re.search(r'[A-Z]', password))
        has_lowercase = bool(re.search(r'[a-z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_special_char = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))

        # Jeśli którykolwiek warunek nie jest spełniony, zgłoś błąd
        if not (has_min_length and has_uppercase and has_lowercase and has_digit and has_special_char):
            raise ValidationError(self.get_help_text())

    def get_help_text(self):
        return _(
            "Hasło musi mieć co najmniej 10 znaków, zawierać małe i duże litery, "
            "co najmniej jedną cyfrę oraz jeden znak specjalny."
        )
