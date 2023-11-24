from django.contrib.auth.base_user import BaseUserManager
from django.utils.translation import gettext as _

class UserManager(BaseUserManager):
   
    def create_user(self, email2, password, **extra_fields):
     
        if not email2:
            raise ValueError(_("The Email must be set"))
        email2 = self.normalize_email(email2)
        user = self.model(email2=email2, **extra_fields)
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, email2, password, **extra_fields):
   
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_active", True)

        if extra_fields.get("is_staff") is not True:
            raise ValueError(_("Superuser must have is_staff=True."))
        if extra_fields.get("is_superuser") is not True:
            raise ValueError(_("Superuser must have is_superuser=True."))
        return self.create_user(email2, password, **extra_fields)