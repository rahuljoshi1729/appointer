from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.core.validators import MaxValueValidator
from django.db.models.signals import pre_save
from django.dispatch import receiver

class UserManager(BaseUserManager):
    def create_user(self, email, password, first_name, last_name, account_type, specialization, salt, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        
        email = self.normalize_email(email)
        user = self.model(email=email, first_name=first_name, last_name=last_name, account_type=account_type, specialization=specialization, salt=salt, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user
    def is_patient(self, user):
        return user.account_type == 'Patient'

    def is_doctor(self, user):
        return user.account_type == 'Doctor'

    def is_admin(self, user):
        return user.account_type == 'Admin'

    def create_superuser(self, email, password, first_name, last_name, account_type, specialization, salt, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(email, password, first_name, last_name, account_type, specialization, salt, **extra_fields)

class User(AbstractBaseUser):
    email = models.EmailField(unique=True)
    first_name = models.CharField(max_length=30)
    last_name = models.CharField(max_length=30)
    account_type = models.CharField(max_length=10, choices=[('Patient', 'Patient'), ('Doctor', 'Doctor'), ('Admin', 'Admin')], default='Patient')
    specialization = models.CharField(max_length=100, null=True, blank=True)
    salt = models.CharField(max_length=100)
    
    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name', 'account_type', 'salt']

    def enforce_specialization_constraint(sender, instance, **kwargs):
        if instance.account_type != 'Doctor':
            instance.specialization = None

   
class Appointment(models.Model):
    patient = models.ForeignKey(User, related_name='appointments', on_delete=models.CASCADE)
    doctor = models.ForeignKey(User, related_name='doctor_appointments', on_delete=models.CASCADE)
    appointment_date = models.DateTimeField(null=True)
    STATUS_CHOICES = [('scheduled', 'Scheduled'), ('completed', 'Completed')]
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='scheduled')

class PasswordReset(models.Model):
    token=models.CharField(max_length=100)
    isverified=models.BooleanField(default=False)
    user=models.ForeignKey(User,on_delete=models.CASCADE)


class loginmodel(models.Model):
    email=models.EmailField(unique=True,default=True)
    token=models.CharField(max_length=100)
    isverified=models.BooleanField(default=False)
    user=models.ForeignKey(User,on_delete=models.CASCADE)
