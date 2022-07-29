from datetime import datetime
from pyexpat import model
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
# Create your models here.


class CustomAccountManager(BaseUserManager):

    def create_user(self, email, user_name, first_name, password, **other_fields):

        if not email:
            raise ValueError(_('You must provide an email address'))

        email = self.normalize_email(email)
        user = self.model(email=email, user_name=user_name,
                          first_name=first_name, **other_fields)
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, email, user_name, first_name, password, **other_fields):
        other_fields.setdefault('is_staff', True)
        other_fields.setdefault('is_superuser', True)
        other_fields.setdefault('is_active', True)

        if other_fields.get('is_staff') is not True:
            raise ValueError(
                'Superuser must be assigned to is_staff=True'
            )

        if other_fields.get('is_superuser') is not True:
            raise ValueError(
                'Superuser must be assigned to is_superuser=True'
            )
        return self.create_user(email, user_name, first_name, password, **other_fields)


class NewUser(AbstractBaseUser, PermissionsMixin):

    email = models.EmailField(_('email address'), unique=True)
    user_name = models.CharField(max_length=150, unique=True)
    first_name = models.CharField(max_length=150)
    start_date = models.DateTimeField(default=timezone.now)
    is_staff = models.BooleanField(default=True)
    is_superuser = models.BooleanField(default=True)
    is_active = models.BooleanField(default=True)

    objects = CustomAccountManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['user_name', 'first_name']

    def __str__(self):
        return self.email


class EncounterExit(models.Model):
    description = models.CharField(max_length=45)

    def __str__(self):
        return self.description


class Gender(models.Model):
    description = models.CharField(max_length=45)

    def __str__(self):
        return self.description


class Promoter(models.Model):
    user = models.OneToOneField(
        NewUser,
        on_delete=models.CASCADE,
    )

    def __str__(self):
        return str(self.user.id) + " " + self.user.email


class Sample(models.Model):
    description = models.CharField(max_length=45)

    def __str__(self):
        return self.description


class Agreement(models.Model):
    description = models.CharField(max_length=45)

    def __str__(self):
        return self.description


class Contact(models.Model):
    description = models.CharField(max_length=45)

    def __str__(self):
        return self.description


class GIID(models.Model):
    description = models.CharField(max_length=45)

    def __str__(self):
        return self.description


class EncounterDaily(models.Model):
    EncounterExitID = models.ForeignKey(
        EncounterExit, on_delete=models.CASCADE,  blank=True)
    PromoterID = models.ForeignKey(
        Promoter, on_delete=models.CASCADE, blank=True)
    GenderID = models.ForeignKey(Gender, on_delete=models.CASCADE, blank=True)
    DateTime = models.DateTimeField(default=datetime.now, blank=True)
    Longtitude = models.DecimalField(
        max_digits=20, decimal_places=15,  blank=True)
    Latitude = models.DecimalField(
        max_digits=20, decimal_places=15,  blank=True)


class Customer(models.Model):
    LastName = models.CharField(max_length=45)
    FirstName = models.CharField(max_length=45)
    MiddleName = models.CharField(max_length=45)
    ExtensionName = models.CharField(max_length=45)
    GenderID = models.ForeignKey(Gender, on_delete=models.CASCADE)

    def __str__(self):
        return self.FirstName + " " + self.LastName


class CustomerContact(models.Model):
    ContactID = models.ForeignKey(Contact, on_delete=models.CASCADE)
    CustomerID = models.ForeignKey(Customer, on_delete=models.CASCADE)


class CustomerAgreement(models.Model):
    CusomterID = models.ForeignKey(Customer, on_delete=models.CASCADE)
    AgreementID = models.ForeignKey(Agreement, on_delete=models.CASCADE)


class CustomerGIID(models.Model):
    GIID = models.ForeignKey(GIID, on_delete=models.CASCADE)
    CustomerID = models.ForeignKey(Customer, on_delete=models.CASCADE)
    IDImage = models.CharField(max_length=50)


class ClaimType(models.Model):
    description = models.CharField(max_length=45)

    def __str__(self):
        return self.description


class CustomerSample(models.Model):
    CustomerID = models.ForeignKey(Customer, on_delete=models.CASCADE)
    SampleID = models.ForeignKey(Sample, on_delete=models.CASCADE)
    PromoterID = models.ForeignKey(Promoter, on_delete=models.CASCADE)
    ClaimTypeID = models.ForeignKey(
        ClaimType, on_delete=models.CASCADE)
    DateTime = models.DateTimeField()
    Longtitude = models.DecimalField(max_digits=20, decimal_places=2)
    Latitude = models.DecimalField(max_digits=20, decimal_places=2)


class Group(models.Model):
    description = models.CharField(max_length=45)

    def __str__(self):
        return self.description


class PromotersGroup(models.Model):
    GroupID = models.ForeignKey(Group, on_delete=models.CASCADE)
    PromoterID = models.ForeignKey(Promoter, on_delete=models.CASCADE)
