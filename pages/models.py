from django.db import models


# python manage.py makemigrations pages
# https://belgeler.yazbel.com/python-istihza/Ucuncu_taraf_moduller/django_mod%C3%BCl%C3%BC/django_2.html

class Project(models.Model):
    VulnerabilityID = models.CharField(max_length=10000)
    PkgName = models.CharField(max_length=10000)
    InstalledVersion = models.CharField(max_length=10000)
    FixedVersion = models.CharField(max_length=10000)
    Title = models.CharField(max_length=10000)
    Description = models.CharField(max_length=10000)
    Severity = models.CharField(max_length=10000)
    References = models.CharField(max_length=10000)
