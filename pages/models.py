from django.db import models


# python manage.py makemigrations pages
# python manage.py sqlmigrate pages 0001
# python manage.py migrate
# https://belgeler.yazbel.com/python-istihza/Ucuncu_taraf_moduller/django_mod%C3%BCl%C3%BC/django_2.html

class Project(models.Model):
    VulnerabilityID = models.TextField()
    PkgName = models.TextField()
    InstalledVersion = models.TextField()
    FixedVersion = models.TextField()
    Title = models.TextField()
    Description = models.TextField()
    Severity = models.TextField()
    References = models.TextField()
