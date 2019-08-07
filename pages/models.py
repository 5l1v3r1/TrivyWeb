from django.db import models


# python manage.py makemigrations pages
# python manage.py sqlmigrate pages 0001
# python manage.py migrate


# https://belgeler.yazbel.com/python-istihza/Ucuncu_taraf_moduller/django_mod%C3%BCl%C3%BC/django_2.html

class VulnPages(models.Model):

    class Meta:
        db_table = 'VulnPages'

    VulnerabilityID = models.TextField(null=True, blank=True,)
    PkgName = models.TextField(null=True, blank=True,)
    InstalledVersion = models.TextField(null=True, blank=True,)
    FixedVersion = models.TextField(null=True, blank=True,)
    Title = models.TextField(null=True, blank=True,)
    Description = models.TextField(null=True, blank=True,)
    Severity = models.TextField(null=True, blank=True,)
    References = models.TextField(null=True, blank=True,)


