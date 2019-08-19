from django.db import models
from django.conf import settings


# python manage.py makemigrations pages
# python manage.py sqlmigrate pages 0001
# python manage.py migrate


# https://belgeler.yazbel.com/python-istihza/Ucuncu_taraf_moduller/django_mod%C3%BCl%C3%BC/django_2.html

# Buraya kadar bir
class Musician(models.Model):
    class Meta:
        db_table = 'musican'

    first_name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50)
    instrument = models.CharField(max_length=100)

    def __str__(self):
        return self.first_name


class Album(models.Model):
    class Meta:
        db_table = 'album'

    # artist = models.ForeignKey(Musician, on_delete=models.CASCADE)
    artist = models.OneToOneField(Musician, on_delete=models.CASCADE)
    name = models.CharField(max_length=100)
    release_date = models.DateField()
    num_stars = models.IntegerField()

    def __str__(self):
        return self.name


# Buraya kadar bir
class Student(models.Model):
    FRESHMAN = 'FR'
    SOPHOMORE = 'SO'
    JUNIOR = 'JR'
    SENIOR = 'SR'
    YEAR_IN_SCHOOL_CHOICES = [
        (FRESHMAN, 'Freshman'),
        (SOPHOMORE, 'Sophomore'),
        (JUNIOR, 'Junior'),
        (SENIOR, 'Senior'),
    ]
    year_in_school = models.CharField(
        max_length=2,
        choices=YEAR_IN_SCHOOL_CHOICES,
        default=FRESHMAN,
    )

    def is_upperclass(self):
        return self.year_in_school in (self.JUNIOR, self.SENIOR)


# Buraya kadar bir
class MySpecialUser(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
    )
    supervisor = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='supervisor_of',
    )


# Buraya kadar bir
class Lezzet(models.Model):
    name = models.CharField(max_length=30)
    description = models.CharField(max_length=100)

    def __str__(self):
        return self.name


class Depo(models.Model):
    name = models.CharField(max_length=30)
    address = models.CharField(max_length=30)
    city = models.CharField(max_length=30)
    state = models.CharField(max_length=2)
    email = models.EmailField()
    amenities = models.ManyToManyField(Lezzet, blank=True)

    def __str__(self):
        return self.name


# Buraya kadar bir
class Menu(models.Model):
    class Meta:
        db_table = 'menu'

    name = models.CharField(max_length=30)

    def __str__(self):
        return self.name


class Item(models.Model):
    class Meta:
        db_table = 'item'

    menu = models.ForeignKey(Menu, on_delete=models.CASCADE)
    name = models.CharField(max_length=30)
    description = models.CharField(max_length=100)
    calories = models.IntegerField()
    price = models.FloatField()

    def __str__(self):
        return self.name


class Drink(models.Model):
    class Meta:
        db_table = 'drink'

    item = models.OneToOneField(Item, on_delete=models.CASCADE, primary_key=True)
    caffeine = models.IntegerField()
