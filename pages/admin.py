from django.contrib import admin

# Register your models here.

from . models import Musician, Album, Student, MySpecialUser, Lezzet, Depo, Drink, Item, Menu


admin.site.register(Musician)

admin.site.register(Album)

admin.site.register(Student)

admin.site.register(MySpecialUser)

admin.site.register(Lezzet)

admin.site.register(Depo)

admin.site.register(Drink)

admin.site.register(Item)

admin.site.register(Menu)