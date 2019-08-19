import pkg_resources
from django.shortcuts import render
from django.http import HttpResponse, Http404
from .models import Musician, Album

from django.http import HttpResponse, JsonResponse
from django.template.loader import render_to_string
import json
import pandas as pd
from pandas.io.json import json_normalize


def index(request):
    return render(request, 'pages/index.html')


def about(request):
    musicans = Musician.objects.order_by('id').all()
    #musicans = Musician.objects.all()[:1]
    #musicans = Musician.objects.filter(id=2)
    #musicans = Musician.objects.filter(id__range=(2, 3))
    albums = Album.objects.order_by('id').all()
    context_1 = {'musicans': musicans, 'albums': albums}
    return render(request, 'pages/about.html', context_1)
