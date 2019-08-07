from django.shortcuts import render

from django.http import HttpResponse, JsonResponse
from django.template.loader import render_to_string
import json
import pandas as pd
from pandas.io.json import json_normalize


def index(request):
    return render(request, 'pages/index.html')


def about(request):
    return render(request, 'pages/about.html')
