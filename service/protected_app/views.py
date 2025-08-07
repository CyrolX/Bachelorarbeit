# from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.shortcuts import render
from django.template import loader
from random import randint

# Create your views here.
def index(request):
    random_bool = True if randint(0,1) else False
    context = {"random_bool": random_bool}
    template = loader.get_template("protected_app/index.html")
    return HttpResponse(template.render(context, request))