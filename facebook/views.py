from django.http      import HttpResponse
from django.shortcuts import render_to_response

def canvas(request):
    return render_to_response('canvas.fbml')
