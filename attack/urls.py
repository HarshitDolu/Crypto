

from django.urls import path
from django.contrib.auth import views as auth_views
from  .import views

urlpatterns = [
    path('',views.home,name="home"),
    path('kshift',views.kshift,name='kshift'),
    path('vignere', views.vignere, name='vignere'),
    path('vernam',views.vernam,name='vernam'),
    path('railfence',views.railfence,name='railfence'),
    path('playfair', views.playfair, name='playfair'),
    path('columnar', views.columnar, name='columnar'),
    path('hill', views.hill, name='hill'),
    path('sdes', views.sdes, name='sdes'),

   ]