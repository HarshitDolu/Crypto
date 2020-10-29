from django.db import models

# Create your models here.
# student contact

class contact(models.Model):
    name=models.CharField(max_length=100,default='')
    email=models.CharField(max_length=200,default='')
    subject=models.CharField(max_length=200,default='')
    message=models.TextField(max_length=500,default='')

    def __str__(self):
        return self.name



