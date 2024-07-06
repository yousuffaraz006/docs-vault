from django.contrib import admin
from .models import *

class Createdtime(admin.ModelAdmin):
    readonly_fields = ('created_at',)

class Createtime(admin.ModelAdmin):
    readonly_fields = ('created',)

class Sharedtime(admin.ModelAdmin):
    readonly_fields = ('shrdtime',)

admin.site.register(Profile, Createdtime)
admin.site.register(Upload, Createtime)
admin.site.register(Share, Sharedtime)