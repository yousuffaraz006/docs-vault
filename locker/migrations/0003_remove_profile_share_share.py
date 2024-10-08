# Generated by Django 4.2.5 on 2024-07-05 05:14

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('locker', '0002_profile_share_alter_profile_auth_token'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='profile',
            name='share',
        ),
        migrations.CreateModel(
            name='Share',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('shrdtitle', models.CharField(max_length=100)),
                ('shrdimg', models.ImageField(upload_to='locker/images/')),
                ('shrdtime', models.DateTimeField(auto_now_add=True)),
                ('reciever_user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
                ('sender_user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='sender', to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
