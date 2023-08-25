# Generated by Django 3.2.20 on 2023-08-21 01:42

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0005_recipe_image'),
    ]

    operations = [
        migrations.CreateModel(
            name='PersonalAccessToken',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('token', models.CharField(max_length=88)),
                ('name', models.CharField(max_length=50)),
                ('created', models.DateField(auto_now_add=True)),
                ('expires', models.DateField(null=True)),
                ('revoked', models.BooleanField(default=False)),
                ('is_expired', models.BooleanField(default=False)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
