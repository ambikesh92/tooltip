# Generated by Django 4.1 on 2023-05-14 04:34

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('inventory', '0008_alter_inventoryattribute_imagenamelink_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='inventoryitem',
            name='inventoryUser',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL),
        ),
    ]