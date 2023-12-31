# Generated by Django 4.1 on 2023-01-24 07:44

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('inventory', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='inventoryattribute',
            name='imageNameLink',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='inventory.inventoryitem'),
        ),
        migrations.AlterField(
            model_name='toolltipdata',
            name='attributeName',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='inventory.inventoryattribute'),
        ),
    ]
