# Generated by Django 4.2.6 on 2023-10-28 06:33

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('appointer', '0006_alter_loginmodel_isverified'),
    ]

    operations = [
        migrations.AlterField(
            model_name='appointment',
            name='appointment_date',
            field=models.DateTimeField(null=True),
        ),
    ]
