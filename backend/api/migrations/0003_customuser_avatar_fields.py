from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0002_trafficlog_acknowledged_trafficlog_acknowledged_at'),
    ]

    operations = [
        migrations.AddField(
            model_name='customuser',
            name='avatar_type',
            field=models.CharField(
                choices=[('preset', 'Preset Avatar'), ('custom', 'Custom Upload'), ('initials', 'Initials')],
                default='initials',
                max_length=10,
            ),
        ),
        migrations.AddField(
            model_name='customuser',
            name='avatar_data',
            field=models.TextField(blank=True, default=''),
        ),
    ]