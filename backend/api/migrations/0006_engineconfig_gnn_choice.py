# Adds 'gnn' to EngineConfig.active_engine choices (Two-Stage GNN engine).

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0005_engineconfig'),
    ]

    operations = [
        migrations.AlterField(
            model_name='engineconfig',
            name='active_engine',
            field=models.CharField(
                choices=[
                    ('ml', 'ML (XGBoost + LightGBM)'),
                    ('dl', 'DL (Two-Stage DNN)'),
                    ('gnn', 'GNN (Two-Stage Graph Neural Network)'),
                ],
                default='dl',
                max_length=10,
            ),
        ),
    ]
