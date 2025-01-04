# Generated by Django 5.1.4 on 2024-12-25 18:26

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('home', '0002_idslog_severity_level_alter_idslog_analysis_result_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='idslog',
            name='attack_types',
            field=models.JSONField(default=list),
        ),
        migrations.AddField(
            model_name='idslog',
            name='remediation_steps',
            field=models.TextField(blank=True),
        ),
        migrations.AddField(
            model_name='idslog',
            name='resolution_notes',
            field=models.TextField(blank=True),
        ),
        migrations.AddField(
            model_name='idslog',
            name='resolved_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='idslog',
            name='source_ips',
            field=models.JSONField(default=dict),
        ),
        migrations.AddField(
            model_name='idslog',
            name='status',
            field=models.CharField(choices=[('new', 'New'), ('investigating', 'Investigating'), ('resolved', 'Resolved'), ('false_positive', 'False Positive')], default='new', max_length=20),
        ),
        migrations.AddIndex(
            model_name='idslog',
            index=models.Index(fields=['-timestamp'], name='home_idslog_timesta_a405fb_idx'),
        ),
        migrations.AddIndex(
            model_name='idslog',
            index=models.Index(fields=['severity_level'], name='home_idslog_severit_7c7e95_idx'),
        ),
        migrations.AddIndex(
            model_name='idslog',
            index=models.Index(fields=['status'], name='home_idslog_status_cd2a6e_idx'),
        ),
    ]
