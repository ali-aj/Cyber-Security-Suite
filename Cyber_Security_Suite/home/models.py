from django.db import models
from django.utils import timezone

class ScanResult(models.Model):
    url = models.URLField(max_length=255)
    scan_type = models.CharField(max_length=50)
    result = models.TextField()
    timestamp = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f'ScanResult {self.id} {self.url}'

    class Meta:
        ordering = ['-timestamp']

class IDSLog(models.Model):
    SEVERITY_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
    ]
    
    STATUS_CHOICES = [
        ('new', 'New'),
        ('investigating', 'Investigating'),
        ('resolved', 'Resolved'),
        ('false_positive', 'False Positive')
    ]
    
    log_data = models.TextField()
    analysis_result = models.JSONField()
    timestamp = models.DateTimeField(auto_now_add=True)
    severity_level = models.CharField(
        max_length=10,
        choices=SEVERITY_CHOICES,
        default='low'
    )
    source_ips = models.JSONField(default=dict)
    attack_types = models.JSONField(default=list)
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='new'
    )
    remediation_steps = models.TextField(blank=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    resolution_notes = models.TextField(blank=True)

    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['-timestamp']),
            models.Index(fields=['severity_level']),
            models.Index(fields=['status'])
        ]

    def mark_resolved(self, notes=''):
        self.status = 'resolved'
        self.resolved_at = timezone.now()
        self.resolution_notes = notes
        self.save()

    def mark_false_positive(self, notes=''):
        self.status = 'false_positive'
        self.resolved_at = timezone.now()
        self.resolution_notes = notes
        self.save()

class CryptoOperation(models.Model):
    operation_type = models.CharField(max_length=50)
    input_text = models.TextField()
    output_text = models.TextField()
    timestamp = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f'CryptoOperation {self.id} {self.operation_type}'

    class Meta:
        ordering = ['-timestamp']