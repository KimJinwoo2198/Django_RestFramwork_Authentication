import os
import signal
import subprocess
from django.apps import AppConfig
from django.conf import settings

class Config(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'Auth_Template'
    worker_process = None

    def ready(self):
        if os.environ.get('RUN_MAIN') != 'true':
            return