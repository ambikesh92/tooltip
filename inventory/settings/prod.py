from .common import *

SECRET_KEY = os.getenv('SECRET_KEY')
DEBUG = False

STATIC_ROOT = BASE_DIR/"asset"
STATICFILES_STORAGE = "whitenoise.storage.CompressedManifestStaticFilesStorage"

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'mishraambikesh92_inventory',
        'USER': 'mishraambikesh92_inventtooltips',
        'PASSWORD': 'inventtooltips92',
        'HOST': '127.0.0.1',
        'PORT': '3306',
    }
}
