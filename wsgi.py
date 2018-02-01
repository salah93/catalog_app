import logging
import site
import sys
from os.path import join, dirname, expanduser

# Add virtualenv site packages
site.addsitedir(join(dirname(__file__), 'env/lib/python3.5/site-packages'))

# Path of execution
sys.path.insert(0, '/var/www/catalog_app')

# Fired up virtualenv before include application
activate_env = expanduser(join(dirname(__file__), 'env/bin/activate_this.py'))
exec(open(activate_env).read(), {'__file__': activate_env})


from run import app as application, log
from utility import random_string


application.secret_key = random_string(30)
logging.basicConfig(filename=log,level=logging.DEBUG)
