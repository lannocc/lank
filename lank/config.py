from appdirs import AppDirs

from os.path import join, exists
from os import makedirs
import sys


DIRS = AppDirs('lank', 'LANNOCC')

if not exists(DIRS.user_data_dir):
    makedirs(DIRS.user_data_dir)

DB = join(DIRS.user_data_dir,
        'LANK.db' if 'run2' not in sys.argv else 'other.db')

