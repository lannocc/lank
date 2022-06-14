from appdirs import AppDirs

from os.path import join, exists
from os import makedirs


DIRS = AppDirs('lank', 'LANNOCC')

if not exists(DIRS.user_data_dir):
    makedirs(DIRS.user_data_dir)

DB = join(DIRS.user_data_dir, 'LANK.db')

