from appdirs import AppDirs

from os.path import join, exists
from os import mkdir


DIRS = AppDirs('lank', 'LANNOCC')

if not exists(DIRS.user_data_dir):
    mkdir(DIRS.user_data_dir)

DB = join(DIRS.user_data_dir, 'LANK.db')

