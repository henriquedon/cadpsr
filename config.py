import os
basedir = os.path.abspath(os.path.dirname(__file__))


class Config(object):
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'L4TgFhfnCZpnkFF522whupTsQfKUXFbxEATUNp7434oNap5ukRntcHEUzeiwMcVT'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', '').replace(
        'postgres://', 'postgresql://') or \
        'sqlite:///' + os.path.join(basedir, 'bd_cadpsr.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
