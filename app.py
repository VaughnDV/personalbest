"""
Flask API backend for recording peronal bests at the gym
"""
from flask import Flask
from flask_sqlalchemy import SQLAlchemy


app = Flask(__name__)

app.config.from_pyfile('config.py')

db = SQLAlchemy(app)

from views import *





if __name__ == '__main__':
    try:
        if os.environ['FLASK_DEBUG']:
            app.run(debug=True)
        else:
            app.run()
    except:
        app.run()