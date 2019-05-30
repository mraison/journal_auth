#!/bin/bash

export FLASK_APP=auth
export FLASK_ENV=development
flask run -h localhost -p 8081
