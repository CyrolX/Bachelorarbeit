#!/bin/bash
sudo systemctl stop nginx
sudo systemctl stop gunicorn.socket
sudo systemctl start nginx
sudo systemctl start gunicorn.socket
