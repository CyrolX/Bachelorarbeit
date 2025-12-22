#!/bin/bash
sudo docker compose -f /opt/keycloak/docker-compose.yml down;
sleep 1;
sudo docker compose -f /opt/keycloak/docker-compose.yml up -d;
