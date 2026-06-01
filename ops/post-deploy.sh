#!/bin/bash
# Garante que o nginx-prod tem acesso à rede do chatcorp
docker network connect btvchatcorp_btv-net ops-nginx-prod-1 2>/dev/null || true
