#!/bin/bash
ip=$(curl -s ifconfig.me)
echo "{\"cidr\": \"${ip}/32\"}"