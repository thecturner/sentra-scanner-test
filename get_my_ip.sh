#!/bin/bash
ip=$(curl -s https://ipv4.icanhazip.com)
echo "{\"cidr\": \"${ip}/32\"}"
