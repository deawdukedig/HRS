#!/bin/bash

zip -r HRS.zip . -x "node_modules/*" ".git/*" "hrs.db" "package-lock.json"
echo "Created HRS.zip (excluding node_modules, .git, and hrs.db)"