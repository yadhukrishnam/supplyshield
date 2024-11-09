#!/bin/bash

GITHUB_APP_PRIVATE_KEY=$(echo "$GITHUB_APP_PRIVATE_KEY" | sed 's/@@/\n/g')

echo "$GITHUB_APP_PRIVATE_KEY" > "/$HOME_DIR/.github_app.pem"

cat "/$HOME_DIR/.github_app.pem" | sha256sum
