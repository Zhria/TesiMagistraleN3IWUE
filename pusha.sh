#!/bin/bash

# Se passo un argomento uso quello, altrimenti metto un messaggio di default
if [ -n "$1" ]; then
    COMMIT_MSG="$1"
else
    COMMIT_MSG="push automatico"
fi

git add .
git commit -m "$COMMIT_MSG"
git push
