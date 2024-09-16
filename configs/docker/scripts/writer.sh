#!/bin/sh

sleep 5

set -x

vault kv put secret/data/myapp/config api_key=12345 environment=production
vault kv metadata put -custom-metadata="replicate_to=vault_replica" secret/metadata/myapp/config
vault kv metadata get secret/metadata/myapp/config

vault kv put secret/data/myapp/database username=dbuser password=supersecret host=db.example.com port=5432

vault kv get -field=api_key secret/data/myapp/config
vault kv get -format=json secret/data/myapp/database

vault kv list secret/metadata/myapp/
vault kv delete secret/data/myapp/config


