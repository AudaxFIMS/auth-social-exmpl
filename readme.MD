## Example of using different sources of authentification.

- email / password;
- facebook;
- google;
- apple;

### Values for work with Facebook auth API (should be added into HashiCorp Vault):
- facebook_app_id
- facebook_app_secret

### Docker command for start local Docker container with HashiCorp Vault and UI (on port 8200)
```shell
docker run --cap-add=IPC_LOCK -d \
  --name vault-dev \
  -p 8200:8200 \
  -e 'VAULT_DEV_ROOT_TOKEN_ID=myroot' \
  -e 'VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200' \
  hashicorp/vault:1.20
```
