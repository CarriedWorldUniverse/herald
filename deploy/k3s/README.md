# herald — k3s manifests

Single-node k3s deploy. herald is internal-only (`ClusterIP`); reach it via
**interchange-gateway** once routed.

## One-time secret

The Deployment reads a `herald-secrets` Secret with:

- `genesis_owner_password` — seeds the platform-admin owner
  (`cwadmin@carriedworld.com`) at deploy time. No default account/password
  ships in the image; admin authority is identity-derived (a herald JWT with
  `herald:platform-admin`), not a static token.
- `signing_key` (optional) — base64 Ed25519 private, 64 bytes. Without it,
  herald generates one on boot — fine for dev, **fatal for prod** because
  issued tokens won't survive a restart.

```sh
# generate the admin-org owner password
OWNER_PW=$(openssl rand -hex 16)

kubectl -n cwb create secret generic herald-secrets \
  --from-literal=genesis_owner_password="$OWNER_PW"

echo "cwadmin@carriedworld.com password = $OWNER_PW"  # save somewhere safe
```

## Apply

```sh
kubectl apply -f deploy/k3s/
kubectl -n cwb rollout status deploy/herald
kubectl -n cwb get pods,svc,pvc
```

## Smoke

```sh
kubectl -n cwb port-forward svc/herald 8099:8099 &
curl -sS http://localhost:8099/healthz       # 200 ok
curl -sS http://localhost:8099/.well-known/openid-configuration | jq .
```

## Notes

- `HERALD_ISSUER` is currently `http://herald.cwb.svc:8099/` (in-cluster).
  Update to the externally-reachable gateway URL (e.g.
  `https://cwb.example/herald/`) once interchange-gateway routes traffic.
- Storage is a `local-path` PVC (k3s default). Single-node only.
- `imagePullPolicy: Never` — image is loaded into containerd directly via
  `podman save | k3s ctr images import -`, not pulled from a registry.
