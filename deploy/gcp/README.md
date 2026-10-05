# Deployment guide

This guide deploys Cairn on one Compute Engine VM, behind an external HTTPS
load balancer. It sets up the controls from
[Deploy integrity](../../design/e2e-trust-model.md#deploy-integrity):

- Only CI builds release images, and it signs each one.
- The VM runs an image only if the signature checks out.
- Audit logs go to a project the deployer can't change, and every change to
  the Cairn project raises an alert there.

The examples use `cairn.example.com` for the app and
`example-usercontent.com` for artifacts. The two must not share a registrable
domain, and Cairn refuses to start if they do. Replace both with your own,
along with every placeholder in capitals, such as `CAIRN_PROJECT`, `REGION`,
and `VM_ZONE`.

## People and projects

Use two projects:

| Project | Holds | Who can change it |
| --- | --- | --- |
| `CAIRN_PROJECT` | The VM, its disk, the load balancer, DNS, and certificates | The deployer |
| `AUDIT_PROJECT` | The audit log bucket and the alert policies | Someone who is not the deployer |

The deployer must not hold Owner, Editor, or Logs Configuration Writer on
`CAIRN_PROJECT`, or any role on `AUDIT_PROJECT`. Any one of those roles lets
the deployer delete the log sink or an alert. Grant narrower roles instead,
such as `roles/compute.admin`, `roles/dns.admin`, and
`roles/certificatemanager.editor`.

The Cairn administrator and the deployer should be different people. If one
person holds both, a second person must approve each deploy.

## 1. Set up the release key

The release key signs the manifest of web assets that `cairn verify` checks.
Until you finish this step, the release and docker workflows fail on purpose.

1. On a machine you trust, make a key:

   ```sh
   go run ./cmd/cairn-release keygen
   ```

   It prints the secret as `CAIRN_RELEASE_KEY=…`, and the public key.
2. Store the secret in the repository. When `gh` asks for the value, paste
   only the part after `CAIRN_RELEASE_KEY=`:

   ```sh
   gh secret set CAIRN_RELEASE_KEY
   ```

   Then clear your terminal's scrollback, so the secret no longer shows on
   screen.

3. Add the public key to `trustedKeys` in `internal/release/manifest.go`, and
   merge that change to `main`. The release and docker workflows check their
   own build with `cairn verify` and no `--key`, so they fail if the
   compiled-in key doesn't match the secret.

## 2. Protect the build

The VM accepts an image only if the `docker` workflow signed it, in a run
from a `v*` tag or from `main`. Set up GitHub so that only reviewed code gets
there:

- A branch ruleset on `main` that requires a pull request with an approving
  review and signed commits, and blocks force pushes.
- A tag ruleset on `v*` that limits who can create tags.
- The package `ghcr.io/davidnoyes/cairn` set to public, so the VM can pull
  it with no credential. The image holds no secret.

The tag ruleset is the control that keeps code nobody reviewed out of a
tagged release. Both workflows refuse a tag whose commit is not on `main`, but that
check lives in the workflow file at the tagged commit. Someone who can push a
`v*` tag can push one on a commit whose workflow skips the check.

Set up both rulesets before the first release. The VM trusts every image the
workflow has ever signed, including any signed before the rulesets existed.

The release and docker workflows pin each action they use to a commit, so
moving a tag in an action's repository can't change what builds and signs a
release. When you update an action, update its version comment in the same
change.

`deploy/gcp/startup.sh` names the repository in `REPOSITORY`. If you deploy
from a fork, change that line. The script doesn't read the repository from
metadata, because the deployer can edit metadata.

To release, push a tag such as `v1.0.0` on a `main` commit. The `docker`
workflow builds the image, embeds the signed manifest, and signs the image
with cosign.

## 3. Send audit logs to the audit project

GCP always writes the activity audit log, which records every change to a
project's resources. Route it to `AUDIT_PROJECT`, and store it there in a
bucket whose retention can't be shortened.

1. In `AUDIT_PROJECT`, create a locked bucket, and a sink that stores the
   Cairn project's audit logs in it:

   ```sh
   gcloud logging buckets create cairn-audit --project=AUDIT_PROJECT \
     --location=global --retention-days=400 --locked
   gcloud logging sinks create cairn-audit --project=AUDIT_PROJECT \
     logging.googleapis.com/projects/AUDIT_PROJECT/locations/global/buckets/cairn-audit \
     --log-filter='logName:"projects/CAIRN_PROJECT/logs/cloudaudit.googleapis.com"'
   ```

   The audit project's `_Default` sink skips activity audit entries routed in
   from another project, so this sink is required.
2. In `CAIRN_PROJECT`, route the audit logs to the audit project:

   ```sh
   gcloud logging sinks create to-audit --project=CAIRN_PROJECT \
     logging.googleapis.com/projects/AUDIT_PROJECT \
     --log-filter='logName:"cloudaudit.googleapis.com"'
   ```

   Make sure the destination is the project, not the bucket. That way, alert
   policies in `AUDIT_PROJECT` scan the entries.
3. Let the sink write to the audit project. Use the writer identity that the
   last command printed:

   ```sh
   gcloud projects add-iam-policy-binding AUDIT_PROJECT \
     --member=WRITER_IDENTITY --role=roles/logging.logWriter
   ```

An aggregated sink on a folder or the organization can intercept these
entries before they get here. If your organization has one, check it with
whoever owns it.

## 4. Raise alerts

The Cairn project runs one VM, so treat every activity audit entry as worth
a look. That one rule covers all of these:

- deploys, because a deploy edits the `cairn-image` metadata;
- edits to the startup script, which is metadata too;
- changes to DNS, the load balancer, certificates, firewall rules, and IAM;
- SSH, which needs a new firewall rule, an SSH key in metadata, or the serial
  console turned on;
- attaching or snapshotting the data disk.

1. Create an email notification channel in `AUDIT_PROJECT`. Note its ID.
2. Save this policy as `alert.json`, with your project IDs and channel:

   ```json
   {
     "displayName": "Cairn or audit project changed",
     "documentation": {"content": "Someone changed the Cairn project. Check that a person you know made the change."},
     "combiner": "OR",
     "conditions": [{
       "displayName": "Activity audit entry",
       "conditionMatchedLog": {
         "filter": "log_id(\"cloudaudit.googleapis.com/activity\")"
       }
     }],
     "alertStrategy": {"notificationRateLimit": {"period": "300s"}, "autoClose": "1800s"},
     "notificationChannels": ["projects/AUDIT_PROJECT/notificationChannels/CHANNEL_ID"]
   }
   ```

3. Create it in the audit project:

   ```sh
   gcloud monitoring policies create --project=AUDIT_PROJECT --policy-from-file=alert.json
   ```

The policy scans the audit project's own activity entries as well, so a
change to the bucket, the sink, or the policy raises the alert too.

## 5. Create the certificates

Certificate Manager issues one certificate for the app and a wildcard
certificate for artifacts, using DNS authorization. Each domain needs its own
DNS authorization.

1. If the two domains have no public DNS zone in `CAIRN_PROJECT` yet, create
   one for each:

   ```sh
   gcloud dns managed-zones create cairn-app \
     --dns-name=cairn.example.com. --description="Cairn app"
   gcloud dns managed-zones create cairn-content \
     --dns-name=example-usercontent.com. --description="Cairn artifacts"
   gcloud dns managed-zones describe cairn-app --format='value(nameServers)'
   gcloud dns managed-zones describe cairn-content --format='value(nameServers)'
   ```

   Then delegate each domain to the name servers its zone lists. For
   `example-usercontent.com`, set them at your registrar. For
   `cairn.example.com`, add them as an `NS` record in the zone for
   `example.com`. The rest of this guide calls the two zones `cairn-app` and
   `cairn-content`.
2. Create the authorizations:

   ```sh
   gcloud certificate-manager dns-authorizations create cairn-app \
     --domain=cairn.example.com
   gcloud certificate-manager dns-authorizations create cairn-content \
     --domain=example-usercontent.com
   ```

3. Read the CNAME record that each one asks for:

   ```sh
   gcloud certificate-manager dns-authorizations describe cairn-app
   gcloud certificate-manager dns-authorizations describe cairn-content
   ```

4. Add each record to the zone for its domain, `cairn-app` or
   `cairn-content`:

   ```sh
   gcloud dns record-sets create CNAME_NAME --zone=DNS_ZONE \
     --type=CNAME --ttl=300 --rrdatas=CNAME_DATA
   ```

5. Create the certificates and a certificate map:

   ```sh
   gcloud certificate-manager certificates create cairn-app \
     --domains=cairn.example.com --dns-authorizations=cairn-app
   gcloud certificate-manager certificates create cairn-content \
     --domains='*.example-usercontent.com' --dns-authorizations=cairn-content
   gcloud certificate-manager maps create cairn
   gcloud certificate-manager maps entries create app --map=cairn \
     --certificates=cairn-app --hostname=cairn.example.com
   gcloud certificate-manager maps entries create content --map=cairn \
     --certificates=cairn-content --hostname='*.example-usercontent.com'
   ```

## 6. Create the virtual machine

1. Create a network for Cairn alone:

   ```sh
   gcloud compute networks create cairn --subnet-mode=custom
   gcloud compute networks subnets create cairn --network=cairn \
     --region=REGION --range=10.10.0.0/24
   ```

   Don't use the `default` network. Its `default-allow-ssh` rule accepts SSH
   from any address, so SSH would need no change that raises an alert. A new
   network accepts no inbound traffic until you add a firewall rule.
2. Create the VM with a separate data disk and no service account. `VM_ZONE`
   is a zone in `REGION`, such as `europe-west2-a`:

   ```sh
   gcloud compute instances create cairn --zone=VM_ZONE \
     --network=cairn --subnet=cairn \
     --machine-type=e2-small --image-family=debian-12 --image-project=debian-cloud \
     --create-disk=name=cairn-data,device-name=cairn-data,size=20GB,auto-delete=no \
     --no-service-account --no-scopes --shielded-secure-boot --tags=cairn \
     --metadata-from-file=startup-script=deploy/gcp/startup.sh \
     --metadata=cairn-image=ghcr.io/davidnoyes/cairn:v1.0.0,enable-oslogin=TRUE
   ```

   On the first boot, the startup script refuses to start Cairn, because the
   data disk is not set up yet.
3. Set up the data disk, once. To connect over SSH through IAP, your account
   needs `roles/iap.tunnelResourceAccessor` and `roles/compute.osAdminLogin`
   in `CAIRN_PROJECT`. First add a temporary firewall rule:

   ```sh
   gcloud compute firewall-rules create cairn-iap-ssh --network=cairn \
     --allow=tcp:22 --source-ranges=35.235.240.0/20 --target-tags=cairn
   gcloud compute ssh cairn --zone=VM_ZONE --tunnel-through-iap
   ```

   Then run:

   ```sh
   sudo mkfs.ext4 -m 0 /dev/disk/by-id/google-cairn-data
   sudo mkdir -p /mnt/disks/cairn
   echo '/dev/disk/by-id/google-cairn-data /mnt/disks/cairn ext4 defaults,nofail 0 2' | sudo tee -a /etc/fstab
   sudo mount /mnt/disks/cairn
   sudo install -d -o 1000 -g 1000 /mnt/disks/cairn/data
   sudo install -m 600 /dev/null /mnt/disks/cairn/cairn.env
   ```

   The container runs as user 1000, so that user must own the data
   directory.
4. Write the server's settings to `/mnt/disks/cairn/cairn.env`. Root owns
   the file, so open it with `sudoedit /mnt/disks/cairn/cairn.env`, which
   keeps its owner and mode:

   ```sh
   CAIRN_PUBLIC_URL=https://cairn.example.com
   CAIRN_CONTENT_DOMAIN=example-usercontent.com
   CAIRN_SIGNUP_DOMAINS=example.com
   CAIRN_ADMIN_EMAIL=you@example.com
   CAIRN_SMTP_URL=smtp://USER:PASSWORD@smtp-relay.example.com:587
   ```

   Compute Engine blocks outbound port 25, so use port 587. The Google
   Workspace SMTP relay or a provider such as SendGrid both work.
5. Delete the SSH firewall rule, then reset the VM so the startup script
   runs again:

   ```sh
   gcloud compute firewall-rules delete cairn-iap-ssh
   gcloud compute instances reset cairn --zone=VM_ZONE
   ```

## 7. Create the load balancer

The load balancer passes the original `Host` header to Cairn, which routes
by it. Cairn reads no forwarded headers. The health check reaches
`/healthz`, because Cairn sends any host that isn't an artifact to the app.

```sh
gcloud compute instance-groups unmanaged create cairn --zone=VM_ZONE
gcloud compute instance-groups unmanaged add-instances cairn --zone=VM_ZONE --instances=cairn
gcloud compute instance-groups unmanaged set-named-ports cairn --zone=VM_ZONE --named-ports=http:8787

gcloud compute health-checks create http cairn --port=8787 --request-path=/healthz
gcloud compute backend-services create cairn --global \
  --load-balancing-scheme=EXTERNAL_MANAGED --protocol=HTTP --port-name=http \
  --health-checks=cairn --timeout=300s
gcloud compute backend-services add-backend cairn --global \
  --instance-group=cairn --instance-group-zone=VM_ZONE
gcloud compute url-maps create cairn --default-service=cairn

gcloud compute addresses create cairn --global
gcloud compute target-https-proxies create cairn --global \
  --url-map=cairn --certificate-map=cairn
gcloud compute forwarding-rules create cairn --global \
  --load-balancing-scheme=EXTERNAL_MANAGED --address=cairn \
  --target-https-proxy=cairn --ports=443

gcloud compute firewall-rules create cairn-lb --network=cairn --allow=tcp:8787 \
  --source-ranges=130.211.0.0/22,35.191.0.0/16 --target-tags=cairn
```

The 300-second timeout leaves room for large uploads. Last, point both
domains at the load balancer's address:

```sh
ADDRESS=$(gcloud compute addresses describe cairn --global --format='value(address)')
gcloud dns record-sets create cairn.example.com. --zone=cairn-app \
  --type=A --ttl=300 --rrdatas="$ADDRESS"
gcloud dns record-sets create '*.example-usercontent.com.' --zone=cairn-content \
  --type=A --ttl=300 --rrdatas="$ADDRESS"
```

## Deploy a new version

1. Push a `v*` tag on `main`, and wait for the `docker` workflow to finish.
2. Point the VM at the new image, and reset it:

   ```sh
   gcloud compute instances add-metadata cairn --zone=VM_ZONE \
     --metadata=cairn-image=ghcr.io/davidnoyes/cairn:v1.1.0
   gcloud compute instances reset cairn --zone=VM_ZONE
   ```

On every boot, the startup script does these things in order:

1. Pulls the image.
2. Resolves the image to its digest.
3. Checks with cosign that this repository's `docker` workflow signed that
   digest, from a `v*` tag or `main`.
4. Checks that the data disk is mounted and holds `cairn.env`. Without this
   check, a missing disk would start Cairn on an empty directory on the boot
   disk.
5. Replaces the container with one that runs that same digest.

If any check fails, the script leaves the old container in place. Docker
restarts it when the VM boots, so a refused deploy leaves the last verified
image running. The serial console log shows why the deploy was refused.

The deploy raises the alert from section 4, which is how you know a deploy can't
go unseen.

## Check a server

To check that a server sends the files and pages of a signed release, run
this on your own machine:

```sh
cairn verify --version v1.1.0 https://cairn.example.com
```

The check needs a session to fetch `/app`, so sign in to that server with
`cairn login` first. Without a session, `cairn verify` skips `/app` and
fails. To accept the skip, pass `--allow-skip`.

Without `--version`, a pass means the server runs some genuine signed
release, not necessarily the one you deployed. See
[Deploy integrity](../../design/e2e-api.md#deploy-integrity) for what it
checks.

## Check by hand on a staging project

Before you rely on these controls, test them on a staging project:

- Set `cairn-image` to an image you built and pushed yourself, then reset
  the VM. The startup script must refuse it.
- Change a DNS record, and confirm the alert email arrives.
- Run `cairn login` against the staging server, then `cairn verify`, and
  confirm it passes with nothing skipped.

## Accepted limits

- Binary Authorization doesn't cover a plain Compute Engine VM, so the
  signature check runs in the startup script. A deployer can edit that
  script, and the edit raises an alert.
- A server could send genuine files to `cairn verify` and altered ones to
  someone else. Treat it as a spot check.
- `cairn verify` compares response bodies only. It doesn't check headers
  such as `Content-Security-Policy`, so it can't tell when a server weakens
  them.
- The startup script accepts any image the `docker` workflow ever signed. A
  deployer can roll back to an older release, even one with a known flaw.
  The rollback raises the alert, and `cairn verify --version` shows which
  release runs.
- The `docker` workflow runs `cairn verify` against a server it builds on
  the runner from the same commit, not against the image it pushes. The
  image comes from the same source, and its signature ties it to that run.
- The startup script trusts a `cosign` binary already on the VM, and
  downloads one, checked against a pinned SHA-256, only when there is none.
  Replacing that binary needs root on the VM, which already means control of
  Cairn.
