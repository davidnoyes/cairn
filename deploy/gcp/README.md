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
domain, and Cairn refuses to start if they do. Replace both, and the project
IDs, with your own.

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
2. Store the secret in the repository, then delete it from your terminal
   history:

   ```sh
   gh secret set CAIRN_RELEASE_KEY
   ```

3. Add the public key to `trustedKeys` in `internal/release/manifest.go`, and
   merge that change to `main`. The release workflow checks its own build
   with `cairn verify` and no `--key`, so it fails if the compiled-in key
   doesn't match the secret.

## 2. Protect the build

The VM accepts an image only if the `docker` workflow signed it, in a run
from a `v*` tag or from `main`. Both workflows refuse a commit that is not on
`main`. Set up GitHub so that only reviewed code gets there:

- A branch ruleset on `main` that requires a pull request with an approving
  review and signed commits, and blocks force pushes.
- A tag ruleset on `v*` that limits who can create tags.
- The package `ghcr.io/davidnoyes/cairn` set to public, so the VM can pull
  it with no credential. The image holds no secret.

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

1. Create the authorizations:

   ```sh
   gcloud certificate-manager dns-authorizations create cairn-app \
     --domain=cairn.example.com
   gcloud certificate-manager dns-authorizations create cairn-content \
     --domain=example-usercontent.com
   ```

2. Read the CNAME record that each one asks for:

   ```sh
   gcloud certificate-manager dns-authorizations describe cairn-app
   gcloud certificate-manager dns-authorizations describe cairn-content
   ```

3. Add each record to the DNS zone for its domain:

   ```sh
   gcloud dns record-sets transaction start --zone=ZONE
   gcloud dns record-sets transaction add CNAME_DATA --zone=ZONE \
     --name=CNAME_NAME --type=CNAME --ttl=300
   gcloud dns record-sets transaction execute --zone=ZONE
   ```

4. Create the certificates and a certificate map:

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

1. Create the VM with a separate data disk and no service account:

   ```sh
   gcloud compute instances create cairn --zone=ZONE \
     --machine-type=e2-small --image-family=debian-12 --image-project=debian-cloud \
     --create-disk=name=cairn-data,device-name=cairn-data,size=20GB,auto-delete=no \
     --no-service-account --no-scopes --shielded-secure-boot --tags=cairn \
     --metadata-from-file=startup-script=deploy/gcp/startup.sh \
     --metadata=cairn-image=ghcr.io/davidnoyes/cairn:v1.0.0,enable-oslogin=TRUE
   ```

   Cairn fails to start on the first boot, because the data disk has no
   settings yet.
2. Set up the data disk, once. Connect over SSH through IAP, which needs a
   temporary firewall rule for `35.235.240.0/20` on port 22. Then run:

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
3. Write the server's settings to `/mnt/disks/cairn/cairn.env`:

   ```sh
   CAIRN_PUBLIC_URL=https://cairn.example.com
   CAIRN_CONTENT_DOMAIN=example-usercontent.com
   CAIRN_SIGNUP_DOMAINS=example.com
   CAIRN_ADMIN_EMAIL=you@example.com
   CAIRN_SMTP_URL=smtp://USER:PASSWORD@smtp-relay.example.com:587
   ```

   Compute Engine blocks outbound port 25, so use port 587. The Google
   Workspace SMTP relay or a provider such as SendGrid both work.
4. Delete the SSH firewall rule, then reset the VM so the startup script
   runs again:

   ```sh
   gcloud compute instances reset cairn --zone=ZONE
   ```

## 7. Create the load balancer

The load balancer passes the original `Host` header to Cairn, which routes
by it. Cairn reads no forwarded headers. The health check reaches
`/healthz`, because Cairn sends any host that isn't an artifact to the app.

```sh
gcloud compute instance-groups unmanaged create cairn --zone=ZONE
gcloud compute instance-groups unmanaged add-instances cairn --zone=ZONE --instances=cairn
gcloud compute instance-groups unmanaged set-named-ports cairn --zone=ZONE --named-ports=http:8787

gcloud compute health-checks create http cairn --port=8787 --request-path=/healthz
gcloud compute backend-services create cairn --global \
  --load-balancing-scheme=EXTERNAL_MANAGED --protocol=HTTP --port-name=http \
  --health-checks=cairn --timeout=300s
gcloud compute backend-services add-backend cairn --global \
  --instance-group=cairn --instance-group-zone=ZONE
gcloud compute url-maps create cairn --default-service=cairn

gcloud compute addresses create cairn --global
gcloud compute target-https-proxies create cairn --global \
  --url-map=cairn --certificate-map=cairn
gcloud compute forwarding-rules create cairn --global \
  --load-balancing-scheme=EXTERNAL_MANAGED --address=cairn \
  --target-https-proxy=cairn --ports=443

gcloud compute firewall-rules create cairn-lb --allow=tcp:8787 \
  --source-ranges=130.211.0.0/22,35.191.0.0/16 --target-tags=cairn
```

The 300-second timeout leaves room for large uploads. Last, add two A
records with the address from `gcloud compute addresses describe cairn
--global`. One is `cairn.example.com`, and the other is
`*.example-usercontent.com`.

## Deploy a new version

1. Push a `v*` tag on `main`, and wait for the `docker` workflow to finish.
2. Point the VM at the new image, and reset it:

   ```sh
   gcloud compute instances add-metadata cairn --zone=ZONE \
     --metadata=cairn-image=ghcr.io/davidnoyes/cairn:v1.1.0
   gcloud compute instances reset cairn --zone=ZONE
   ```

On every boot, the startup script does five things:

1. Pulls the image.
2. Resolves the image to its digest.
3. Checks with cosign that this repository's `docker` workflow signed that
   digest, from a `v*` tag or `main`.
4. Runs that same digest.
5. If any check fails, refuses to replace the container.

Docker restarts the old container when the VM boots, so a refused deploy
leaves the last verified image running. The serial console log shows why
the deploy was refused.

The deploy raises the alert from section 4, which is how you know a deploy can't
go unseen.

## Check a server

To check that a server sends the files and pages of a signed release, run
this on your own machine:

```sh
cairn verify https://cairn.example.com
```

To also check `/app`, sign in to that server with `cairn login` first. See
[Deploy integrity](../../design/e2e-api.md#deploy-integrity) for what it
checks.

## Check by hand on a staging project

Before you rely on these controls, test them on a staging project:

- Set `cairn-image` to an image you built and pushed yourself, then reset
  the VM. The startup script must refuse it.
- Change a DNS record, and confirm the alert email arrives.
- Run `cairn verify` against the staging server, and confirm it passes.

## Accepted limits

- Binary Authorization doesn't cover a plain Compute Engine VM, so the
  signature check runs in the startup script. A deployer can edit that
  script, and the edit raises an alert.
- A server could send genuine files to `cairn verify` and altered ones to
  someone else. Treat it as a spot check.
