# PUB-04R review candidate for linux/arm64. No production approval.
# Digests bind the official registry indexes observed in the R3 build.
FROM ghcr.io/openai/tunnel-client:v0.0.21@sha256:983df88cd56d49ae3863ae52b751d106c95aba8a03783c87ac2304b4e0cd154a AS tunnel
FROM python:3.15.2-alpine3.24@sha256:0f9552bb28711333da16915ec146f5e6bb44a7fdac9ced15dc17c2e0206346dd
ARG TARGETARCH
COPY apk-arm64.lock requirements-arm64.lock /app/
RUN set -eu; \
    test "$TARGETARCH" = arm64; \
    test "$(apk --print-arch)" = aarch64; \
    set --; \
    while read -r pin checksum; do \
      test -n "$pin" && test -n "$checksum" || exit 1; \
      set -- "$@" "$pin"; \
    done < /app/apk-arm64.lock; \
    apk add --upgrade --no-cache "$@"; \
    awk -F: '/^C:/{checksum=substr($0,3)} /^P:/{name=substr($0,3)} \
      /^V:/ && name!=".python-rundeps"{print name "=" substr($0,3) " " checksum}' \
      /lib/apk/db/installed | LC_ALL=C sort > /tmp/pub04r-apk.actual; \
    cmp /app/apk-arm64.lock /tmp/pub04r-apk.actual; \
    rm /tmp/pub04r-apk.actual; \
    python3 -m pip --isolated install --no-cache-dir --only-binary=:all: --require-hashes --force-reinstall \
      --index-url https://pypi.org/simple -r /app/requirements-arm64.lock; \
    python3 -m pip check
COPY --from=tunnel /usr/bin/tunnel-client /usr/bin/tunnel-client
COPY gateway.py filesystem.py dashboards.py dashboard_writes.py dashboard_safety_stage2.py dashboard_commit.py dashboard_snapshot_metadata.py dashboard_restore.py dashboard_approval_reset.py backup_retention_stage3.py backup_retention_stage5.py backup_retention_stage6.py backup_retention_commit_stage4.py backup_retention_preview.py backup_retention_production.py apparmor_diagnose.py unified_approval.py /app/
COPY apparmor.txt /app/apparmor.txt
COPY run.sh /app/run.sh
RUN chmod 0700 /app/run.sh
WORKDIR /app
ENTRYPOINT ["/bin/sh", "/app/run.sh"]
