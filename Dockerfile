# aibank — self-hosted image.
#
# Base is python:3.12-slim and NOT alpine: aibank is pure stdlib, so musl buys
# nothing here, while glibc avoids the DNS-resolver differences that bite an
# outbound HTTPS client talking to a payment provider. There is no build stage
# and no requirements.txt because there are no dependencies -- the whole
# "install" is a file copy.
FROM python:3.12-slim

# Run as a non-root uid. A payment service that is root inside its container
# turns any RCE into a host-level problem, and nothing here needs privilege:
# the only writable path is the database directory.
RUN useradd --create-home --uid 10001 aibank \
 && mkdir -p /var/lib/aibank \
 && chown aibank:aibank /var/lib/aibank

WORKDIR /app
COPY aibank/ /app/aibank/
RUN chown -R aibank:aibank /app
USER aibank

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    AIBANK_DB=/var/lib/aibank/aibank.db \
    AIBANK_HOST=0.0.0.0 \
    AIBANK_PORT=8000

# The ledger must outlive the container. Declaring it here means `docker run`
# without a mount still gets a volume rather than silently writing the only
# copy of the books into a layer that `docker rm` deletes.
VOLUME ["/var/lib/aibank"]

EXPOSE 8000

# /health is served without auth and reports the schema version, so an
# orchestrator can tell "process up" from "process up against the right
# database" -- the second is what actually matters after a deploy.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request,os,sys; \
u='http://127.0.0.1:'+os.environ.get('AIBANK_PORT','8000')+'/health'; \
sys.exit(0 if urllib.request.urlopen(u,timeout=4).status==200 else 1)"

# NOT `migrate && serve`. Migration is a deliberate, auditable step (see
# README): an entrypoint that migrates on every container start would apply an
# unreviewed ALTER to a production ledger during a routine restart or a
# replica scale-up. `serve` refuses to boot against an unexpected schema and
# names `migrate` as the fix.
ENTRYPOINT ["python", "-m", "aibank.cli"]
CMD ["serve"]
