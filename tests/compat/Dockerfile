# Pin the multi-architecture base manifest so a tag move cannot silently change the fixture.
FROM debian:bookworm-slim@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df

ENV DEBIAN_FRONTEND=noninteractive
ARG SERVER
RUN case "$SERVER" in \
        openssh) package=openssh-server ;; \
        vsftpd) package=vsftpd ;; \
        proftpd) package=proftpd-basic ;; \
        *) echo "unknown SERVER build argument: $SERVER" >&2; exit 64 ;; \
    esac \
    && apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates "$package" \
    && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /usr/local/bin/gmacftp-compat-server
RUN chmod 0755 /usr/local/bin/gmacftp-compat-server

EXPOSE 2121 2222 30000-30009
ENTRYPOINT ["/usr/local/bin/gmacftp-compat-server"]
