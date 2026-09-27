FROM alpine:3.21

RUN apk add --no-cache bash curl jq kubectl

COPY collect-kubernetes-dns.sh /usr/local/bin/collect-kubernetes-dns.sh
RUN chmod 0555 /usr/local/bin/collect-kubernetes-dns.sh

USER 65532:65532
ENTRYPOINT ["/usr/local/bin/collect-kubernetes-dns.sh"]
