FROM debian:stable-slim

RUN apt-get update && apt-get -uy upgrade
RUN apt-get -y install ca-certificates && update-ca-certificates

FROM scratch

COPY --from=0 /etc/ssl/certs /etc/ssl/certs
RUN pwd
RUN ls
ADD coredns /coredns

EXPOSE 53 53/udp
ENTRYPOINT ["/coredns"]