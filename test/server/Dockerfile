FROM alpine:latest

RUN apk add --no-cache openssl
RUN mkdir -p /data && adduser -D -u 1000 openssl

COPY ./entrypoint.sh /entrypoint.sh
RUN sed -i 's/\r$//' /entrypoint.sh && chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]

WORKDIR /data
EXPOSE 8888

USER openssl

COPY ./data/ ./
