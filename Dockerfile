FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Pure-Go SQLite driver: static binary, no CGO.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /cairn ./cmd/cairn

FROM alpine:3.20
# /data must exist in the image owned by the runtime user: named volumes are
# initialized from the image, so a fresh volume inherits this ownership.
RUN adduser -D -u 1000 cairn && mkdir -p /data && chown cairn:cairn /data
COPY --from=build /cairn /usr/local/bin/cairn
USER cairn
ENV CAIRN_DATA_DIR=/data
VOLUME /data
EXPOSE 8787
ENTRYPOINT ["cairn"]
CMD ["serve"]
