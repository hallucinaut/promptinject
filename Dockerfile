FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY . .

RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -o /promptinject-api ./cmd/promptinject-api

FROM alpine:latest
RUN apk --no-cache add ca-certificates

COPY --from=builder /promptinject-api /usr/local/bin/

EXPOSE 8080

ENTRYPOINT ["promptinject-api"]
