FROM golang:1.21-alpine as builder
WORKDIR /app
COPY . .
RUN go mod download
RUN CGO_ENABLED=0 go build -o kms-service main.go

FROM alpine:3.18
WORKDIR /app
COPY --from=builder /app/kms-service .
COPY --from=builder /app/.env .
CMD ["./kms-service"]
