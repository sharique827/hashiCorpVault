FROM golang:1.21-alpine as builder
WORKDIR /app
COPY . .
RUN go mod download
RUN CGO_ENABLED=0 go build -o backend-service main.go

FROM alpine:3.18
WORKDIR /app
COPY --from=builder /app/backend-service .
COPY --from=builder /app/.env .
CMD ["./backend-service"]
