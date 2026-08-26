# syntax=docker/dockerfile:1

FROM oven/bun:1 AS frontend-builder
WORKDIR /app
COPY frontend/package.json frontend/bun.lockb* ./
RUN bun install --frozen-lockfile
COPY frontend/ ./
RUN bun run build

FROM golang:1.23-alpine AS backend-builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /app/server .

FROM nginx:1.27-alpine

RUN apk add --no-cache ca-certificates tzdata bash

COPY --from=frontend-builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

COPY --from=backend-builder /app/server /app/server

COPY start.sh /start.sh
RUN chmod +x /start.sh

EXPOSE 80 4500

ENTRYPOINT ["/start.sh"]