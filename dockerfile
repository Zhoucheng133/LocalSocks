FROM golang:1.25-alpine AS builder
WORKDIR /app

COPY . .
ENV TZ=Asia/Shanghai

RUN go env -w GO111MODULE=on
RUN go env -w GOPROXY=https://goproxy.cn,direct

RUN go mod tidy
RUN go build -o server .

FROM alpine:3.18
WORKDIR /app
COPY --from=builder /app/server /usr/local/bin/server

EXPOSE 3000

CMD ["server"]