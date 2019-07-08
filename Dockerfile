############################
# STEP 1 build executable binary
############################

FROM quay.io:443/90poe/golang-build:builder-v3 as builder

COPY . $GOPATH/src/github.com/90poe/kafka_connect_exporter/
WORKDIR $GOPATH/src/github.com/90poe/kafka_connect_exporter/


# Using go mod.
# RUN go mod download
# Build the binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -installsuffix cgo -o /go/bin/kafka_connect_exporter -ldflags="-s -w"


############################
# STEP 2 build a small image
############################

FROM alpine

# Import from builder.
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy our static executable
COPY --from=builder /go/bin/kafka_connect_exporter /kafka_connect_exporter

# Port on which the service will be exposed.
EXPOSE 8080
EXPOSE 8888

# Run the svc binary.
CMD ["./kafka_connect_exporter"]

