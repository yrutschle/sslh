##########################################################################################
## BUILD APPLICATION
##########################################################################################
FROM alpine:latest as build

# install required packages first to be able to take advantage of caching
RUN apk add \
  gcc \
  libconfig-dev \
  make \
  musl-dev \
  pcre2-dev \
  perl

# copy files and build the app
WORKDIR /sslh
ADD . .
RUN make sslh-select && \
  strip sslh-select


##########################################################################################
## PACKAGE APPLICATION
##########################################################################################
FROM alpine:latest

# install required packages first and in parallel with the build container execution
RUN apk --no-cache add libconfig pcre2

# copy the final executable from the build container
COPY --from=build /sslh/sslh-select /sslh
ENTRYPOINT [ "/sslh", "--foreground"]
