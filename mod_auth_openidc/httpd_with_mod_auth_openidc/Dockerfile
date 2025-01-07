FROM debian:bookworm
ARG MOD_AUTH_OPENIDC_VERSION=2.4.16.6

RUN apt update
RUN apt-get install --assume-yes apache2 curl php-common libapache2-mod-php php-cli

# Download pre-build binaries from the project
RUN curl https://github.com/OpenIDC/mod_auth_openidc/releases/download/v${MOD_AUTH_OPENIDC_VERSION}/libapache2-mod-auth-openidc_${MOD_AUTH_OPENIDC_VERSION}-1.bookworm_amd64.deb -L -o mod_auth_openidc.deb
# Install the binary, and install all missing dependencies
RUN dpkg -i mod_auth_openidc.deb || apt-get --fix-broken install --assume-yes

COPY keys.sh /etc/apache2
RUN cd /etc/apache2 && chmod +x keys.sh && ./keys.sh

# Change Apache to run on port 8080
RUN sed -i 's/Listen 80/Listen 8000/g' /etc/apache2/ports.conf

# Run Apache in the foreground to avoid the container to terminate
CMD ["apachectl", "-X"]
