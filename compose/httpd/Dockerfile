FROM debian:bookworm

RUN apt update
RUN apt-get install --assume-yes apache2 curl
RUN curl https://github.com/OpenIDC/mod_auth_openidc/releases/download/v2.4.16.6/libapache2-mod-auth-openidc_2.4.16.6-1.bookworm_amd64.deb -L -o mod_auth_openidc.deb
RUN dpkg -i mod_auth_openidc.deb || apt-get --fix-broken install --assume-yes
RUN sed -i 's/Listen 80/Listen 8000/g' /etc/apache2/ports.conf

CMD ["apachectl", "-X"]
