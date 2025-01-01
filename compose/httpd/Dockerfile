FROM ubi9/ubi:latest
RUN dnf install httpd mod_auth_openidc nc -y

RUN rm /etc/httpd/conf.d/welcome.conf

# CMD ["sleep", "100000"]

CMD ["httpd", "-DFOREGROUND"]
