FROM php:7.1-apache

COPY www/ /var/www/html/
COPY flag /flag
COPY ./run.sh /var/www/run.sh
RUN chmod +x /var/www/run.sh

EXPOSE 80
