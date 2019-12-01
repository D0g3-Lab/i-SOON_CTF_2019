FROM php:7.2-apache
COPY ./php.ini /usr/local/etc/php/php.ini
COPY ./html /var/www/html
RUN chmod 555 /var/www/html
EXPOSE 80