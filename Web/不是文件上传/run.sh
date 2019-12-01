#! /usr/bin/env bash
service mysql start 
service apache2 start
mysql -uroot -e "create user 'r00t'@'%' identified by 'r00t';flush privileges;"
mysql -uroot -proot -e "create database pic_base;"
mysql -uroot -e "grant all privileges on pic_base.* to 'r00t'@'localhost' identified by 'r00t';flush privileges;"
v=`cat /var/www/flag`
cat /var/www/install.sql | sed -i "s/D0g3{.*}/$v/g" /var/www/install.sql
mysql -uroot -proot pic_base < /var/www/install.sql
/bin/bash


