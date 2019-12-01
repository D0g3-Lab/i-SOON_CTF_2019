FROM ubuntu:16.04

RUN sed -i 's/archive.ubuntu.com/asia-east1.gce.archive.ubuntu.com/g' /etc/apt/sources.list && apt update && apt-get install -y lib32z1 xinetd && rm -rf /var/lib/apt/lists/ && rm -rf /root/.cache && apt-get autoclean && rm -rf /tmp/* /var/lib/apt/* /var/cache/* /var/log/*
#apt update && apt-get install -y lib32z1 xinetd && rm -rf /var/lib/apt/lists/ && rm -rf /root/.cache && apt-get autoclean && rm -rf /tmp/* /var/lib/apt/* /var/cache/* /var/log/*

COPY ./pwn.xinetd /etc/xinetd.d/pwn

COPY ./service.sh /service.sh

RUN chmod +x /service.sh

# useradd and put flag
RUN useradd -m pwn2 
#&& echo 'flag{d106bb2e-b8a0-4384-9d2f-04157915edcd}' > /home/pwn2/flag.txt
COPY ./flag /home/pwn2/flag

# copy bin
COPY ./bin/pwn2 /home/pwn2/pwn2
COPY ./catflag /home/pwn2/bin/sh


# chown & chmod
RUN chown -R root:pwn2 /home/pwn2 && chmod -R 750 /home/pwn2 && chmod 740 /home/pwn2/flag

# copy lib,/bin 
RUN cp -R /lib* /home/pwn2 && cp -R /usr/lib* /home/pwn2 && mkdir /home/pwn2/dev && mknod /home/pwn2/dev/null c 1 3 && mknod /home/pwn2/dev/zero c 1 5 && mknod /home/pwn2/dev/random c 1 8 && mknod /home/pwn2/dev/urandom c 1 9 && chmod 666 /home/pwn2/dev/* && cp /bin/sh /home/pwn2/bin && cp /bin/ls /home/pwn2/bin && cp /bin/cat /home/pwn2/bin

COPY ./qemu-mipsel-static /home/pwn2/qemu-mipsel
RUN chmod 755 /home/pwn2/qemu-mipsel

COPY ./ld-uClibc.so.0 /home/pwn2/lib

COPY ./libc.so.0 /home/pwn2/lib

CMD ["/service.sh"]
