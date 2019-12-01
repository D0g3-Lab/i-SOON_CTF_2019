FROM ubuntu:16.04

RUN sed -i 's/archive.ubuntu.com/asia-east1.gce.archive.ubuntu.com/g' /etc/apt/sources.list && apt update && apt-get install -y lib32z1 xinetd && rm -rf /var/lib/apt/lists/ && rm -rf /root/.cache && apt-get autoclean && rm -rf /tmp/* /var/lib/apt/* /var/cache/* /var/log/*
#apt update && apt-get install -y lib32z1 xinetd && rm -rf /var/lib/apt/lists/ && rm -rf /root/.cache && apt-get autoclean && rm -rf /tmp/* /var/lib/apt/* /var/cache/* /var/log/*

COPY ./pwn.xinetd /etc/xinetd.d/pwn

COPY ./service.sh /service.sh

RUN chmod +x /service.sh

# useradd and put flag
RUN useradd -m pwn1 
#&& echo 'flag{8fd8333c-1c19-44b3-b3da-0264db0e1ffb}' > /home/pwn1/flag.txt
COPY ./flag /home/pwn1/flag

# copy bin
COPY ./bin/pwn1 /home/pwn1/pwn1
COPY ./catflag /home/pwn1/bin/sh


# chown & chmod
RUN chown -R root:pwn1 /home/pwn1 && chmod -R 750 /home/pwn1 && chmod 740 /home/pwn1/flag

# copy lib,/bin 
RUN cp -R /lib* /home/pwn1 && cp -R /usr/lib* /home/pwn1 && mkdir /home/pwn1/dev && mknod /home/pwn1/dev/null c 1 3 && mknod /home/pwn1/dev/zero c 1 5 && mknod /home/pwn1/dev/random c 1 8 && mknod /home/pwn1/dev/urandom c 1 9 && chmod 666 /home/pwn1/dev/* && cp /bin/sh /home/pwn1/bin && cp /bin/ls /home/pwn1/bin && cp /bin/cat /home/pwn1/bin

CMD ["/service.sh"]
