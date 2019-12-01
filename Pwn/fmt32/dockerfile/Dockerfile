FROM ubuntu:16.04

# set source download and install xinted
RUN sed -i 's/archive.ubuntu.com/asia-east1.gce.archive.ubuntu.com/g' /etc/apt/sources.list && apt update && apt-get install -y lib32z1 xinetd && rm -rf /var/lib/apt/lists/ && rm -rf /root/.cache && apt-get autoclean && rm -rf /tmp/* /var/lib/apt/* /var/cache/* /var/log/*

COPY ./pwn.xinetd /etc/xinetd.d/pwn

COPY ./service.sh /service.sh
#COPY ./flag.py /flag.py

RUN chmod 700 /service.sh 
#&& chmod 700 /flag.py

# useradd
RUN useradd -m pwn 

#put flag
COPY ./flag /home/pwn/flag

# copy bin
COPY ./bin/pwn /home/pwn/pwn
COPY ./binsh/sh /home/pwn/bin/sh
COPY ./binsh/cat /home/pwn/bin/cat
COPY ./binsh/ls /home/pwn/bin/ls


# chown & chmod
RUN chown -R root:pwn /home/pwn && chmod -R 750 /home/pwn && chmod 740 /home/pwn/flag

# copy lib,/bin 
RUN cp -R /lib* /home/pwn && mkdir /home/pwn/dev && mknod /home/pwn/dev/null c 1 3 && mknod /home/pwn/dev/zero c 1 5 && mknod /home/pwn/dev/random c 1 8 && mknod /home/pwn/dev/urandom c 1 9 && chmod 666 /home/pwn/dev/* 

#change passwd
#RUN echo pwn:1q2q3q4q | chpasswd && echo root:spr1ng | chpasswd


#open ssh
RUN apt-get update && apt-get -y install ssh
RUN sed -i 's/Port 22/Port 22250/g' /etc/ssh/sshd_config && sed -i 's/PermitRootLogin prohibit-password/PermitRootLogin yes/g' /etc/ssh/sshd_config

#chroot
RUN sed -i '$a#define username to apply chroot jail to\nMatch User pwn\n#specify chroot jail\nChrootDirectory /home/pwn' /etc/ssh/sshd_config

CMD ["/service.sh"]
