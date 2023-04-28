# srvfs - /srv from plan9 on FreeBSD

### Create the kernel mod
make && make load
mount -t srv none /srv

