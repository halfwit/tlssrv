## x9utils

*All operations support dp9ik, as well as p9sk1 if enabled on your authserver* 

This is a set of tools that is designed for Unix/Linux systems, allowing interactions from a 9front machine.
 - tlssrv accepts TLS connections over stdio, and runs the cmd from args over an encrypted TLS connection
 - wrkey creates a pseudo-nvram keystore that tlssrv, devshim, procshim, and exportfs use to authenticate against a remote authserver using dp9ik or p9sk1.
 - tlsclient was written by someone else, as well of much of the supporting framework for these utilities
   - see https://git.sr.ht/~moody/tlsclient for much more detail on usage
 - srv dials the remote resource and posts the fd to /srv. Requires srvfs

## Caveats 
This is a work in progress, but is intended to be used to create a cpu listener with access to a Unix/Linux userland for further work on https://github.com/halfwit/x9dev and eventually the ability to rcpu into a Unix/Linux system where X11 programs can be forwarded to a plan9/9front machine while utilizing more powerful graphics cards but still maintaining a native feel

## Jails

*Currently not available*

A jail implementation will be provided for use on FreeBSD. This will set up a chrooted directory with our FUSE-based stubs in place, and inetd listening for incoming connections. In this role, it will take the place of aux/listen to start our usual scripts, such as tcp17019. 

The scripts mount and bind will mimic the utilities from 9front, using devshim's /dev/namespace device. Any other considerations and steps will be documented here as things progress. 
