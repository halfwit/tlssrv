## tlssrv

*All operations support dp9ik, as well as p9sk1 if enabled on your authserver* 

This is a set of tools that is designed for Unix/Linux systems, allowing interactions from a 9front machine.
 - tlssrv accepts TLS connections over stdio, and runs the cmd from args over an encrypted TLS connection
 - wrkey creates a keystore that tlssrv uses to authenticate against a remote authserver using dp9ik or p9sk1.

## caveats

`wrkey` currently places a file in /tmp, which can be read by `tlssrv` but it would benefit from Unix-native password integration into `tlssrv`