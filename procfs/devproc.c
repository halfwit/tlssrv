/** 
 * could be a patched procfs with semantics in place as expected, a replacement, or something else entirely  
 *  args seems like the biggest missing piec to this, though cmdline seems to be the same
 *
 * The proc device shims some 9-specific semantics via the following files:
 * - /proc/{pid}/ctl    ctl interface - not much we can replicate, nicing/clear interrupts/close fds/kill/stop/start the process 
 * - /proc/{pid}/fd	open file descriptors for process 
 * - /proc/{pid}/note   send note to process
 * - /proc/{pid}/notepg send note to process group
 * - /proc/{pid}/ns     readonly file showing current namespace 
 * - /proc/{pid}/args   read/write program cmdline arguments - check this file in the programs to see if anything is updated 

// additional output from 9
	  /proc/trace
	  /proc/n/fpregs
	  /proc/n/kregs
	  /proc/n/mem
	  /proc/n/noteid
	  /proc/n/ns
	  /proc/n/proc
	  /proc/n/profile
	  /proc/n/regs
	  /proc/n/segment
	  /proc/n/status
	  /proc/n/text
	  /proc/n/wait
 */

/* Output from curproc on FreeBSD

cmdline
dbregs
etype
file
fpregs
map
mem
note
notepg
osrel
regs
rlimit
status

/*
