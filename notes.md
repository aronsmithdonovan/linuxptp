
## SETUP
 * enabled WSL
 * installed gcc into WSL ([tutorial](https://paperbun.org/how-to-install-linux-with-c-compiler-in-windows-sd3ktpoltpbo/))
 * forked linuxptp source code so that I can save edits
 * cloned the repo into WSL
 * opened the repo in VSC with `$ code .` command

## PTP4L
 * running ptp4l.c on a device configures it as a PTP interface
 * the following output comes from initializing the WSL system:

> aronsmithdonovan@ARON-LAPTOP:~/linuxptp$ sudo ./ptp4l -i eth0 -m -S\
> [sudo] password for aronsmithdonovan:\
> ptp4l[5520.464]: port 1: INITIALIZING to LISTENING on INIT_COMPLETE\
> ptp4l[5520.464]: port 0: INITIALIZING to LISTENING on INIT_COMPLETE\
> ptp4l[5527.602]: port 1: LISTENING to MASTER on ANNOUNCE_RECEIPT_TIMEOUT_EXPIRES\
> ptp4l[5527.602]: selected local clock 00155d.fffe.894958 as best master\
> ptp4l[5527.603]: port 1: assuming the grand master role

## CHANGING THE MESSAGE CONSTRUCTION
 * files `transport.h`, `transport.c`, `msg.h`, and `msg.c` appear to be responsible for constructing the PTP messages
 * goal: modify these files s.t. it is possible to implement covert channels
 * `struct ptp_header` and `struct ptp_message` declarations are in `msg.h`
 * `sync_msg`, `delay_req_message`, and `delay_resp_msg`

## RUNNING PTP4L IN GDB
> $ sudo gdb --args ptp4l -i eth0 -m -S\
> (gdb) run

## PULL CHANGES AND PERFORM SYNC
### leader:

> $ git pull\
> $ rm -f pre-send.txt\
> $ rm -f post-receive.txt\
> $ find . -type f -exec touch {} +\
> $ make clean\
> $ make ptp4l\
> $ sudo ./ptp4l -i eth0 -m -S

### follower:

> $ git pull\
> $ rm -f pre-send.txt\
> $ rm -f post-receive.txt\
> $ find . -type f -exec touch {} +\
> $ make clean\
> $ make ptp4l\
> $ sudo date 010100001970\
> $ sudo ./ptp4l -i eth0 -m -s -S

## ADD EXECUTE PERMISSIONS TO SHELL SCRIPTS

> $ chmod +x pull-and-make.sh\
> $ chmod +x l_run.sh\
> $ chmod +x f_run.sh

## DO AFTER MODIFYING SHELL SCRIPTS
> \# try this first:
> $ git stash\
> $ git pull\
> $ git stash pop\
> $ git pull
> \# if any of those steps fail, try this:
> $ git fetch --all\
> $ git reset --hard origin/master
> \# then add execute permissions to shell scripts (above)