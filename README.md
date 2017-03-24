# Purge Red Hat Storage Console
Tool for purging Red Hat Storage Console configuration and reinitializing
associated nodes.

## Usage 
The `rhscon-purge` script should be ran on the RHSC host you wish to purge.  It
requires no arguments, but accepts some optional ones:

~~~
./rhscon-purge.py [-h] [-n] [--no-node-clean]
~~~ 

* -h, --help            Print the help page and exit
* -n NODES, --nodes NODES
                        Define a FQDN or list of comma-delimited FQDNs which
                        currently serve as nodes in a cluster. rhscon-purge
                        will attempt to determine nodes associated with an
                        RHSC automatically. This option should only be used to
                        specify additional nodes that need to be cleaned, that
                        did not clean successfully following automated
                        cleaning.
* --no-node-clean       Do not clean the storage nodes, only clean the local
                        configuration from the RHSC node.

It's recommended to attempt an automated cleanup before specifying any nodes
yourself via the `-n`, `--nodes` flag.

## What does it do?
`rhscon-purge` is based on the Red Hat Storage Console 2 purge guide found here: 
https://access.redhat.com/solutions/2944461
