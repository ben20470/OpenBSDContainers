# Zones                                                                         
## Containers for OpenBSD
Container technologies aim to provide virtualisation at the kernel level instead of at the hardware level. This is implemented by extending a kernel to partition and isolate certain services to prevent processes ina container from interacting with processes in another container. Such isolation may require limiting thevisibility of processes and file descriptors in the system, creating independent users and views of the filesystem, virtualising the network stack, and guaranteeing access to resources.

Several container technologies exist such as Docker, Solaris Zones, FreeBSD jails, and AIX WPARs. This project is loosely modelled on the design of Solaris Zones as documented in PSARC/2002/174 ([documented here](https://documents.pub/document/zones-designspecopensolaris.html)). This project implements isolation of processes and several kernel variables in OpenBSD.

## How to run
A diff has been provided that adds header files, programs, and modifications to the system to use and test the kernel zone functionality. The diff can be applied by running the following:
```
$ cd /usr/src
$ mkdir usr.sbin/zone
$ patch < /path/to/zones.diff
Hmm...  Looks like a unified diff to me...
```
Note that you must be in an OpenBSD environment to run this project.

## Interfaces
### zone_create
zoneid_t        `zone_create(const char *zonename);`

`zone_create` should create a new zone id for use in the system, with a unique name specified by zonename. Valid zone names may contain alphanumeric characters, ’-’ (hyphen), or ’_’ (underscore). On success it returns the zone id that was created. On failure it returns -1 and sets errno accordingly:

**EPERM** the current program is not in the global zone

**EPERM** the current user is not root

**EEXIST** a zone with the specified name already exists

**ERANGE** too many zones are currently running

**EFAULT** zonename points to a bad address

**ENAMETOOLONG** the name of the zone exceeds MAXZONENAMELEN

**EINVAL** the name of the zone contains invalid characters


### zone_destroy
int                `zone_destroy(zoneid_t z);`

`zone_destroy` should delete the specified zone instance. On success returns 0. On failure it returns -1 and sets errno accordingly:

**EPERM** the current program is not in the global zone

**EPERM** the current user is not root

**ESRCH** the specified zone does not exist

**EBUSY** the specified zone is still in use, ie, a process is still running in the zone

### zone_enter
int                `zone_enter(zoneid_t z);`

`zone_enter` moves the current process into the zone. On success it returns 0. On failure it returns -1 and sets errno accordingly:

**EPERM** the current program is not in the global zone

**EPERM** the current user is not root

**ESRCH** the specified zone does not exist

### zone_list
int               ` zone_list(zoneid_t *zs, size_t *nzs);`

In the global zone `zone_list` will provide the list of zones in the running system as an array of zoneid_ts. If run in a non-global zone, the list will only contain the current zone. The value at nzs refers to the number of array entries in zs on input. On success it returns 0 and the value at nzs is set to the number of zones listed in zs. On failure it returns -1 and sets errno accordingly:

**EFAULT** zs or nzs point to a bad address

**ERANGE** if the number at nzs is less than the number of running zones in the system

### zone_lookupzone
id_t        `zone_lookup(const char *name);`

`zone_lookup` provides the id associated with the name. If run in a non-global zone, only the current zone may be specified. On success it returns the zone id that is associated to the name. If name is a NULL pointer, the zone id of the calling process must be returned. On failure it returns -1 and sets errno accordingly:

**ESRCH** The specified zone does not exist

**ESRCH** The specified zone is not visible in a non-global zone

**EFAULT** namerefers to a bad memory address

**ENAMETOOLONG** the name of the zone exceeds MAXZONENAMELEN

### zone_name
int        `zone_name(zoneid_t z, char *name, size_t namelen);`

`zone_name` provides the name of the zone identified by z. If run in a non-global zone, only the current zone may be specified. If the zone id z is -1, it will return the name of the current zone. On success retursn 0 with the name returned in the memory specified by name and namelen. On failure it returns -1 and sets errno accordingly:

**ESRCH** The specified zone does not exist

**ESRCH** The specified zone is not visible in a non-global zone

**EFAULT** name refers to a bad memory address

**ENAMETOOLONG** The requested name is longer than namelen bytes.

### fork(2)
When a process forks, the child must inherit the zone it is running in from its parent. The only way for a process to change zones is via the `zone_enter` syscall, which is limited to root processes in the global zone.

### kill(2)
The kernel signalling code should be modified to provide the following semantics:

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;•If any user in a non-global zone tries to signal any process in another zone, it fails with ESRCH.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;•If a non-root user in the global zone signals a process in another zone, it fails with EPERM.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;•root in the global zone may signal any process in any zone

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;•Users within a zone get normal signalling semantics

### sysctl(3)
The kernel side of sysctl modifies its handling of CTL_KERN, KERN_PROC and KERN_FILE to filter results.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;•the kinfo_proc structure has been modified to include a ps_zoneid field which identifies the zonethe process is running in

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;•the global zone does not get a filtered list of processes

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;•non-global zones gets a list of processes that exist in their current zone

The following CTL_KERN variables will be modified to have per-zone settings:

**KERN_HOSTNAME** The global zone defaults to an empty hostname value. Non-global zones default the host name to the zone name it is created with. The host name value can only be changed by the root user within a zone.

**KERN_DOMAINNAME** The domain name value defaults to an empty string in both the global and non-global zones. The domain name value can only be changed by the root user within a zone.

**KERN_HOSTID** The host identifier defaults to 0. The host identifier can only be changed by the root user within a zone.

**KERN_BOOTTIME** The boot-time value for non-global zones is set to the time at which a zone was created. It is read-only. The following CTL_KERN variables will be modified to be read-only in non-global zones:

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;•KERN_MAXCLUSTERS

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;•KERN_CACHEPCT

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;•KERN_POOL_DEBUG

### struct process
`struct process` represents the kernels state relating to a running program. This type has been extended to record which zone the process is running in.

## Userland Programs
To test the zones subsystem, some userland utilities have been modified. When appropriate, programs were modified to accept the following options:

**-z zone** Limit the scope of the command to the specified zone. The zone may be specified by name, or by numeric id.

**-Z** The name of the zone should be added to the programs output.

&nbsp;
The following changes were implemented:
### ps(1)
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;•the -z option

When a zone is specified, the list of processes displayed by ps will be limited to those processes running in the specified zone.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;•the -Z option

-Z causes the zones name to be prepended to the columns that are output by ps(1). 

Additionally, “ZONES” may be specified as a column in custom column format specifiers.
### pgrep, pkill
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;•the -z flag

pgrep and pkill will only match on processes that are running in the specified zone.

### zone(8)
zone(8) is a new program and can be installed under /usr/sbin. The usage output is shown below: 
```
usage:  zone create zonename
        zone destroy zonename|zoneid
        zone listzone lookup [zonename]
        zone name [zoneid]
        zone exec zonename|zoneid command ...
```
The sub-commands map to the system calls described above. Note that the arguments to the lookup, and name sub-commands are optional and default to the syscalls that look up the information for the current zone.

