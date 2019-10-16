#include <lib/libkern/libkern.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/zones.h>
#include <sys/systm.h>
#include <sys/rwlock.h>
#include <sys/malloc.h>
#include <sys/syscall.h>
#include <sys/_types.h>
#include <sys/atomic.h>
#include <sys/ucred.h>
#include <sys/filedesc.h>
#include <sys/proc.h>
#include <sys/acct.h>
#include <sys/mount.h>
#include <sys/pool.h>
#include <sys/syscallargs.h>

#define DEBUG 1

struct rwlock zonesLock;
const char *name = "zonesLock";

struct entry {
	zoneid_t id; /* one particular zone id */
	char *zone_name;
	TAILQ_ENTRY(entry) entries;
};
TAILQ_HEAD(zone_list, entry);
struct entry *e;
struct zone_list zones = TAILQ_HEAD_INITIALIZER(zones);


int 
sys_zone_create(struct proc *p, void *v, register_t *retval)
{
	//	rw_init(&zonesLock, name); /* TODO fix concurrency */
	//rw_enter(&zonesLock, RW_READ | RW_WRITE);
	if (suser(p)) {
		*retval = -1;
		return EPERM;
	}
	int scanner = 0; /* Used for scanning to find first non-used zone */
	size_t done;
	struct entry *n1, *np;
	struct sys_zone_create_args /* {
		syscallarg(const char *)zonename;
	} */	*uap = v;
	char *name;
	if ((name = malloc(sizeof(char) * MAXZONENAMELEN + 1, 
	    M_TEMP, M_WAITOK | M_CANFAIL | M_ZERO)) == NULL) {
		printf("mallocing name failed\n");
		return -1;
	}
	const char *temp = SCARG(uap, zonename);
	if (temp == 0) {
		*retval = -1;
		return EFAULT;
	}
       	copyinstr(SCARG(uap, zonename), (void *)name, MAXZONENAMELEN + 1, &done);
	if (strlen(name) > MAXZONENAMELEN) {
		*retval = -1;
		return ENAMETOOLONG;
	}
#ifdef DEBUG
	printf("%s! %d, %d\n", __func__, scanner, MAXZONENAMELEN);
	printf("adding zone with name: %s\n", name);
#endif
        if ((n1 = malloc(sizeof(struct entry), M_TEMP, 
	    M_WAITOK | M_CANFAIL | M_ZERO)) == NULL) {
		printf("mallocing new zone failed\n");
		return -1;
	}
	n1->zone_name = (char *)malloc(strlen(name) + 1, M_TEMP, 
	    M_WAITOK | M_CANFAIL | M_ZERO);
	if (TAILQ_EMPTY(&zones)) {
		n1->id = scanner;
		strncpy(n1->zone_name, name, strlen(name) + 1);
		TAILQ_INSERT_HEAD(&zones, n1, entries);
		goto inserted;
	}
	TAILQ_FOREACH(np, &zones, entries) {
		printf("np->zone_name: %s, name: %s\n", np->zone_name, name);
		if (!strcmp(np->zone_name, name)) {
			printf("name already in use!\n");
			*retval = -1;
			return EEXIST;
		}
		if (scanner == -1)
			continue;
		if (np->id != scanner) {
			n1->id = scanner;
			strncpy(n1->zone_name, name, strlen(name) + 1);
			TAILQ_INSERT_BEFORE(np, n1, entries);
			*retval = (zoneid_t)scanner;
			scanner = -1;
			goto inserted;
		}
		scanner++;
	}
	if (scanner >= MAXZONES) {
		*retval = -1;
		return ERANGE;
	}
	if (scanner != -1) {
		n1->id = scanner;
		strncpy(n1->zone_name, name, strlen(name) + 1);
		TAILQ_INSERT_TAIL(&zones, n1, entries);
	}
inserted:
#ifdef DEBUG
	{
	struct entry *np2;
	printf("scanner: %d\n", scanner);
	TAILQ_FOREACH(np2, &zones, entries)
		printf("%d\n", np2->id);
	}
#endif 
	//rw_exit(&zonesLock);
	return(0);
}

int
sys_zone_destroy(struct proc *p, void *v, register_t *retval)
{
	if (suser(p)) {
		*retval = -1;
		return EPERM;
	}
	struct entry *np;
	struct sys_zone_destroy_args /* {
		syscallarg(zoneid_t)z;
	} */	*uap = v;
	zoneid_t arg = SCARG(uap, z);
	int found = 0;
	printf("%s!\n", __func__);
	TAILQ_FOREACH(np, &zones, entries) {
		if (np->id == arg) {
			TAILQ_REMOVE(&zones, np, entries);
			found = 1;
			break;
		}
	}
	if (!found) {
		*retval = -1;
		return ESRCH;
	}
	return(0);
}

int
sys_zone_enter(struct proc *p, void *v, register_t *retval)
{
	printf("%s!\n", __func__);
	return(0);
}

int
sys_zone_list(struct proc *p, void *v, register_t *retval)
{
	printf("%s!\n", __func__);
	/* TODO handle non-global zone */
	struct sys_zone_list_args /* {
		syscallarg(zoneid_t *)	zs;
		syscallarg(size_t *)	nzs;
	} */ 	*uap = v;
	int counter = 0;
	struct entry *np;
	size_t *nzsInput = malloc(sizeof(size_t),
	    M_TEMP, M_WAITOK | M_CANFAIL | M_ZERO);
        if (copyin(SCARG(uap, nzs), nzsInput, sizeof(size_t)) == EFAULT) {
		*retval = -1;
		return EFAULT;
	}
	zoneid_t *zsOutput = malloc(sizeof(zoneid_t) * (*nzsInput),
	    M_TEMP, M_WAITOK | M_CANFAIL | M_ZERO);
	printf("1\n");
	printf("nzsInput: %zu\n", *nzsInput);
	TAILQ_FOREACH(np, &zones, entries) {
		if (counter >= *nzsInput) {
			printf("YEET %d, %zu\n", counter, *nzsInput);
			*retval = -1;
			return ERANGE;
		}
		zsOutput[counter] = np->id;
		printf("Adding %d\n", counter);
		counter++;
	}
	printf("Done adding\n");
	if (copyout(zsOutput, SCARG(uap, zs), sizeof(zoneid_t) * counter)
	    == EFAULT) {
		*retval = -1;
		return EFAULT;
	}
	return(0);
}

int
sys_zone_name(struct proc *p, void *v, register_t *retval)
{
	printf("%s!\n", __func__);
	return(0);
}

int
sys_zone_lookup(struct proc *p, void *v, register_t *retval)
{
	printf("%s!\n", __func__);
	return(0);
}
