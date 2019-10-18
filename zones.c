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

#define GLOBAL -1
#define DLIST 1


struct rwlock zonesLock;
const char *name = "zonesLock";

struct proc_entry {
	pid_t pid;
	SLIST_ENTRY(proc_entry) proc_entries;
};
SLIST_HEAD(proc_list, proc_entry);
struct proc_entry *f;

struct entry {
	zoneid_t id; /* one particular zone id */
	char *zone_name;
	struct proc_list procs;
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

	/* Zones can only be created root in global zone */
	if (suser(p) || (p->p_p->zone != GLOBAL)) {
#ifdef DCREATE
		*retval = -1;
#endif
		return EPERM;
	}
	int scanner = 1; /* Used for scanning to find first non-used zone */
	struct entry *n1, *np;
	struct sys_zone_create_args /* {
		syscallarg(const char *)zonename;
	} */	*uap = v;

	/* Get new zone's name */
	char *name;
	if ((name = malloc(sizeof(char) * MAXZONENAMELEN + 1, 
	    M_TEMP, M_WAITOK | M_CANFAIL | M_ZERO)) == NULL) {
		printf("mallocing name failed\n");
		return -1;
	}
       	copyinstr(SCARG(uap, zonename), (void *)name, 
	    MAXZONENAMELEN + 1, NULL);
	if (strlen(name) > MAXZONENAMELEN) {
		*retval = -1;
		return ENAMETOOLONG;
	}

#ifdef DCREATE
	printf("%s! %d, %d\n", __func__, scanner, MAXZONENAMELEN);
	printf("adding zone with name: %s\n", name);
#endif
        if ((n1 = malloc(sizeof(struct entry), M_TEMP, 
	    M_WAITOK | M_CANFAIL | M_ZERO)) == NULL) {
		printf("mallocing new zone failed\n");
		return -1;
	}
	struct proc_list procs = SLIST_HEAD_INITIALIZER(procs);
	n1->procs = procs;
	n1->zone_name = (char *)malloc(strlen(name) + 1, M_TEMP, 
	    M_WAITOK | M_CANFAIL | M_ZERO);

	if (TAILQ_EMPTY(&zones)) {
		/* If there are no non-global zones, insert first one */
		n1->id = scanner;
		strncpy(n1->zone_name, name, strlen(name) + 1);
		TAILQ_INSERT_HEAD(&zones, n1, entries);
		goto inserted;
	}

	/* Iterate through until there is a missing zone id */
	TAILQ_FOREACH(np, &zones, entries) {
#ifdef DCREATE
		printf("np->zone_name: %s, name: %s\n", np->zone_name, name);
#endif
		if (!strcmp(np->zone_name, name)) {
#ifdef DCREATE
			printf("name already in use!\n");
#endif
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
	if (scanner > MAXZONES) {
		*retval = -1;
		return ERANGE;
	}
	/* If a zone wasn't added, one needs to be added to tail */
	if (scanner != -1) {
		n1->id = scanner;
		strncpy(n1->zone_name, name, strlen(name) + 1);
		TAILQ_INSERT_TAIL(&zones, n1, entries);
		*retval = scanner;
	}
inserted:
#ifdef DCREATE
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
	/* Zones can only be destroyed by root in global zone */
	if (suser(p) || (p->p_p->zone != GLOBAL)) {
		*retval = -1;
		return EPERM;
	}
	struct entry *np;
	struct proc_entry *proc;
	struct sys_zone_destroy_args /* {
		syscallarg(zoneid_t)z;
	} */	*uap = v;
	zoneid_t arg = SCARG(uap, z);

	/* Global zone can't be deleted */
	if (arg == GLOBAL) {
		*retval = -1;
		return EBUSY;
	}
	int found = 0;

#ifdef DDEST
	printf("%s!\n", __func__);
#endif

	TAILQ_FOREACH(np, &zones, entries) {
		if (np->id == arg) {
			/* Found zone to destroy, check if still in use */
			if (!SLIST_EMPTY(&np->procs)) {
				SLIST_FOREACH(proc, &np->procs, proc_entries) {
				}
			}
#ifdef DDEST
			printf("destroying zone with id: %d\n", np->id);
#endif
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
	if (suser(p) || (p->p_p->zone != GLOBAL)) {
		*retval = -1;
		return EPERM;
	}
	struct sys_zone_enter_args /* {
		syscallarg(zoneid_t)	z;
	} */ 	*uap = v;
	zoneid_t zone = SCARG(uap, z);
	struct entry *np;
	struct proc_entry *new;
        if ((new = malloc(sizeof(struct proc_entry), M_TEMP, 
	    M_WAITOK | M_CANFAIL | M_ZERO)) == NULL) {
		printf("mallocing new zone failed\n");
		return -1;
	}
	new->pid = p->p_p->ps_pid;
	TAILQ_FOREACH(np, &zones, entries) {
		if (np->id == zone) {
			SLIST_INSERT_HEAD(&np->procs, new, proc_entries);
			*retval = 0;
			return 0;
		}
	}
	p->p_p->zone = zone;
	*retval = -1;
	return ESRCH;
}

int
sys_zone_list(struct proc *p, void *v, register_t *retval)
{
#ifdef DLIST
	printf("%s!\n", __func__);
#endif
	/* TODO handle non-global zone */
	struct sys_zone_list_args /* {
		syscallarg(zoneid_t *)	zs;
		syscallarg(size_t *)	nzs;
	} */ 	*uap = v;
	int counter = 0;
	struct entry *np;
	size_t *nzsInput = malloc(sizeof(size_t),
	    M_TEMP, M_WAITOK | M_CANFAIL | M_ZERO);

	/* Grab size of zs */
        if (copyin(SCARG(uap, nzs), nzsInput, sizeof(size_t)) == EFAULT) {
#ifdef DLIST
		printf("copyin failed\n");
#endif
		*retval = -1;
		return EFAULT;
	}

	zoneid_t *zsOutput = malloc(sizeof(zoneid_t) * (*nzsInput),
	    M_TEMP, M_WAITOK | M_CANFAIL | M_ZERO);
	zsOutput[counter++] = 0;
	TAILQ_FOREACH(np, &zones, entries) {
		if (counter >= *nzsInput) {
#ifdef DLIST
			printf("nzs is less than number of zones \
			    number of zones:%d, nzs:%zu\n", counter, *nzsInput);
#endif
			*retval = -1;
			return ERANGE;
		}
		zsOutput[counter] = np->id;
#ifdef DLIST
		printf("Adding %d\n", counter);
#endif
		counter++;
	}
	if (copyout(zsOutput, SCARG(uap, zs), sizeof(zoneid_t) * counter)
	    == EFAULT) {
#ifdef DLIST
		printf("copyout failed in zone_list\n");
#endif
		*retval = -1;
		return EFAULT;
	}
	if (copyout(&counter, SCARG(uap, nzs), sizeof(size_t))
	    == EFAULT) {
#ifdef DLIST
		printf("copyout failed in zone_list2\n");
#endif
		*retval = -1;
		return EFAULT;
	}
	*retval = 0;
	return(0);
}


int
zone_name(zoneid_t z, char *name, size_t namelen)
{
	zoneid_t zoneID = z;
	struct entry *np;
	TAILQ_FOREACH(np, &zones, entries) {
		if (np->id == zoneID) {
			if (strlen(np->zone_name) > namelen) {
#ifdef DNAME
				printf("len of zone_name:%zu\n",
				    strlen(np->zone_name));
				printf("namelen:%zu\n", namelen);
#endif
				return ENAMETOOLONG;
			}
			strncpy(name, np->zone_name, namelen);
			return 0;
		}
	}
	return ESRCH;
}

int
sys_zone_name(struct proc *p, void *v, register_t *retval)
{
	/* TODO -1 if current zone, non-global zones */
	int error;
	zoneid_t zoneID;
	size_t namelen;
	struct entry *np;
	struct sys_zone_name_args /* {
		syscallarg(zoneid_t)	z;
		syscallarg(char *)	name;
		syscallarg(size_t) 	namelen;
	} */	*uap = v;
	zoneID = SCARG(uap, z);
	namelen = SCARG(uap, namelen);
	if (!zoneID) {
		/* Global zone */
		error = copyoutstr("global", SCARG(uap, name), 
		    strlen("global") + 1, NULL);
		if (error) {
			*retval = -1;
			return error;
		}
		*retval = 0;
		return 0;
	}
#ifdef DNAME
	printf("%s!\n", __func__);
	printf("zoneID:%d\n", zoneID);
	printf("namelen:%zu\n", namelen);
#endif
	TAILQ_FOREACH(np, &zones, entries) {
		if (np->id == zoneID) {
			if (strlen(np->zone_name) > namelen) {
#ifdef DNAME
				printf("len of zone_name:%zu\n",
				    strlen(np->zone_name));
				printf("namelen:%zu\n", namelen);
#endif
				*retval = -1;
				return ENAMETOOLONG;
			}
			error = copyoutstr(np->zone_name, SCARG(uap, name),
			    strlen(np->zone_name) + 1, NULL);
			if (error) {
				*retval = -1;
				return error;
			}
			*retval = 0;
			return 0;
		}
	}
	*retval = -1;
	return ESRCH;
}

int
sys_zone_lookup(struct proc *p, void *v, register_t *retval)
{
	struct entry *np;
	int error;
	struct sys_zone_lookup_args /* {
		syscallarg(const char *) name;
	} */ 	*uap = v;
	char *name;
	if ((name = malloc(sizeof(char) * MAXZONENAMELEN + 1, 
	    M_TEMP, M_WAITOK | M_CANFAIL | M_ZERO)) == NULL) {
		printf("mallocing name failed in lookup\n");
		return -1;
	}
       	error = copyinstr(SCARG(uap, name), (void *)name, 
	    MAXZONENAMELEN + 1, NULL);
	if (error ==  ENAMETOOLONG) {
#ifdef DLOOK
		printf("enametoolong in lookup\n");
#endif
		*retval = -1;
		return ENAMETOOLONG;
	} else if (error == EFAULT) {
#ifdef DLOOK
		printf("efault in lookup\n");
#endif
		*retval = -1;
		return EFAULT;
	}
#ifdef DLOOK
	printf("%s!\n", __func__);
	printf("name given:%s.\n", name);
#endif
	if (!strcmp(name, "global")) {
		*retval = np->id;
		return 0;
	}
	TAILQ_FOREACH(np, &zones, entries) {
		if (!strcmp(np->zone_name, name)) {
			*retval = np->id;
			return 0;
		}
	}
	*retval = -1;
	return(ESRCH);
}
