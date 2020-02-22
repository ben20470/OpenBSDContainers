+#include <lib/libkern/libkern.h>
+#include <sys/param.h>
+#include <sys/types.h>
+#include <sys/zones.h>
+#include <sys/systm.h>
+#include <sys/rwlock.h>
+#include <sys/malloc.h>
+#include <sys/syscall.h>
+#include <sys/_types.h>
+#include <sys/atomic.h>
+#include <sys/ucred.h>
+#include <sys/filedesc.h>
+#include <sys/proc.h>
+#include <sys/acct.h>
+#include <sys/mount.h>
+#include <sys/pool.h>
+#include <sys/syscallargs.h>
+
+int check_name(char *);
+
+#define GLOBAL 0
+
+struct proc_entry {
+	pid_t pid;
+	SLIST_ENTRY(proc_entry) proc_entries;
+};
+SLIST_HEAD(proc_list, proc_entry);
+struct proc_entry *f;
+
+struct entry {
+	zoneid_t 	id; /* one particular zone id */
+	int 		hostid; /* per-zone hostid */
+	char 		*zone_name;
+	struct proc_list procs;
+	TAILQ_ENTRY(entry) entries;
+};
+TAILQ_HEAD(zone_list, entry);
+struct entry *e;
+struct zone_list zones = TAILQ_HEAD_INITIALIZER(zones);
+int globalHost = 0;
+
+/*
+ * Return 0 if all chars are valid for zone name, 1 otherwise.
+ */
+int
+check_name(char *name)
+{
+	int i;
+	for (i = 0; i < strlen(name); i++) {
+		if (name[i] >= '0' && name[i] <= '9')
+			continue;
+		if (name[i] >= 'A' && name[i] <= 'Z')
+			continue;
+		if (name[i] >= 'a' && name[i] <= 'z')
+			continue;
+		if (name[i] == '-' || name[i] == '_')
+			continue;
+		return 1;
+	}
+	return 0;
+}
+
+/*
+ * Create a new zone for process isolation.
+ */
+int
+sys_zone_create(struct proc *p, void *v, register_t *retval)
+{
+	int 	scanner;
+	char 	*name;
+	struct entry *n1, *np;
+	struct sys_zone_create_args /* {
+		syscallarg(const char *)zonename;
+	} */	*uap = v;
+
+	if (suser(p) || (p->p_p->zone != GLOBAL)) {
+		*retval = -1;
+		/* zones can only be created root in global zone */
+		return EPERM;
+	}
+	scanner = 1; /* Used for scanning to find first non-used zone */
+
+	/* Get new zone's name */
+	if ((name = malloc(sizeof(char) * MAXZONENAMELEN + 1,
+	    M_TEMP, M_WAITOK | M_CANFAIL | M_ZERO)) == NULL) {
+		printf("mallocing name failed\n");
+		return -1;
+	}
+       	copyinstr(SCARG(uap, zonename), (void *)name,
+	    MAXZONENAMELEN + 1, NULL);
+
+	/* check for valid characters */
+	if (check_name(name)) {
+		*retval = -1;
+		return EINVAL;
+	}
+
+	if (strlen(name) > MAXZONENAMELEN) {
+		*retval = -1;
+		return ENAMETOOLONG;
+	}
+
+#ifdef DCREATE
+	printf("%s! %d, %d\n", __func__, scanner, MAXZONENAMELEN);
+	printf("adding zone with name: %s\n", name);
+#endif
+
+	/* n1 represents new zone being created */
+        if ((n1 = malloc(sizeof(struct entry), M_TEMP,
+	    M_WAITOK | M_CANFAIL | M_ZERO)) == NULL) {
+		printf("mallocing new zone failed\n");
+		return -1;
+	}
+	struct proc_list procs = SLIST_HEAD_INITIALIZER(procs);
+	n1->procs = procs;
+	n1->hostid = 0;
+	n1->zone_name = (char *)malloc(strlen(name) + 1, M_TEMP,
+	    M_WAITOK | M_CANFAIL | M_ZERO);
+
+	if (TAILQ_EMPTY(&zones)) {
+		/* If there are no non-global zones, insert first one */
+		n1->id = scanner;
+		strncpy(n1->zone_name, name, strlen(name) + 1);
+		TAILQ_INSERT_HEAD(&zones, n1, entries);
+		goto inserted;
+	}
+
+	/* Iterate through until there is a missing zone id */
+	TAILQ_FOREACH(np, &zones, entries) {
+		if (!strcmp(np->zone_name, name)) {
+#ifdef DCREATE
+			printf("name already in use!\n");
+#endif			/* we've found a zone with same name */
+			*retval = -1;
+			return EEXIST;
+		}
+		if (np->id != scanner) {
+			/* we've found a missing id to fill */
+			n1->id = scanner;
+			strncpy(n1->zone_name, name, strlen(name) + 1);
+			TAILQ_INSERT_BEFORE(np, n1, entries);
+			*retval = (zoneid_t)scanner;
+			scanner = -1;
+			goto inserted;
+		}
+		scanner++;
+	}
+	if (scanner > MAXZONES) {
+		*retval = -1; 	/* too many zones */
+		return ERANGE;
+	}
+
+	/* If a zone wasn't added, one needs to be added to tail */
+	if (scanner != -1) {
+		n1->id = scanner;
+		strncpy(n1->zone_name, name, strlen(name) + 1);
+		TAILQ_INSERT_TAIL(&zones, n1, entries);
+		*retval = scanner;
+	}
+inserted:
+	return(0);
+}
+
+/*
+ * Find specified zone, then remove from tailq of zones,
+ * unless there are 1 or more procs still running in it
+ */
+int
+sys_zone_destroy(struct proc *p, void *v, register_t *retval)
+{
+	zoneid_t arg;
+	int found;
+	struct entry *np;
+	struct sys_zone_destroy_args /* {
+		syscallarg(zoneid_t)z;
+	} */	*uap = v;
+
+	if (suser(p) || (p->p_p->zone != GLOBAL)) {
+	/* zones can only be destroyed by root in global zone */
+		*retval = -1;
+		return EPERM;
+	}
+	arg = SCARG(uap, z);
+
+	if (arg == GLOBAL) {
+		/* global zone can't be deleted */
+		*retval = -1;
+		return EBUSY;
+	}
+	found = 0;
+
+	TAILQ_FOREACH(np, &zones, entries) {
+		if (np->id == arg) {
+			/* found zone to destroy, check if still in use */
+			if (!SLIST_EMPTY(&np->procs)) {
+				*retval = -1;
+				return EBUSY;
+			}
+#ifdef DEBUG
+			printf("destroying zone with id: %d\n", np->id);
+#endif
+			TAILQ_REMOVE(&zones, np, entries);
+			found = 1;
+			break;
+		}
+	}
+
+	if (!found) {
+		*retval = -1;
+		return ESRCH;
+	}
+	return(0);
+}
+
+/*
+ * Add new proc into a linked list which represents a zone's running procs.
+ */
+int
+zone_enter(pid_t pid, zoneid_t zone)
+{
+	struct entry *np;
+	struct proc_entry *new;
+        if ((new = malloc(sizeof(struct proc_entry), M_TEMP,
+	    M_WAITOK | M_CANFAIL | M_ZERO)) == NULL) {
+		printf("mallocing new zone failed\n");
+		return -1;
+	}
+	new->pid = pid;
+	if (pid == GLOBAL) {
+		/* Global implicitly exists and is the zone of all procs
+		 * that aren't in another zone. Nothing to be done */
+		return 0;
+	}
+	TAILQ_FOREACH(np, &zones, entries) {
+		if (np->id == zone) {
+#ifdef DEBUG
+			printf("adding pid: %d to zone: %d\n", new->pid, zone);
+#endif
+			SLIST_INSERT_HEAD(&np->procs, new, proc_entries);
+			return 0;
+		}
+	}
+	return ESRCH;
+}
+
+
+/*
+ * Called on sys_exit(), remove an element from a zone's list
+ */
+int
+zone_exit(pid_t pid, zoneid_t zone)
+{
+	struct entry *np;
+	if (zone == GLOBAL) {
+		return 0;
+	}
+	TAILQ_FOREACH(np, &zones, entries) {
+		if (np->id == zone) {
+#ifdef DEBUG
+			printf("removing from np->id%d\n", np->id);
+#endif
+			if (SLIST_EMPTY(&np->procs))
+				return 0;
+			SLIST_REMOVE_HEAD(&np->procs, proc_entries);
+			return 0;
+		}
+	}
+	return ESRCH;
+}
+
+/*
+ * Syscall for a when a process starts running in a particular zone
+ */
+int
+sys_zone_enter(struct proc *p, void *v, register_t *retval)
+{
+	zoneid_t zone;
+	struct entry *np;
+	struct proc_entry *new;
+	struct sys_zone_enter_args /* {
+		syscallarg(zoneid_t)	z;
+	} */ 	*uap = v;
+	if (suser(p) || (p->p_p->zone != GLOBAL)) {
+		/* zone can only be entered if root and from global */
+		*retval = -1;
+		return EPERM;
+	}
+	zone = SCARG(uap, z);
+        if ((new = malloc(sizeof(struct proc_entry), M_TEMP,
+	    M_WAITOK | M_CANFAIL | M_ZERO)) == NULL) {
+		printf("mallocing new zone failed\n");
+		return -1;
+	}
+	new->pid = p->p_p->ps_pid;
+	p->p_p->zone = zone;
+
+	TAILQ_FOREACH(np, &zones, entries) {
+		if (np->id == zone) {
+			/* Add new proc to list of zone's running procs */
+			SLIST_INSERT_HEAD(&np->procs, new, proc_entries);
+			*retval = 0;
+			return 0;
+		}
+	}
+	*retval = -1;
+	return ESRCH;
+}
+
+/*
+ * Provide a list of all zone IDs
+ */
+int
+sys_zone_list(struct proc *p, void *v, register_t *retval)
+{
+	struct sys_zone_list_args /* {
+		syscallarg(zoneid_t *)	zs;
+		syscallarg(size_t *)	nzs;
+	} */ 	*uap = v;
+	struct entry *np;
+	size_t *nzsInput = malloc(sizeof(size_t),
+	    M_TEMP, M_WAITOK | M_CANFAIL | M_ZERO);
+	size_t nzsOutput = 0;
+
+	/* grab size of zs */
+        if (copyin(SCARG(uap, nzs), nzsInput, sizeof(size_t)) == EFAULT) {
+		*retval = -1;
+		return EFAULT;
+	}
+
+	zoneid_t *zsOutput = malloc(sizeof(zoneid_t) * (*nzsInput),
+	    M_TEMP, M_WAITOK | M_CANFAIL | M_ZERO);
+
+	/* add global zone */
+	if (!p->p_p->zone) {
+		zsOutput[nzsOutput++] = 0;
+	}
+
+	TAILQ_FOREACH(np, &zones, entries) {
+		if (nzsOutput >= *nzsInput) {
+			/* number of actual zones is greater than zs */
+			*retval = -1;
+			return ERANGE;
+		}
+		if (np->id == p->p_p->zone && p->p_p->zone) {
+			/* In non-global zone, find relevant zone, add it,
+			 * then you're done. */
+			zsOutput[0] = np->id;
+			*retval = 0;
+			nzsOutput = 1;
+			goto copyNzs;
+		}
+		if (!p->p_p->zone) {
+			/* global zone means all zones are added */
+			zsOutput[nzsOutput] = np->id;
+			nzsOutput++;
+		}
+	}
+copyNzs:
+	if (copyout(zsOutput, SCARG(uap, zs), sizeof(zoneid_t) * nzsOutput)
+	    == EFAULT) {
+		*retval = -1;
+		return EFAULT;
+	}
+	if (copyout(&nzsOutput, SCARG(uap, nzs), sizeof(size_t))){
+		*retval = -1;
+		return EFAULT;
+	}
+	*retval = 0;
+	return(0);
+}
+
+/*
+ * Given a zone ID, find its name.
+ */
+int
+zone_name(zoneid_t z, char *name, size_t namelen)
+{
+	zoneid_t zoneID = z;
+	struct entry *np;
+	TAILQ_FOREACH(np, &zones, entries) {
+		if (np->id == zoneID) {
+			if (strlen(np->zone_name) > namelen) {
+#ifdef DNAME
+				printf("len of zone_name:%zu\n",
+				    strlen(np->zone_name));
+				printf("namelen:%zu\n", namelen);
+#endif
+				return ENAMETOOLONG;
+			}
+			strncpy(name, np->zone_name, namelen);
+			return 0;
+		}
+	}
+	return ESRCH;
+}
+
+/*
+ * Given a zone ID, find its name.
+ * Same as above, but a userland syscall.
+ */
+int
+sys_zone_name(struct proc *p, void *v, register_t *retval)
+{
+	int error;
+	zoneid_t zoneID;
+	size_t namelen;
+	struct entry *np;
+	struct sys_zone_name_args /* {
+		syscallarg(zoneid_t)	z;
+		syscallarg(char *)	name;
+		syscallarg(size_t) 	namelen;
+	} */	*uap = v;
+	zoneID = SCARG(uap, z);
+	namelen = SCARG(uap, namelen);
+
+	if (zoneID == -1)
+		zoneID = p->p_p->zone;
+
+	if (p->p_p->zone && zoneID != p->p_p->zone) {
+		*retval = -1; /* non-global zone can only call for itself */
+		return ESRCH;
+	}
+
+	if (!zoneID) {
+		/* global zone */
+		error = copyoutstr("global", SCARG(uap, name),
+		    strlen("global") + 1, NULL);
+		if (error) {
+			*retval = -1;
+			return error;
+		}
+		*retval = 0;
+		return 0;
+	}
+
+	TAILQ_FOREACH(np, &zones, entries) {
+		if (np->id == zoneID) {
+			if (strlen(np->zone_name) > namelen) {
+				*retval = -1;
+				return ENAMETOOLONG;
+			}
+			error = copyoutstr(np->zone_name, SCARG(uap, name),
+			    strlen(np->zone_name) + 1, NULL);
+			if (error) {
+				*retval = -1;
+				return error;
+			}
+			*retval = 0;
+			return 0;
+		}
+	}
+
+	/* if reached, zone wasn't found */
+	*retval = -1;
+	return ESRCH;
+}
+
+/*
+ * Given a zone name, return its ID.
+ */
+int
+sys_zone_lookup(struct proc *p, void *v, register_t *retval)
+{
+	int 	error;
+	char 	*name;
+	struct sys_zone_lookup_args /* {
+		syscallarg(const char *) name;
+	} */ 	*uap = v;
+	struct entry *np;
+
+	if (SCARG(uap, name) == NULL) {
+		/* if NULL, return this proc's zone */
+		*retval = p->p_p->zone;
+		return 0;
+	}
+
+	/* get zone name being searched for */
+	if ((name = malloc(sizeof(char) * MAXZONENAMELEN + 1,
+	    M_TEMP, M_WAITOK | M_CANFAIL | M_ZERO)) == NULL) {
+		printf("mallocing name failed in lookup\n");
+		return -1;
+	}
+       	error = copyinstr(SCARG(uap, name), (void *)name,
+	    MAXZONENAMELEN + 1, NULL);
+	if (error ==  ENAMETOOLONG) {
+		*retval = -1;
+		return ENAMETOOLONG;
+	} else if (error == EFAULT) {
+		*retval = -1;
+		return EFAULT;
+	}
+	if (!strcmp(name, "global")) {
+		/* global not in linked list, but implicitly is ID 0 */
+		*retval = GLOBAL;
+		return 0;
+	}
+
+	TAILQ_FOREACH(np, &zones, entries) {
+		if (!strcmp(np->zone_name, name)) {
+			if (p->p_p->zone && np->id != p->p_p->zone)
+				break; /* not visible in non-global zone */
+			*retval = np->id;
+			return 0;
+		}
+	}
+	*retval = -1;
+	return(ESRCH);
+}
+
+/*
+ * Used in sysctl for changing a zone's hostid.
+ */
+void
+change_hostid(zoneid_t zone, int hostid)
+{
+	struct entry *np;
+	if (!zone) {
+		globalHost = hostid;
+		return;
+	}
+
+	TAILQ_FOREACH(np, &zones, entries) {
+		if (np->id == zone) {
+			np->hostid = hostid;
+		}
+	}
+}
+
+/*
+ * Used in sysctl for retrieving a zone's hostid.
+ */
+int
+get_hostid(zoneid_t zone)
+{
+	struct entry *np;
+	if (!zone)
+		return globalHost;
+	TAILQ_FOREACH(np, &zones, entries) {
+		if (np->id == zone) {
+			return np->hostid;
+		}
+	}
+	return 0;
+}
