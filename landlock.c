/*
 * Setup a sandbox using the Landlock LSM, if available.

# Copyright (C) 2023  Yves Rutschle
# 
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License as published by the Free Software Foundation; either
# version 2 of the License, or (at your option) any later
# version.
# 
# This program is distributed in the hope that it will be
# useful, but WITHOUT ANY WARRANTY; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
# PURPOSE.  See the GNU General Public License for more
# details.
# 
# The full text for the General Public License is here:
# http://www.gnu.org/licenses/gpl.html
#
*/

#include "config.h"
#include "log.h"

#ifdef HAVE_LANDLOCK

#define _GNU_SOURCE
#include <linux/landlock.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

/* Ubuntu 22.04 does not have this symbol */
#ifndef LANDLOCK_ACCESS_FS_REFER
#define LANDLOCK_ACCESS_FS_REFER			(1ULL << 13)
#endif

#ifndef landlock_create_ruleset
static inline int
landlock_create_ruleset(const struct landlock_ruleset_attr *const attr,
			const size_t size, const __u32 flags)
{
	return syscall(__NR_landlock_create_ruleset, attr, size, flags);
}
#endif

#ifndef landlock_add_rule
static inline int landlock_add_rule(const int ruleset_fd,
				    const enum landlock_rule_type rule_type,
				    const void *const rule_attr,
				    const __u32 flags)
{
	return syscall(__NR_landlock_add_rule, ruleset_fd, rule_type, rule_attr,
		       flags);
}
#endif

#ifndef landlock_restrict_self
static inline int landlock_restrict_self(const int ruleset_fd,
					 const __u32 flags)
{
	return syscall(__NR_landlock_restrict_self, ruleset_fd, flags);
}
#endif

typedef enum {
    LL_TREE,
    LL_FILE
} ll_obj_type;

static int add_path_ro(int ruleset_fd, ll_obj_type otype, const char* path)
{
    int fd = open(path, O_PATH | O_CLOEXEC);
    if (fd < 0) {
        print_message(msg_config_error, "Landlock: Failed to open %s: %s\n", path, strerror(errno));
        return -1;
    }

    struct landlock_path_beneath_attr path_beneath = {
        .allowed_access = (otype == LL_TREE ? LANDLOCK_ACCESS_FS_READ_DIR : 0 ) |
                          LANDLOCK_ACCESS_FS_READ_FILE,
        .parent_fd = fd,
    };

    int res = landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &path_beneath, 0);
    if (res) {
        print_message(msg_config_error, "Landlock: Failed to update the ruleset with \"%s\": %s\n",
                path, strerror(errno));
        close(path_beneath.parent_fd);
        return -1;
    }

    // close helper handle
    close(fd);

    return 0;
}


static int add_libs(int ruleset_fd)
{
    /* Access to libraries, to be able to fork */
    add_path_ro(ruleset_fd, LL_TREE, "/lib");
    add_path_ro(ruleset_fd, LL_TREE, "/usr/lib");
    add_path_ro(ruleset_fd, LL_FILE, "/etc/ld.so.cache");  /* To avoid searching all libs... */
    return 0;
}

static int add_resolv(int ruleset_fd)
{
    /* Files to resolve names (required when dynamic resolution is used) */
    add_path_ro(ruleset_fd, LL_FILE, "/etc/hosts");
    add_path_ro(ruleset_fd, LL_FILE, "/etc/resolv.conf");
    add_path_ro(ruleset_fd, LL_FILE, "/etc/nsswitch.conf");
    return 0;
}

static int add_libwrap(int ruleset_fd)
{
    /* Files for libwrap */
#ifdef LIBWRAP
    add_path_ro(ruleset_fd, LL_FILE, "/etc/hosts.allow");
    add_path_ro(ruleset_fd, LL_FILE, "/etc/hosts.deny");
#endif

    return 0;
}



void setup_landlock(void)
{
    __u64 restrict_rules = 
        LANDLOCK_ACCESS_FS_EXECUTE |
        LANDLOCK_ACCESS_FS_READ_FILE |
        LANDLOCK_ACCESS_FS_READ_DIR |
        LANDLOCK_ACCESS_FS_WRITE_FILE |
        LANDLOCK_ACCESS_FS_REMOVE_DIR |
        LANDLOCK_ACCESS_FS_REMOVE_FILE |
        LANDLOCK_ACCESS_FS_MAKE_CHAR |
        LANDLOCK_ACCESS_FS_MAKE_DIR |
        LANDLOCK_ACCESS_FS_MAKE_REG |
        LANDLOCK_ACCESS_FS_MAKE_SOCK |
        LANDLOCK_ACCESS_FS_MAKE_FIFO |
        LANDLOCK_ACCESS_FS_MAKE_BLOCK |
        LANDLOCK_ACCESS_FS_MAKE_SYM |
        LANDLOCK_ACCESS_FS_REFER;

    struct landlock_ruleset_attr ruleset_attr = {
        .handled_access_fs = restrict_rules
    };

    /* ruleset_addr.handled_access_fs contains all rights that will be restricted
     * unless explicitly added */
    int ruleset_fd = landlock_create_ruleset(&ruleset_attr, sizeof(ruleset_attr), 0);
    if (ruleset_fd < 0) {
        print_message(msg_config_error, "Landlock: Failed to create a ruleset");
        return;
    }


    /* Add all the paths we need */
    add_libs(ruleset_fd);
    add_resolv(ruleset_fd);
    add_libwrap(ruleset_fd);

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        print_message(msg_config_error, "Landlock: Failed to restrict privileges");
        return;
    }
    if (landlock_restrict_self(ruleset_fd, 0)) {
        print_message(msg_config_error, "Landlock: Failed to enforce ruleset");
        return;
    }
    close(ruleset_fd);

    print_message(msg_config, "Landlock: all restricted\n");
}

#else /* HAVE_LANDLOCK */
void setup_landlock(void)
{
    print_message(msg_config, "Landlock: not built in\n");
    return;
}
#endif /* HAVE_LANDLOCK */
