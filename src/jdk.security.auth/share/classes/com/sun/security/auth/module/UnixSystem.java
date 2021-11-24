/*
 * Copyright (c) 2000, 2021, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package com.sun.security.auth.module;

import com.sun.security.auth.module.unix.pwd.passwd;
import jdk.incubator.foreign.CLinker;
import jdk.incubator.foreign.FunctionDescriptor;
import jdk.incubator.foreign.MemoryAddress;
import jdk.incubator.foreign.MemoryLayout;
import jdk.incubator.foreign.MemorySegment;
import jdk.incubator.foreign.ResourceScope;
import jdk.incubator.foreign.SegmentAllocator;
import jdk.incubator.foreign.ValueLayout;

import java.util.Arrays;

import static com.sun.security.auth.module.unix.pwd.pwd_h.getpwuid_r;
import static com.sun.security.auth.module.unix.unistd.unistd_h.*;
import static jdk.incubator.foreign.MemoryAddress.NULL;
import static jdk.incubator.foreign.ValueLayout.*;

/**
 * This class implementation retrieves and makes available Unix
 * UID/GID/groups information for the current user.
 */
public class UnixSystem {

    private void getUnixInfo() {
        try {
            getuid$MH();
        } catch (NullPointerException npe) {
            throw new UnsatisfiedLinkError();
        }
        try (ResourceScope scope = ResourceScope.newConfinedScope()) {
            var allocator = SegmentAllocator.nativeAllocator(scope);
            int groupnum = getgroups(0, NULL);
            var gs = allocator.allocateArray(JAVA_INT, groupnum);
            getgroups(groupnum, gs);

            groups = new long[groupnum];
            for (int i = 0; i < groupnum; i++) {
                groups[i] = gs.getAtIndex(JAVA_INT, i);
            }

            var pwd = passwd.allocate(scope);
            var res = allocator.allocate(ADDRESS);
            int uidHere = getuid();
            int out = getpwuid_r(uidHere, pwd, allocator.allocate(1024), 1024, res);
            if (out == 0 && res.get(C_LONG, 0) != 0) {
                var rr = passwd.ofAddress(res.get(ADDRESS, 0), scope);
                uid = passwd.pw_uid$get(rr);
                gid = passwd.pw_gid$get(rr);
                username = passwd.pw_name$get(rr).getUtf8String(0);
            } else {
                uid = uidHere;
                gid = getgid();
            }
        } catch (Throwable t) {
            uid = gid = 0;
            groups = null;
            username = null;
        }
    }

    // Warning: the following 4 fields are used by Unix.c

    /** The current username. */
    protected String username;

    /** The current user ID. */
    protected long uid;

    /** The current group ID. */
    protected long gid;

    /** The current list of groups. */
    protected long[] groups;

    /**
     * Instantiate a {@code UnixSystem} and access the underlying
     * system information.
     */
    public UnixSystem() {
        getUnixInfo();
    }

    /**
     * Get the username for the current Unix user.
     *
     * @return the username for the current Unix user.
     */
    public String getUsername() {
        return username;
    }

    /**
     * Get the UID for the current Unix user.
     *
     * @return the UID for the current Unix user.
     */
    public long getUid() {
        return uid;
    }

    /**
     * Get the GID for the current Unix user.
     *
     * @return the GID for the current Unix user.
     */
    public long getGid() {
        return gid;
    }

    /**
     * Get the supplementary groups for the current Unix user.
     *
     * @return the supplementary groups for the current Unix user.
     */
    public long[] getGroups() {
        return groups == null ? null : groups.clone();
    }
}
