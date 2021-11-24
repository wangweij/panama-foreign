/*
 * Copyright (c) 2000, 2019, Oracle and/or its affiliates. All rights reserved.
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

import com.sun.security.auth.module.windows.SID_AND_ATTRIBUTES;
import com.sun.security.auth.module.windows.TOKEN_GROUPS;
import jdk.incubator.foreign.MemoryAddress;
import jdk.incubator.foreign.MemoryLayout;
import jdk.incubator.foreign.MemorySegment;
import jdk.incubator.foreign.ResourceScope;
import jdk.incubator.foreign.SegmentAllocator;

import java.util.Arrays;

import static com.sun.security.auth.module.windows.windows_h.*;
import static jdk.incubator.foreign.MemoryAddress.NULL;
import static jdk.incubator.foreign.ValueLayout.*;

/**
 * This class implementation retrieves and makes available NT
 * security information for the current user.
 *
 */
public class NTSystem {

    private void getCurrent(boolean debug) {
        System.loadLibrary("Kernel32");
        System.loadLibrary("Advapi32");
        try (ResourceScope scope = ResourceScope.newConfinedScope()) {
            var allocator = SegmentAllocator.nativeAllocator(scope);

            var currentThread = GetCurrentThread();
            var pHandle = allocator.allocate(ADDRESS);
            var out = OpenThreadToken(currentThread, TOKEN_READ(), 1, pHandle);
            if (out == 0) {
                var currentProcess = GetCurrentProcess();
                out = OpenProcessToken(currentProcess, TOKEN_READ(), pHandle);
            }

            if (out == 0) {
                return;
            }

            var handle = pHandle.get(ADDRESS, 0);

            var outLen = allocator.allocate(JAVA_INT);
            GetTokenInformation(handle, TokenUser(), NULL, 0, outLen);
            var len = outLen.get(JAVA_INT, 0);
            var userInfo = allocator.allocate(len);
            GetTokenInformation(handle, TokenUser(), userInfo, len, outLen);
            var usersid = userInfo.get(ADDRESS, 0);

            var name = allocator.allocate(1024);
            var domain = allocator.allocate(1024);
            var nameUse = allocator.allocate(4);
            out = LookupAccountSidA(NULL, usersid,
                    name, allocator.allocate(JAVA_INT, 1024),
                    domain, allocator.allocate(JAVA_INT, 1024),
                    nameUse);
            if (out == 0) {
                return;
            }

            var pdsid = allocator.allocate(24);
            var dsn = allocator.allocate(4);
            var l1 = allocator.allocate(JAVA_INT, 24);
            var l2 = allocator.allocate(JAVA_INT, 4);
            out = LookupAccountNameA(NULL, domain, pdsid, l1, dsn, l2, nameUse);
            if (out == 0) {
                return;
            }
            var domainsid = pdsid.address();

            GetTokenInformation(handle, TokenPrimaryGroup(), NULL, 0, outLen);
            len = outLen.get(JAVA_INT, 0);
            var tokenGroupInfo = allocator.allocate(len);
            out = GetTokenInformation(handle, TokenPrimaryGroup(), tokenGroupInfo, len, outLen);
            if (out == 0) {
                return;
            }
            var primegroupsid = tokenGroupInfo.get(ADDRESS, 0);

            GetTokenInformation(handle, TokenGroups(), NULL, 0, outLen);
            len = outLen.get(JAVA_INT, 0);
            var groupsInfo = allocator.allocate(len);
            out = GetTokenInformation(handle, TokenGroups(), groupsInfo, len, outLen);
            if (out == 0) {
                System.out.println("GetTokenInformation 2 failed");
                return;
            }
            var count = TOKEN_GROUPS.GroupCount$get(groupsInfo);
            var groupsLayout = MemoryLayout.sequenceLayout(count, SID_AND_ATTRIBUTES.$LAYOUT());
            var groups = MemorySegment.ofAddressNative(TOKEN_GROUPS.Groups$slice(groupsInfo).address(),
//                    groupsLayout.byteSize(),
                    SID_AND_ATTRIBUTES.sizeof() * count,
                    scope);
            for (int i = 0; i < count; i++) {
                System.out.println(i + ": " + getTextSid(scope, SID_AND_ATTRIBUTES.Sid$get(groups, i)));
            }

            this.userName = name.getUtf8String(0);
            this.userSID = getTextSid(scope, usersid);
            this.domain = domain.getUtf8String(0);
            this.domainSID = getTextSid(scope, domainsid);
            this.primaryGroupID = getTextSid(scope, primegroupsid);

            String[] tmp = new String[count];
            int pos = 0;
            for (int i = 0; i < count; i++) {
                String g = getTextSid(scope, SID_AND_ATTRIBUTES.Sid$get(groups, i));
                if (g.equals(this.primaryGroupID)) {
                    continue;
                }
                tmp[pos++] = g;
            }
            if (pos != count) {
                this.groupIDs = Arrays.copyOf(tmp, pos);
            } else {
                this.groupIDs = tmp;
            }

            CloseHandle(handle);
        }  catch (Throwable t) {
            t.printStackTrace();
        }
    }

    private static void dump(byte[] data) {
        int len = data.length;
        for (int i = 0; i < len; i++) {
            System.out.printf("%02X ", data[i] & 0xff);
            if (i % 16 == 15) System.out.println();
        }
        System.out.println();
    }

    private static String getTextSid(ResourceScope scope, MemoryAddress sid) {
        String textSid;
        var sia = MemorySegment.ofAddressNative(GetSidIdentifierAuthority(sid), 6, scope);
        var subCC = GetSidSubAuthorityCount(sid).get(JAVA_INT, 0);
        StringBuilder sb = new StringBuilder("S-1-");
        sb.append(sia.get(JAVA_BYTE, 5) & 0xff
                + ((sia.get(JAVA_BYTE, 4) & 0xff) << 8)
                + ((sia.get(JAVA_BYTE, 3) & 0xff) << 16)
                + ((sia.get(JAVA_BYTE, 2) & 0xff) << 24));
        for (int i = 0; i < subCC; i++) {
            sb.append('-').append(Integer.toUnsignedLong((GetSidSubAuthority(sid, i)).get(JAVA_INT, 0)));
        }
        textSid = sb.toString();
        return textSid;
    }

    private long getImpersonationToken0() {
        try (ResourceScope scope = ResourceScope.newConfinedScope()) {
            var allocator = SegmentAllocator.nativeAllocator(scope);
            var dupToken = allocator.allocate(ADDRESS);
            if (OpenThreadToken(GetCurrentThread(), TOKEN_DUPLICATE(), 0, dupToken) == 0) {
                if (OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE(), dupToken) == 0) {
                    return 0;
                }
            }
            var impToken = allocator.allocate(ADDRESS);
            if (DuplicateToken(dupToken.get(ADDRESS, 0), SecurityImpersonation(), impToken) == 0) {
                return 0;
            }
            CloseHandle(dupToken);
            return impToken.get(JAVA_LONG, 0);
        }
    }

    // Warning: the next 6 fields are used by nt.c
    private String userName;
    private String domain;
    private String domainSID;
    private String userSID;
    private String[] groupIDs;
    private String primaryGroupID;

    private long   impersonationToken;

    /**
     * Instantiate an {@code NTSystem} and load
     * the native library to access the underlying system information.
     */
    public NTSystem() {
        this(false);
    }

    /**
     * Instantiate an {@code NTSystem} and load
     * the native library to access the underlying system information.
     */
    NTSystem(boolean debug) {
        loadNative();
        getCurrent(debug);
    }

    /**
     * Get the username for the current NT user.
     *
     * @return the username for the current NT user.
     */
    public String getName() {
        return userName;
    }

    /**
     * Get the domain for the current NT user.
     *
     * @return the domain for the current NT user.
     */
    public String getDomain() {
        return domain;
    }

    /**
     * Get a printable SID for the current NT user's domain.
     *
     * @return a printable SID for the current NT user's domain.
     */
    public String getDomainSID() {
        return domainSID;
    }

    /**
     * Get a printable SID for the current NT user.
     *
     * @return a printable SID for the current NT user.
     */
    public String getUserSID() {
        return userSID;
    }

    /**
     * Get a printable primary group SID for the current NT user.
     *
     * @return the primary group SID for the current NT user.
     */
    public String getPrimaryGroupID() {
        return primaryGroupID;
    }

    /**
     * Get the printable group SIDs for the current NT user.
     *
     * @return the group SIDs for the current NT user.
     */
    public String[] getGroupIDs() {
        return groupIDs == null ? null : groupIDs.clone();
    }

    /**
     * Get an impersonation token for the current NT user.
     *
     * @return an impersonation token for the current NT user.
     */
    public synchronized long getImpersonationToken() {
        if (impersonationToken == 0) {
            impersonationToken = getImpersonationToken0();
        }
        return impersonationToken;
    }


    private void loadNative() {
        System.loadLibrary("jaas");
    }
}
