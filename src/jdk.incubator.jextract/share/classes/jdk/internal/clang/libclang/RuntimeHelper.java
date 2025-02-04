/*
 *  Copyright (c) 2021, Oracle and/or its affiliates. All rights reserved.
 *  DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 *  This code is free software; you can redistribute it and/or modify it
 *  under the terms of the GNU General Public License version 2 only, as
 *  published by the Free Software Foundation.  Oracle designates this
 *  particular file as subject to the "Classpath" exception as provided
 *  by Oracle in the LICENSE file that accompanied this code.
 *
 *  This code is distributed in the hope that it will be useful, but WITHOUT
 *  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 *  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 *  version 2 for more details (a copy is included in the LICENSE file that
 *  accompanied this code).
 *
 *  You should have received a copy of the GNU General Public License version
 *  2 along with this work; if not, write to the Free Software Foundation,
 *  Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 *   Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 *  or visit www.oracle.com if you need additional information or have any
 *  questions.
 */

package jdk.internal.clang.libclang;
// Generated by jextract

import jdk.incubator.foreign.Addressable;
import jdk.incubator.foreign.CLinker;
import jdk.incubator.foreign.FunctionDescriptor;
import jdk.incubator.foreign.GroupLayout;
import jdk.incubator.foreign.NativeSymbol;
import jdk.incubator.foreign.SymbolLookup;
import jdk.incubator.foreign.MemoryAddress;
import jdk.incubator.foreign.MemoryLayout;
import jdk.incubator.foreign.MemorySegment;
import jdk.incubator.foreign.ResourceScope;
import jdk.incubator.foreign.SegmentAllocator;
import jdk.incubator.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.io.File;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Optional;
import java.util.stream.Stream;

import static jdk.incubator.foreign.CLinker.*;
import static jdk.incubator.foreign.ValueLayout.*;

final class RuntimeHelper {

    private RuntimeHelper() {}
    private final static CLinker LINKER = CLinker.systemCLinker();
    private final static ClassLoader LOADER = RuntimeHelper.class.getClassLoader();
    private final static MethodHandles.Lookup MH_LOOKUP = MethodHandles.lookup();
    private final static SymbolLookup SYMBOL_LOOKUP;

    final static SegmentAllocator CONSTANT_ALLOCATOR =
            (size, align) -> MemorySegment.allocateNative(size, align, ResourceScope.newImplicitScope());

    static {
        // Manual change to handle platform specific library name difference
        String libName = System.getProperty("os.name").startsWith("Windows")? "libclang" : "clang";
        System.loadLibrary(libName);

        SymbolLookup loaderLookup = SymbolLookup.loaderLookup();
        SYMBOL_LOOKUP = name -> loaderLookup.lookup(name).or(() -> LINKER.lookup(name));
    }

    static <T> T requireNonNull(T obj, String symbolName) {
        if (obj == null) {
            throw new UnsatisfiedLinkError("unresolved symbol: " + symbolName);
        }
        return obj;
    }

    private final static SegmentAllocator THROWING_ALLOCATOR = (x, y) -> { throw new AssertionError("should not reach here"); };

    static final MemorySegment lookupGlobalVariable(String name, MemoryLayout layout) {
        return SYMBOL_LOOKUP.lookup(name).map(symbol -> MemorySegment.ofAddressNative(symbol.address(), layout.byteSize(), ResourceScope.newSharedScope())).orElse(null);
    }

    static final MethodHandle downcallHandle(String name, FunctionDescriptor fdesc, boolean variadic) {
        return SYMBOL_LOOKUP.lookup(name).map(
                addr -> {
                    return variadic ?
                        VarargsInvoker.make(addr, fdesc) :
                        LINKER.downcallHandle(addr, fdesc);
                }).orElse(null);
    }

    static final MethodHandle downcallHandle(FunctionDescriptor fdesc, boolean variadic) {
        if (variadic) {
            throw new AssertionError("Cannot get here!");
        }
        return LINKER.downcallHandle(fdesc);
    }

    static final <Z> NativeSymbol upcallStub(Class<Z> fi, Z z, FunctionDescriptor fdesc, String mtypeDesc, ResourceScope scope) {
        try {
            MethodHandle handle = MH_LOOKUP.findVirtual(fi, "apply",
                    MethodType.fromMethodDescriptorString(mtypeDesc, LOADER));
            handle = handle.bindTo(z);
            return LINKER.upcallStub(handle, fdesc, scope);
        } catch (Throwable ex) {
            throw new AssertionError(ex);
        }
    }

    static MemorySegment asArray(MemoryAddress addr, MemoryLayout layout, int numElements, ResourceScope scope) {
         return MemorySegment.ofAddressNative(addr, numElements * layout.byteSize(), scope);
    }

    // Internals only below this point

    private static class VarargsInvoker {
        private static final MethodHandle INVOKE_MH;
        private final NativeSymbol symbol;
        private final FunctionDescriptor function;

        private VarargsInvoker(NativeSymbol symbol, FunctionDescriptor function) {
            this.symbol = symbol;
            this.function = function;
        }

        static {
            try {
                INVOKE_MH = MethodHandles.lookup().findVirtual(VarargsInvoker.class, "invoke", MethodType.methodType(Object.class, SegmentAllocator.class, Object[].class));
            } catch (ReflectiveOperationException e) {
                throw new RuntimeException(e);
            }
        }

        static MethodHandle make(NativeSymbol symbol, FunctionDescriptor function) {
            VarargsInvoker invoker = new VarargsInvoker(symbol, function);
            MethodHandle handle = INVOKE_MH.bindTo(invoker).asCollector(Object[].class, function.argumentLayouts().size() + 1);
            MethodType mtype = MethodType.methodType(function.returnLayout().isPresent() ? carrier(function.returnLayout().get(), true) : void.class);
            for (MemoryLayout layout : function.argumentLayouts()) {
                mtype = mtype.appendParameterTypes(carrier(layout, false));
            }
            mtype = mtype.appendParameterTypes(Object[].class);
            if (mtype.returnType().equals(MemorySegment.class)) {
                mtype = mtype.insertParameterTypes(0, SegmentAllocator.class);
            } else {
                handle = MethodHandles.insertArguments(handle, 0, THROWING_ALLOCATOR);
            }
            return handle.asType(mtype);
        }

        static Class<?> carrier(MemoryLayout layout, boolean ret) {
            if (layout instanceof ValueLayout valueLayout) {
                return (ret || valueLayout.carrier() != MemoryAddress.class) ?
                        valueLayout.carrier() : Addressable.class;
            } else if (layout instanceof GroupLayout) {
                return MemorySegment.class;
            } else {
                throw new AssertionError("Cannot get here!");
            }
        }

        private Object invoke(SegmentAllocator allocator, Object[] args) throws Throwable {
            // one trailing Object[]
            int nNamedArgs = function.argumentLayouts().size();
            assert(args.length == nNamedArgs + 1);
            // The last argument is the array of vararg collector
            Object[] unnamedArgs = (Object[]) args[args.length - 1];

            int argsCount = nNamedArgs + unnamedArgs.length;
            Class<?>[] argTypes = new Class<?>[argsCount];
            MemoryLayout[] argLayouts = new MemoryLayout[nNamedArgs + unnamedArgs.length];

            int pos = 0;
            for (pos = 0; pos < nNamedArgs; pos++) {
                argLayouts[pos] = function.argumentLayouts().get(pos);
            }

            assert pos == nNamedArgs;
            for (Object o: unnamedArgs) {
                argLayouts[pos] = variadicLayout(normalize(o.getClass()));
                pos++;
            }
            assert pos == argsCount;

            FunctionDescriptor f = (function.returnLayout().isEmpty()) ?
                    FunctionDescriptor.ofVoid(argLayouts) :
                    FunctionDescriptor.of(function.returnLayout().get(), argLayouts);
            MethodHandle mh = LINKER.downcallHandle(symbol, f);
            if (mh.type().returnType() == MemorySegment.class) {
                mh = mh.bindTo(allocator);
            }
            // flatten argument list so that it can be passed to an asSpreader MH
            Object[] allArgs = new Object[nNamedArgs + unnamedArgs.length];
            System.arraycopy(args, 0, allArgs, 0, nNamedArgs);
            System.arraycopy(unnamedArgs, 0, allArgs, nNamedArgs, unnamedArgs.length);

            return mh.asSpreader(Object[].class, argsCount).invoke(allArgs);
        }

        private static Class<?> unboxIfNeeded(Class<?> clazz) {
            if (clazz == Boolean.class) {
                return boolean.class;
            } else if (clazz == Void.class) {
                return void.class;
            } else if (clazz == Byte.class) {
                return byte.class;
            } else if (clazz == Character.class) {
                return char.class;
            } else if (clazz == Short.class) {
                return short.class;
            } else if (clazz == Integer.class) {
                return int.class;
            } else if (clazz == Long.class) {
                return long.class;
            } else if (clazz == Float.class) {
                return float.class;
            } else if (clazz == Double.class) {
                return double.class;
            } else {
                return clazz;
            }
        }

        private Class<?> promote(Class<?> c) {
            if (c == byte.class || c == char.class || c == short.class || c == int.class) {
                return long.class;
            } else if (c == float.class) {
                return double.class;
            } else {
                return c;
            }
        }

        private Class<?> normalize(Class<?> c) {
            c = unboxIfNeeded(c);
            if (c.isPrimitive()) {
                return promote(c);
            }
            if (MemoryAddress.class.isAssignableFrom(c)) {
                return MemoryAddress.class;
            }
            if (MemorySegment.class.isAssignableFrom(c)) {
                return MemorySegment.class;
            }
            throw new IllegalArgumentException("Invalid type for ABI: " + c.getTypeName());
        }

        private MemoryLayout variadicLayout(Class<?> c) {
            if (c == long.class) {
                return JAVA_LONG;
            } else if (c == double.class) {
                return JAVA_DOUBLE;
            } else if (MemoryAddress.class.isAssignableFrom(c)) {
                return ADDRESS;
            } else {
                throw new IllegalArgumentException("Unhandled variadic argument class: " + c);
            }
        }
    }
}
