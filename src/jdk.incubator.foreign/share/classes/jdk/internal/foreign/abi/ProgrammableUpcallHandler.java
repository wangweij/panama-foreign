/*
 * Copyright (c) 2020, Oracle and/or its affiliates. All rights reserved.
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

package jdk.internal.foreign.abi;

import jdk.incubator.foreign.MemoryHandles;
import jdk.incubator.foreign.MemoryLayout;
import jdk.incubator.foreign.MemorySegment;
import jdk.incubator.foreign.NativeSymbol;
import jdk.incubator.foreign.ResourceScope;
import jdk.incubator.foreign.ValueLayout;
import sun.security.action.GetPropertyAction;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Stream;

import static java.lang.invoke.MethodHandles.collectArguments;
import static java.lang.invoke.MethodHandles.dropArguments;
import static java.lang.invoke.MethodHandles.empty;
import static java.lang.invoke.MethodHandles.exactInvoker;
import static java.lang.invoke.MethodHandles.identity;
import static java.lang.invoke.MethodHandles.insertArguments;
import static java.lang.invoke.MethodHandles.lookup;
import static java.lang.invoke.MethodType.methodType;
import static jdk.internal.foreign.abi.SharedUtils.mergeArguments;
import static sun.security.action.GetBooleanAction.privilegedGetProperty;

public class ProgrammableUpcallHandler {
    private static final boolean DEBUG =
        privilegedGetProperty("jdk.internal.foreign.ProgrammableUpcallHandler.DEBUG");
    private static final boolean USE_SPEC = Boolean.parseBoolean(
        GetPropertyAction.privilegedGetProperty("jdk.internal.foreign.ProgrammableUpcallHandler.USE_SPEC", "true"));

    private static final MethodHandle MH_invokeInterpBindings;

    static {
        try {
            MethodHandles.Lookup lookup = lookup();
            MH_invokeInterpBindings = lookup.findStatic(ProgrammableUpcallHandler.class, "invokeInterpBindings",
                    methodType(Object.class, Object[].class, InvocationData.class));
        } catch (ReflectiveOperationException e) {
            throw new InternalError(e);
        }
    }

    public static NativeSymbol make(ABIDescriptor abi, MethodHandle target, CallingSequence callingSequence, ResourceScope scope) {
        Binding.VMLoad[] argMoves = argMoveBindings(callingSequence);
        Binding.VMStore[] retMoves = retMoveBindings(callingSequence);

        Class<?> llReturn = retMoves.length == 1 ? retMoves[0].type() : void.class;
        Class<?>[] llParams = Arrays.stream(argMoves).map(Binding.Move::type).toArray(Class<?>[]::new);
        MethodType llType = methodType(llReturn, llParams);

        MethodHandle doBindings;
        if (USE_SPEC) {
            doBindings = specializedBindingHandle(target, callingSequence, llReturn, abi);
            assert doBindings.type() == llType;
        } else {
            Map<VMStorage, Integer> argIndices = SharedUtils.indexMap(argMoves);
            Map<VMStorage, Integer> retIndices = SharedUtils.indexMap(retMoves);
            int spreaderCount = callingSequence.methodType().parameterCount();
            if (callingSequence.needsReturnBuffer()) {
                spreaderCount--; // return buffer is dropped from the argument list
            }
            target = target.asSpreader(Object[].class, spreaderCount);
            InvocationData invData = new InvocationData(target, argIndices, retIndices, callingSequence, retMoves, abi);
            doBindings = insertArguments(MH_invokeInterpBindings, 1, invData);
            doBindings = doBindings.asCollector(Object[].class, llType.parameterCount());
            doBindings = doBindings.asType(llType);
        }

        checkPrimitive(doBindings.type());
        doBindings = insertArguments(exactInvoker(doBindings.type()), 0, doBindings);
        VMStorage[] args = Arrays.stream(argMoves).map(Binding.Move::storage).toArray(VMStorage[]::new);
        VMStorage[] rets = Arrays.stream(retMoves).map(Binding.Move::storage).toArray(VMStorage[]::new);
        CallRegs conv = new CallRegs(args, rets);
        long entryPoint = allocateOptimizedUpcallStub(doBindings, abi, conv,
                callingSequence.needsReturnBuffer(), callingSequence.returnBufferSize());
        return UpcallStubs.makeUpcall(entryPoint, scope);
    }

    private static void checkPrimitive(MethodType type) {
        if (!type.returnType().isPrimitive()
                || type.parameterList().stream().anyMatch(p -> !p.isPrimitive()))
            throw new IllegalArgumentException("MethodHandle type must be primitive: " + type);
    }

    private static Stream<Binding.VMLoad> argMoveBindingsStream(CallingSequence callingSequence) {
        return callingSequence.argumentBindings()
                .filter(Binding.VMLoad.class::isInstance)
                .map(Binding.VMLoad.class::cast);
    }

    private static Binding.VMLoad[] argMoveBindings(CallingSequence callingSequence) {
        return argMoveBindingsStream(callingSequence)
                .toArray(Binding.VMLoad[]::new);
    }

    private static Binding.VMStore[] retMoveBindings(CallingSequence callingSequence) {
        return callingSequence.returnBindings().stream()
                .filter(Binding.VMStore.class::isInstance)
                .map(Binding.VMStore.class::cast)
                .toArray(Binding.VMStore[]::new);
    }

    private static MethodHandle specializedBindingHandle(MethodHandle target, CallingSequence callingSequence,
                                                         Class<?> llReturn, ABIDescriptor abi) {
        MethodType highLevelType = callingSequence.methodType();

        MethodHandle specializedHandle = target; // initial

        // we handle returns first since IMR adds an extra parameter that needs to be specialized as well
        if (llReturn != void.class || callingSequence.needsReturnBuffer()) {
            int retAllocatorPos = -1; // assumed not needed
            int retInsertPos;
            MethodHandle filter;
            if (callingSequence.needsReturnBuffer()) {
                retInsertPos = 1;
                filter = empty(methodType(void.class, MemorySegment.class));
            } else {
                retInsertPos = 0;
                filter = identity(llReturn);
            }
            long retBufWriteOffset = callingSequence.returnBufferSize();
            List<Binding> bindings = callingSequence.returnBindings();
            for (int j = bindings.size() - 1; j >= 0; j--) {
                Binding binding = bindings.get(j);
                if (callingSequence.needsReturnBuffer() && binding.tag() == Binding.Tag.VM_STORE) {
                    Binding.VMStore store = (Binding.VMStore) binding;
                    ValueLayout layout = MemoryLayout.valueLayout(store.type(), ByteOrder.nativeOrder()).withBitAlignment(8);
                    // since we iterate the bindings in reverse, we have to compute the offset in reverse as well
                    retBufWriteOffset -= abi.arch.typeSize(store.storage().type());
                    MethodHandle storeHandle = MemoryHandles.insertCoordinates(MemoryHandles.varHandle(layout), 1, retBufWriteOffset)
                            .toMethodHandle(VarHandle.AccessMode.SET);
                    filter = collectArguments(filter, retInsertPos, storeHandle);
                    filter = mergeArguments(filter, retInsertPos - 1, retInsertPos);
                } else {
                    filter = binding.specialize(filter, retInsertPos, retAllocatorPos);
                }
            }
            specializedHandle = collectArguments(filter, retInsertPos, specializedHandle);
        }

        int argAllocatorPos = 0;
        int argInsertPos = 1;
        specializedHandle = dropArguments(specializedHandle, argAllocatorPos, Binding.Context.class);
        for (int i = 0; i < highLevelType.parameterCount(); i++) {
            MethodHandle filter = identity(highLevelType.parameterType(i));
            int filterAllocatorPos = 0;
            int filterInsertPos = 1; // +1 for allocator
            filter = dropArguments(filter, filterAllocatorPos, Binding.Context.class);

            List<Binding> bindings = callingSequence.argumentBindings(i);
            for (int j = bindings.size() - 1; j >= 0; j--) {
                Binding binding = bindings.get(j);
                filter = binding.specialize(filter, filterInsertPos, filterAllocatorPos);
            }
            specializedHandle = MethodHandles.collectArguments(specializedHandle, argInsertPos, filter);
            specializedHandle = mergeArguments(specializedHandle, argAllocatorPos, argInsertPos + filterAllocatorPos);
            argInsertPos += filter.type().parameterCount() - 1; // -1 for allocator
        }

        specializedHandle = SharedUtils.wrapWithAllocator(specializedHandle, argAllocatorPos, callingSequence.allocationSize(), true);

        return specializedHandle;
    }

    private record InvocationData(MethodHandle leaf,
                                  Map<VMStorage, Integer> argIndexMap,
                                  Map<VMStorage, Integer> retIndexMap,
                                  CallingSequence callingSequence,
                                  Binding.VMStore[] retMoves,
                                  ABIDescriptor abi) {}

    private static Object invokeInterpBindings(Object[] lowLevelArgs, InvocationData invData) throws Throwable {
        Binding.Context allocator = invData.callingSequence.allocationSize() != 0
                ? Binding.Context.ofBoundedAllocator(invData.callingSequence.allocationSize())
                : Binding.Context.ofScope();
        try (allocator) {
            /// Invoke interpreter, got array of high-level arguments back
            Object[] highLevelArgs = new Object[invData.callingSequence.methodType().parameterCount()];
            for (int i = 0; i < highLevelArgs.length; i++) {
                highLevelArgs[i] = BindingInterpreter.box(invData.callingSequence.argumentBindings(i),
                        (storage, type) -> lowLevelArgs[invData.argIndexMap.get(storage)], allocator);
            }

            MemorySegment returnBuffer = null;
            if (invData.callingSequence.needsReturnBuffer()) {
                // this one is for us
                returnBuffer = (MemorySegment) highLevelArgs[0];
                Object[] newArgs = new Object[highLevelArgs.length - 1];
                System.arraycopy(highLevelArgs, 1, newArgs, 0, newArgs.length);
                highLevelArgs = newArgs;
            }

            if (DEBUG) {
                System.err.println("Java arguments:");
                System.err.println(Arrays.toString(highLevelArgs).indent(2));
            }

            // invoke our target
            Object o = invData.leaf.invoke(highLevelArgs);

            if (DEBUG) {
                System.err.println("Java return:");
                System.err.println(Objects.toString(o).indent(2));
            }

            Object[] returnValues = new Object[invData.retIndexMap.size()];
            if (invData.leaf.type().returnType() != void.class) {
                BindingInterpreter.unbox(o, invData.callingSequence.returnBindings(),
                        (storage, type, value) -> returnValues[invData.retIndexMap.get(storage)] = value, null);
            }

            if (returnValues.length == 0) {
                return null;
            } else if (returnValues.length == 1) {
                return returnValues[0];
            } else {
                assert invData.callingSequence.needsReturnBuffer();

                Binding.VMStore[] retMoves = invData.callingSequence.returnBindings().stream()
                        .filter(Binding.VMStore.class::isInstance)
                        .map(Binding.VMStore.class::cast)
                        .toArray(Binding.VMStore[]::new);

                assert returnValues.length == retMoves.length;
                int retBufWriteOffset = 0;
                for (int i = 0; i < retMoves.length; i++) {
                    Binding.VMStore store = retMoves[i];
                    Object value = returnValues[i];
                    SharedUtils.writeOverSized(returnBuffer.asSlice(retBufWriteOffset), store.type(), value);
                    retBufWriteOffset += invData.abi.arch.typeSize(store.storage().type());
                }
                return null;
            }
        } catch(Throwable t) {
            SharedUtils.handleUncaughtException(t);
            return null;
        }
    }

    // used for transporting data into native code
    private static record CallRegs(VMStorage[] argRegs, VMStorage[] retRegs) {}

    static native long allocateOptimizedUpcallStub(MethodHandle mh, ABIDescriptor abi, CallRegs conv,
                                                   boolean needsReturnBuffer, long returnBufferSize);

    private static native void registerNatives();
    static {
        registerNatives();
    }
}
