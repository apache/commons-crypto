/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.commons.crypto.utils;

import java.lang.ref.WeakReference;
import java.lang.reflect.Constructor;
import java.util.Collections;
import java.util.Map;
import java.util.WeakHashMap;

import org.apache.commons.crypto.cipher.CryptoCipher;

/**
 * General utility methods for working with reflection.
 */
public final class ReflectionUtils {

    private static final Map<ClassLoader, Map<String, WeakReference<Class<?>>>> CACHE_CLASSES = new WeakHashMap<>();

    private static final ClassLoader CLASSLOADER;

    static {
        final ClassLoader threadClassLoader = Thread.currentThread()
                .getContextClassLoader();
        CLASSLOADER = (threadClassLoader != null) ? threadClassLoader
                : CryptoCipher.class.getClassLoader();
    }

    /**
     * Sentinel value to store negative cache results in {@link #CACHE_CLASSES}.
     */
    private static final Class<?> NEGATIVE_CACHE_SENTINEL = NegativeCacheSentinel.class;

    /**
     * The private constructor of {@link ReflectionUtils}.
     */
    private ReflectionUtils() {
    }

    /**
     * A unique class which is used as a sentinel value in the caching for
     * getClassByName. {@link #getClassByNameOrNull(String)}.
     */
    private static abstract class NegativeCacheSentinel {
    }

    /**
     * Uses the constructor represented by this {@code Constructor} object to
     * create and initialize a new instance of the constructor's declaring
     * class, with the specified initialization parameters.
     *
     * @param <T> type for the new instance
     * @param klass the Class object.
     * @param args array of objects to be passed as arguments to the constructor
     *        call.
     * @return a new object created by calling the constructor this object
     *         represents.
     */
    public static <T> T newInstance(final Class<T> klass, final Object... args) {
        try {
            Constructor<T> ctor;

            if (args.length == 0) {
                ctor = klass.getDeclaredConstructor();
            } else {
                final Class<?>[] argClses = new Class[args.length];
                for (int i = 0; i < args.length; i++) {
                    argClses[i] = args[i].getClass();
                }
                ctor = klass.getDeclaredConstructor(argClses);
            }
            ctor.setAccessible(true);
            return ctor.newInstance(args);
        } catch (final Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Loads a class by name.
     *
     * @param name the class name.
     * @return the class object.
     * @throws ClassNotFoundException if the class is not found.
     */
    public static Class<?> getClassByName(final String name)
            throws ClassNotFoundException {
        final Class<?> ret = getClassByNameOrNull(name);
        if (ret == null) {
            throw new ClassNotFoundException("Class " + name + " not found");
        }
        return ret;
    }

    /**
     * Loads a class by name, returning null rather than throwing an exception
     * if it couldn't be loaded. This is to avoid the overhead of creating an
     * exception.
     *
     * @param name the class name.
     * @return the class object, or null if it could not be found.
     */
    private static Class<?> getClassByNameOrNull(final String name) {
        Map<String, WeakReference<Class<?>>> map;

        synchronized (CACHE_CLASSES) {
            map = CACHE_CLASSES.get(CLASSLOADER);
            if (map == null) {
                map = Collections
                        .synchronizedMap(new WeakHashMap<String, WeakReference<Class<?>>>());
                CACHE_CLASSES.put(CLASSLOADER, map);
            }
        }

        Class<?> clazz = null;
        final WeakReference<Class<?>> ref = map.get(name);
        if (ref != null) {
            clazz = ref.get();
        }

        if (clazz == null) {
            try {
                clazz = Class.forName(name, true, CLASSLOADER);
            } catch (final ClassNotFoundException e) {
                // Leave a marker that the class isn't found
                map.put(name, new WeakReference<Class<?>>(
                        NEGATIVE_CACHE_SENTINEL));
                return null;
            }
            // two putters can race here, but they'll put the same class
            map.put(name, new WeakReference<Class<?>>(clazz));
            return clazz;
        } else if (clazz == NEGATIVE_CACHE_SENTINEL) {
            return null; // not found
        } else {
            // cache hit
            return clazz;
        }
    }
}
