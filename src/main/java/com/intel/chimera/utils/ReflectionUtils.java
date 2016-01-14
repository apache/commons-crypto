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
package com.intel.chimera.utils;

import java.lang.ref.WeakReference;
import java.lang.reflect.Constructor;
import java.util.Collections;
import java.util.Map;
import java.util.WeakHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.intel.chimera.crypto.Cipher;

public class ReflectionUtils {

  private static final Map<ClassLoader, Map<String, WeakReference<Class<?>>>>
    CACHE_CLASSES = new WeakHashMap<ClassLoader, Map<String, WeakReference<Class<?>>>>();

  private static ClassLoader classLoader;
  static {
    classLoader = Thread.currentThread().getContextClassLoader();
    if (classLoader == null) {
      classLoader = Cipher.class.getClassLoader();
    }
  }

  /**
   * Sentinel value to store negative cache results in {@link #CACHE_CLASSES}.
   */
  private static final Class<?> NEGATIVE_CACHE_SENTINEL =
    NegativeCacheSentinel.class;

  /**
   * A unique class which is used as a sentinel value in the caching
   * for getClassByName. {@link Cipher#getClassByNameOrNull(String)}
   */
  private static abstract class NegativeCacheSentinel {}

  @SuppressWarnings("rawtypes")
  public static <T> T newInstance(Class<T> klass, Object ... args) {
    try {
      Constructor<T> ctor = null;

      if (args.length == 0) {
        ctor = klass.getDeclaredConstructor(new Class[] {});
      } else {
        Class[] argClses = new Class[args.length];
        for (int i = 0; i < args.length; i++) {
          argClses[i] = args[i].getClass();
        }
        ctor = klass.getDeclaredConstructor(argClses);
      }
      ctor.setAccessible(true);
      return ctor.newInstance(args);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  /** 
   * Get the value of the <code>name</code> property as a <code>Class</code>
   * implementing the interface specified by <code>xface</code>.
   *   
   * If no such property is specified, then <code>defaultValue</code> is 
   * returned.
   * 
   * An exception is thrown if the returned class does not implement the named
   * interface. 
   * 
   * @param name the class name.
   * @param defaultValue default value.
   * @param xface the interface implemented by the named class.
   * @return property value as a <code>Class</code>, 
   *         or <code>defaultValue</code>.
   */
  public static <U> Class<? extends U> getClass(String name, 
                                         Class<? extends U> defaultValue, 
                                         Class<U> xface) {
    try {
      Class<?> theClass = null;
      if (name != null && !name.isEmpty()) {
        theClass = getClassByName(name);
      }
      if (theClass == null) {
        theClass = defaultValue;
      }
      if (theClass != null && !xface.isAssignableFrom(theClass))
        throw new RuntimeException(theClass+" not "+xface.getName());
      else if (theClass != null)
        return theClass.asSubclass(xface);
      else
        return null;
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  /** 
   * Get the value of the <code>name</code> property as a <code>Class</code>.  
   * If no such property is specified, then <code>defaultValue</code> is 
   * returned.
   * 
   * @param name the class name.
   * @param defaultValue default value.
   * @return property value as a <code>Class</code>, 
   *         or <code>defaultValue</code>. 
   */
  public static Class<?> getClass(String name, Class<?> defaultValue) {
    String valueString = System.getProperty(name);
    if (valueString == null)
      return defaultValue;
    try {
      return getClassByName(valueString);
    } catch (ClassNotFoundException e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * Load a class by name.
   * 
   * @param name the class name.
   * @return the class object.
   * @throws ClassNotFoundException if the class is not found.
   */
  public static Class<?> getClassByName(String name)
      throws ClassNotFoundException {
    Class<?> ret = getClassByNameOrNull(name);
    if (ret == null) {
      throw new ClassNotFoundException("Class " + name + " not found");
    }
    return ret;
  }
  
  /**
   * Load a class by name, returning null rather than throwing an exception
   * if it couldn't be loaded. This is to avoid the overhead of creating
   * an exception.
   * 
   * @param name the class name
   * @return the class object, or null if it could not be found.
   */
  private static Class<?> getClassByNameOrNull(String name) {
    Map<String, WeakReference<Class<?>>> map;

    synchronized (CACHE_CLASSES) {
      map = CACHE_CLASSES.get(classLoader);
      if (map == null) {
        map = Collections.synchronizedMap(
          new WeakHashMap<String, WeakReference<Class<?>>>());
        CACHE_CLASSES.put(classLoader, map);
      }
    }

    Class<?> clazz = null;
    WeakReference<Class<?>> ref = map.get(name); 
    if (ref != null) {
       clazz = ref.get();
    }
     
    if (clazz == null) {
      try {
        clazz = Class.forName(name, true, classLoader);
      } catch (ClassNotFoundException e) {
        // Leave a marker that the class isn't found
        map.put(name, new WeakReference<Class<?>>(NEGATIVE_CACHE_SENTINEL));
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
