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
package com.intel.chimera.random;

import java.io.Closeable;

/**
 * The interface for SecureRandom.
 */
public interface SecureRandom extends Closeable {

  /**
   * Generates random bytes and places them into a user-supplied
   * byte array.  The number of random bytes produced is equal to
   * the length of the byte array.
   * @param bytes the byte array to fill with random bytes
   */
  public void nextBytes(byte[] bytes);

  /**
   * Returns the next pseudorandom, uniformly distributed {@code int}
   * value from this random number generator's sequence. The general
   * contract of {@code nextInt} is that one {@code int} value is
   * pseudorandomly generated and returned. All 2<font size="-1"><sup>32
   * </sup></font> possible {@code int} values are produced with
   * (approximately) equal probability.
   *
   * <p>The method {@code nextInt} is implemented by class {@code Random}
   * as if by:
   *  <pre> {@code
   * public int nextInt() {
   *   return next(32);
   * }}</pre>
   *
   * @return the next pseudorandom, uniformly distributed {@code int}
   *         value from this random number generator's sequence
   */
  public int nextInt();

  /**
   * Returns the next pseudorandom, uniformly distributed {@code long}
   * value from this random number generator's sequence. The general
   * contract of {@code nextLong} is that one {@code long} value is
   * pseudorandomly generated and returned.
   *
   * <p>The method {@code nextLong} is implemented by class {@code Random}
   * as if by:
   *  <pre> {@code
   * public long nextLong() {
   *   return ((long)next(32) << 32) + next(32);
   * }}</pre>
   *
   * Because class {@code Random} uses a seed with only 48 bits,
   * this algorithm will not return all possible {@code long} values.
   *
   * @return the next pseudorandom, uniformly distributed {@code long}
   *         value from this random number generator's sequence
   */
  public long nextLong();

  /**
   * Returns the next pseudorandom, uniformly distributed {@code float}
   * value between {@code 0.0} and {@code 1.0} from this random
   * number generator's sequence.
   *
   * <p>The general contract of {@code nextFloat} is that one
   * {@code float} value, chosen (approximately) uniformly from the
   * range {@code 0.0f} (inclusive) to {@code 1.0f} (exclusive), is
   * pseudorandomly generated and returned. All 2<font
   * size="-1"><sup>24</sup></font> possible {@code float} values
   * of the form <i>m&nbsp;x&nbsp</i>2<font
   * size="-1"><sup>-24</sup></font>, where <i>m</i> is a positive
   * integer less than 2<font size="-1"><sup>24</sup> </font>, are
   * produced with (approximately) equal probability.
   *
   * <p>The method {@code nextFloat} is implemented by class {@code Random}
   * as if by:
   *  <pre> {@code
   * public float nextFloat() {
   *   return next(24) / ((float)(1 << 24));
   * }}</pre>
   *
   * <p>The hedge "approximately" is used in the foregoing description only
   * because the next method is only approximately an unbiased source of
   * independently chosen bits. If it were a perfect source of randomly
   * chosen bits, then the algorithm shown would choose {@code float}
   * values from the stated range with perfect uniformity.<p>
   * [In early versions of Java, the result was incorrectly calculated as:
   *  <pre> {@code
   *   return next(30) / ((float)(1 << 30));}</pre>
   * This might seem to be equivalent, if not better, but in fact it
   * introduced a slight nonuniformity because of the bias in the rounding
   * of floating-point numbers: it was slightly more likely that the
   * low-order bit of the significand would be 0 than that it would be 1.]
   *
   * @return the next pseudorandom, uniformly distributed {@code float}
   *         value between {@code 0.0} and {@code 1.0} from this
   *         random number generator's sequence
   */
  public float nextFloat();
  /**
   * Returns the next pseudorandom, uniformly distributed
   * {@code double} value between {@code 0.0} and
   * {@code 1.0} from this random number generator's sequence.
   *
   * <p>The general contract of {@code nextDouble} is that one
   * {@code double} value, chosen (approximately) uniformly from the
   * range {@code 0.0d} (inclusive) to {@code 1.0d} (exclusive), is
   * pseudorandomly generated and returned.
   *
   * <p>The method {@code nextDouble} is implemented by class {@code Random}
   * as if by:
   *  <pre> {@code
   * public double nextDouble() {
   *   return (((long)next(26) << 27) + next(27))
   *     / (double)(1L << 53);
   * }}</pre>
   *
   * <p>The hedge "approximately" is used in the foregoing description only
   * because the {@code next} method is only approximately an unbiased
   * source of independently chosen bits. If it were a perfect source of
   * randomly chosen bits, then the algorithm shown would choose
   * {@code double} values from the stated range with perfect uniformity.
   * <p>[In early versions of Java, the result was incorrectly calculated as:
   *  <pre> {@code
   *   return (((long)next(27) << 27) + next(27))
   *     / (double)(1L << 54);}</pre>
   * This might seem to be equivalent, if not better, but in fact it
   * introduced a large nonuniformity because of the bias in the rounding
   * of floating-point numbers: it was three times as likely that the
   * low-order bit of the significand would be 0 than that it would be 1!
   * This nonuniformity probably doesn't matter much in practice, but we
   * strive for perfection.]
   *
   * @return the next pseudorandom, uniformly distributed {@code double}
   *         value between {@code 0.0} and {@code 1.0} from this
   *         random number generator's sequence
   * @see Math#random
   */
  public double nextDouble();
  /**
   * Closes the SecureRandom
   */
  public void close();
}
