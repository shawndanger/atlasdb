/*
 * (c) Copyright 2021 Palantir Technologies Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.palantir.atlasdb.atomic;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.palantir.atlasdb.encoding.PtBytes;
import com.palantir.atlasdb.keyvalue.api.Cell;
import com.palantir.atlasdb.keyvalue.api.CheckAndSetException;
import com.palantir.atlasdb.keyvalue.api.KeyAlreadyExistsException;
import java.util.Optional;
import java.util.concurrent.ExecutionException;
import org.junit.Test;

public class PueCassImitatingConsensusForgettingStoreTest {
    private static final Cell CELL = Cell.create(new byte[] {1}, new byte[] {0});
    private static final byte[] VALUE = PtBytes.toBytes("VAL");
    private static final byte[] VALUE_2 = PtBytes.toBytes("VAL2");
    // solution to (1-x)^4 = 0.5
    private static final double PROBABILITY_THROWING_ON_QUORUM_HALF = 0.16;

    private final ConsensusForgettingStore neverFailing = new PueCassImitatingConsensusForgettingStore(0.0);
    private final CassandraImitatingConsensusForgettingStore sometimesThrowing =
            new PueCassImitatingConsensusForgettingStore(PROBABILITY_THROWING_ON_QUORUM_HALF);

    @Test
    public void trivialGet() throws ExecutionException, InterruptedException {
        assertThat(neverFailing.get(CELL).get()).isEmpty();
    }

    @Test
    public void canGetAfterPue() throws ExecutionException, InterruptedException {
        AtomicUpdateResult atomicUpdateResult = neverFailing.atomicUpdate(CELL, VALUE);
        assertSuccessfulResponse(CELL, atomicUpdateResult);
        assertThat(neverFailing.get(CELL).get()).contains(VALUE);
    }

    @Test
    public void canGetAfterPut() throws ExecutionException, InterruptedException {
        neverFailing.put(CELL, VALUE);
        assertThat(neverFailing.get(CELL).get()).hasValue(VALUE);
    }

    @Test
    public void putOverwritesPue() throws ExecutionException, InterruptedException {
        AtomicUpdateResult atomicUpdateResult = neverFailing.atomicUpdate(CELL, VALUE);
        assertSuccessfulResponse(CELL, atomicUpdateResult);
        neverFailing.put(CELL, VALUE_2);
        assertThat(neverFailing.get(CELL).get()).hasValue(VALUE_2);
    }

    @Test
    public void cannotPueTwice() {
        assertSuccessfulResponse(CELL, neverFailing.atomicUpdate(CELL, VALUE));
        // second pue fails
        assertFailedRequest(CELL, neverFailing.atomicUpdate(CELL, VALUE));
    }

    private static void assertSuccessfulResponse(Cell cell, AtomicUpdateResult atomicUpdateResult) {
        assertThat(atomicUpdateResult.knownSuccessfullyCommittedKeys()).containsExactly(cell);
        assertThat(atomicUpdateResult.existingKeys()).isEmpty();
    }

    private static void assertFailedRequest(Cell cell, AtomicUpdateResult atomicUpdateResult) {
        assertThat(atomicUpdateResult.existingKeys()).containsExactly(cell);
        assertThat(atomicUpdateResult.knownSuccessfullyCommittedKeys()).isEmpty();
    }

    @Test
    public void canTouchAfterPue() throws ExecutionException, InterruptedException {
        assertSuccessfulResponse(CELL, neverFailing.atomicUpdate(CELL, VALUE));
        neverFailing.checkAndTouch(CELL, VALUE);
        assertThat(neverFailing.get(CELL).get()).hasValue(VALUE);
    }

    @Test
    public void cannotTouchWhenNotMatching() {
        assertThatThrownBy(() -> neverFailing.checkAndTouch(CELL, VALUE))
                .isInstanceOf(CheckAndSetException.class)
                .satisfies(exception -> assertThat(((CheckAndSetException) exception).getActualValues())
                        .isEmpty());

        assertSuccessfulResponse(CELL, neverFailing.atomicUpdate(CELL, VALUE));
        assertThatThrownBy(() -> neverFailing.checkAndTouch(CELL, VALUE_2))
                .isInstanceOf(CheckAndSetException.class)
                .satisfies(exception -> assertThat(((CheckAndSetException) exception).getActualValues())
                        .containsExactly(VALUE));
    }

    @Test
    public void testPartialFailures() throws ExecutionException, InterruptedException {
        int numberOfSuccessfulPue = 0;
        int numberOfNothingPresent = 0;
        int numberOfValuePresentAfterFailure = 0;
        for (int i = 0; i < 100; i++) {
            Cell cell = Cell.create(PtBytes.toBytes(i), PtBytes.toBytes(i));
            try {
                AtomicUpdateResult atomicUpdateResult = sometimesThrowing.atomicUpdate(cell, VALUE);
                if (!atomicUpdateResult.existingKeys().isEmpty()) {
                    throw new KeyAlreadyExistsException(
                            "Could not perform pue",
                            atomicUpdateResult.existingKeys(),
                            atomicUpdateResult.knownSuccessfullyCommittedKeys());
                }
                numberOfSuccessfulPue++;
                sometimesThrowing.setProbabilityOfFailure(0.0);
                assertThat(sometimesThrowing.get(cell).get()).hasValue(VALUE);
                sometimesThrowing.setProbabilityOfFailure(PROBABILITY_THROWING_ON_QUORUM_HALF);

            } catch (RuntimeException e) {
                sometimesThrowing.setProbabilityOfFailure(0.0);
                Optional<byte[]> actualValue = sometimesThrowing.get(cell).get();
                if (actualValue.isEmpty()) {
                    numberOfNothingPresent++;
                } else {
                    assertThat(actualValue).hasValue(VALUE);
                    numberOfValuePresentAfterFailure++;
                }
                sometimesThrowing.setProbabilityOfFailure(PROBABILITY_THROWING_ON_QUORUM_HALF);
            }
        }
        // expected half succeed
        assertThat(numberOfSuccessfulPue).isBetween(30, 70);
        // too lazy to calculate exactly, rough estimates
        assertThat(numberOfNothingPresent).isBetween(5, 40);
        assertThat(numberOfValuePresentAfterFailure).isBetween(10, 55);
    }
}
