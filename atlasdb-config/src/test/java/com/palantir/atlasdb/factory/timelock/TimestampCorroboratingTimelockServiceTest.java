/*
 * (c) Copyright 2018 Palantir Technologies Inc. All rights reserved.
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

package com.palantir.atlasdb.factory.timelock;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.Before;
import org.junit.Test;

import com.palantir.lock.v2.IdentifiedTimeLockRequest;
import com.palantir.lock.v2.LockImmutableTimestampResponse;
import com.palantir.lock.v2.LockToken;
import com.palantir.lock.v2.StartAtlasDbTransactionResponse;
import com.palantir.lock.v2.TimelockService;
import com.palantir.timestamp.TimestampRange;

public class TimestampCorroboratingTimelockServiceTest {
    private static final IdentifiedTimeLockRequest IDENTIFIED_TIME_LOCK_REQUEST = IdentifiedTimeLockRequest.create();
    private static final LockImmutableTimestampResponse LOCK_IMMUTABLE_TIMESTAMP_RESPONSE =
            LockImmutableTimestampResponse.of(1L, mock(LockToken.class));

    private TimelockService rawTimelockService;
    private TimestampCorroboratingTimelockService timelockService;

    @Before
    public void setUp() {
        rawTimelockService = mock(TimelockService.class);
        timelockService = TimestampCorroboratingTimelockService.create(rawTimelockService);
    }

    @Test
    public void getFreshTimestampShouldFail() {
        when(rawTimelockService.getFreshTimestamp()).thenReturn(1L);

        assertThrowsOnSecondCall(timelockService::getFreshTimestamp);
    }

    @Test
    public void getFreshTimestampsShouldFail() {
        TimestampRange timestampRange = TimestampRange.createInclusiveRange(1, 2);
        when(rawTimelockService.getFreshTimestamps(anyInt())).thenReturn(timestampRange);

        assertThrowsOnSecondCall(() -> timelockService.getFreshTimestamps(1));
    }

    @Test
    public void startAtlasDbTransactionShouldFail() {
        StartAtlasDbTransactionResponse response = StartAtlasDbTransactionResponse.of(
                mock(LockImmutableTimestampResponse.class), 1L);
        when(rawTimelockService.startAtlasDbTransaction(any())).thenReturn(response);

        assertThrowsOnSecondCall(() -> timelockService.startAtlasDbTransaction(IDENTIFIED_TIME_LOCK_REQUEST));
    }

    @Test
    public void lockImmutableTimestampShouldFail() {
        when(rawTimelockService.lockImmutableTimestamp(any())).thenReturn(LOCK_IMMUTABLE_TIMESTAMP_RESPONSE);

        assertThrowsOnSecondCall(() -> timelockService.lockImmutableTimestamp(IDENTIFIED_TIME_LOCK_REQUEST));
    }

    @Test
    public void failsIfFreshTimestampIsLowerThanConservativeBound() {
        when(rawTimelockService.getFreshTimestamp()).thenReturn(0L);
        assertThrowsGoBackInTimeError(() -> timelockService.validateWithConservativeLowerBound(() -> 1L));
    }

    @Test
    public void shouldNotFailIfConservativeBoundIsLowerThanFreshTimestamp() {
        when(rawTimelockService.getFreshTimestamp()).thenReturn(2L);
        timelockService.validateWithConservativeLowerBound(() -> 1L);
    }

    private void assertThrowsOnSecondCall(Runnable runnable) {
        runnable.run();
        assertThrowsGoBackInTimeError(runnable);
    }

    private void assertThrowsGoBackInTimeError(Runnable runnable) {
        assertThatThrownBy(runnable::run)
                .isInstanceOf(AssertionError.class)
                .hasMessageStartingWith("Expected timestamp to be greater than");
    }
}
