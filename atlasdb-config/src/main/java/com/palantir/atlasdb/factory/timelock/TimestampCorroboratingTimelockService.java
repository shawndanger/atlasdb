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

import java.util.concurrent.atomic.LongAccumulator;
import java.util.function.Supplier;
import java.util.function.ToLongFunction;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.palantir.lock.v2.AutoDelegate_TimelockService;
import com.palantir.lock.v2.IdentifiedTimeLockRequest;
import com.palantir.lock.v2.LockImmutableTimestampResponse;
import com.palantir.lock.v2.StartAtlasDbTransactionResponse;
import com.palantir.lock.v2.TimelockService;
import com.palantir.logsafe.SafeArg;
import com.palantir.timestamp.TimestampRange;

/**
 * A timelock service decorator for introducing runtime validity checks on received timestamps.
 */
public final class TimestampCorroboratingTimelockService implements AutoDelegate_TimelockService {
    private static final Logger log = LoggerFactory.getLogger(TimestampCorroboratingTimelockService.class);
    private static final String CLOCKS_WENT_BACKWARDS_MESSAGE =
            "Expected timestamp to be greater than %s, but a fresh timestamp was %s!";

    private final TimelockService delegate;
    private final LongAccumulator lowerBound = new LongAccumulator(Long::max, Long.MIN_VALUE);

    private TimestampCorroboratingTimelockService(TimelockService delegate) {
        this.delegate = delegate;
    }

    public static TimestampCorroboratingTimelockService create(TimelockService delegate) {
        return new TimestampCorroboratingTimelockService(delegate);
    }

    @Override
    public TimelockService delegate() {
        return delegate;
    }

    @Override
    public long getFreshTimestamp() {
        return checkAndUpdateLowerBound(delegate::getFreshTimestamp, x -> x, x -> x);
    }

    @Override
    public TimestampRange getFreshTimestamps(int numTimestampsRequested) {
        return checkAndUpdateLowerBound(() -> delegate.getFreshTimestamps(numTimestampsRequested),
                TimestampRange::getLowerBound,
                TimestampRange::getUpperBound);
    }

    @Override
    public StartAtlasDbTransactionResponse startAtlasDbTransaction(IdentifiedTimeLockRequest request) {
        return checkAndUpdateLowerBound(() -> delegate.startAtlasDbTransaction(request),
                StartAtlasDbTransactionResponse::freshTimestamp,
                StartAtlasDbTransactionResponse::freshTimestamp);
    }

    @Override
    public LockImmutableTimestampResponse lockImmutableTimestamp(IdentifiedTimeLockRequest request) {
        return checkAndUpdateLowerBound(() -> delegate.lockImmutableTimestamp(request),
                LockImmutableTimestampResponse::getImmutableTimestamp,
                LockImmutableTimestampResponse::getImmutableTimestamp);
    }

    /**
     * Runs a validation by comparing a fresh timestamp with a conservative lower bound that should be strictly lower
     * than any timestamp returned. This method can be used for assertion checks on startup.
     *
     * @param conservativeLowerBoundSupplier
     */
    public void validateWithConservativeLowerBound(Supplier<Long> conservativeLowerBoundSupplier) {
        long unreadableTimestamp = conservativeLowerBoundSupplier.get();
        long freshTimestamp = getFreshTimestamp();

        if (freshTimestamp <= unreadableTimestamp) {
            log.error("Your AtlasDB client believes that a strict lower bound for the timestamp was {} (typically by"
                            + " reading the unreadable timestamp), but that's newer than a fresh timestamp of {}, which"
                            + " implies clocks went back. If using TimeLock, this could be because timestamp bounds"
                            + " were not migrated properly - which can happen if you've moved TimeLock Server without"
                            + " moving its persistent state. For safety, AtlasDB will refuse to start.",
                    SafeArg.of("timestampLowerBound", lowerBound),
                    SafeArg.of("freshTimestamp", freshTimestamp));
            throw clocksWentBackwards(unreadableTimestamp, freshTimestamp);
        }

        log.info("Passed timestamp corroboration consistency check; expected a strict lower bound of {}, which was"
                        + " lower than a fresh timestamp of {}.",
                SafeArg.of("timestampLowerBound", lowerBound),
                SafeArg.of("freshTimestamp", freshTimestamp));
    }

    private <T> T checkAndUpdateLowerBound(Supplier<T> timestampContainerSupplier,
            ToLongFunction<T> lowerBoundExtractor,
            ToLongFunction<T> upperBoundExtractor) {
        long threadLocalLowerBound = lowerBound.get();
        T timestampContainer = timestampContainerSupplier.get();

        checkTimestamp(threadLocalLowerBound, lowerBoundExtractor.applyAsLong(timestampContainer));
        updateLowerBound(upperBoundExtractor.applyAsLong(timestampContainer));
        return timestampContainer;
    }

    private void checkTimestamp(long timestampLowerBound, long freshTimestamp) {
        if (freshTimestamp <= lowerBound.get()) {
            throw clocksWentBackwards(timestampLowerBound, freshTimestamp);
        }
    }

    private void updateLowerBound(long freshTimestamp) {
        lowerBound.accumulate(freshTimestamp);
    }

    private static AssertionError clocksWentBackwards(long timestampLowerBound, long freshTimestamp) {
        return new AssertionError(String.format(CLOCKS_WENT_BACKWARDS_MESSAGE, timestampLowerBound, freshTimestamp));
    }
}
