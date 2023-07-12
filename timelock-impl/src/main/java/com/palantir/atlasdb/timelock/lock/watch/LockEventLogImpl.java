/*
 * (c) Copyright 2019 Palantir Technologies Inc. All rights reserved.
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

package com.palantir.atlasdb.timelock.lock.watch;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.RangeSet;
import com.palantir.atlasdb.timelock.lock.AsyncLock;
import com.palantir.atlasdb.timelock.lock.HeldLocksCollection;
import com.palantir.lock.LockDescriptor;
import com.palantir.lock.v2.LockToken;
import com.palantir.lock.watch.LockEvent;
import com.palantir.lock.watch.LockRequestMetadata;
import com.palantir.lock.watch.LockWatchCreatedEvent;
import com.palantir.lock.watch.LockWatchReferences.LockWatchReference;
import com.palantir.lock.watch.LockWatchStateUpdate;
import com.palantir.lock.watch.LockWatchVersion;
import com.palantir.lock.watch.UnlockEvent;
import com.palantir.logsafe.SafeArg;
import com.palantir.logsafe.Unsafe;
import com.palantir.logsafe.logger.SafeLogger;
import com.palantir.logsafe.logger.SafeLoggerFactory;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.Supplier;
import java.util.stream.Collectors;

public class LockEventLogImpl implements LockEventLog {
    private static final SafeLogger log = SafeLoggerFactory.get(LockEventLogImpl.class);

    // Our Sliding window can hold a maximum of 1000 values. If we never store more than 100 metadata values at a time
    // memory usage by metadata will be bounded by 100 * 1000 * MAX_CHANGE_METADATA bytes.
    // Assuming we are using ChangeMetadata that holds ~2KB max each, metadata cannot take up more than 200MB of memory.
    @VisibleForTesting
    static final int MAX_METADATA_SIZE = 100;

    private final UUID logId;
    private final ArrayLockEventSlidingWindow slidingWindow = new ArrayLockEventSlidingWindow(1000);
    private final Supplier<LockWatches> watchesSupplier;
    private final HeldLocksCollection heldLocksCollection;

    LockEventLogImpl(UUID logId, Supplier<LockWatches> watchesSupplier, HeldLocksCollection heldLocksCollection) {
        this.logId = logId;
        this.watchesSupplier = watchesSupplier;
        this.heldLocksCollection = heldLocksCollection;
    }

    @Override
    public synchronized LockWatchStateUpdate getLogDiff(Optional<LockWatchVersion> fromVersion) {
        return tryGetNextEvents(fromVersion).orElseGet(this::calculateSnapshot);
    }

    @Override
    public synchronized <T> ValueAndLockWatchStateUpdate<T> runTask(
            Optional<LockWatchVersion> lastKnownVersion, Supplier<T> task) {
        T t = task.get();
        LockWatchStateUpdate logDiff = getLogDiff(lastKnownVersion);
        return ValueAndLockWatchStateUpdate.of(logDiff, t);
    }

    @Override
    public synchronized void logLock(
            Set<LockDescriptor> locksTakenOut, LockToken lockToken, Optional<LockRequestMetadata> metadata) {
        // We don't want metadata to blow to consume absurd amounts of memory, but we cannot fail here as not publishing
        // the LockEvent would mean cache corruption. Discarding the metadata is fine, but we should keep track of
        // how often this happens.
        int metadataSize = metadata.map(LockRequestMetadata::size).orElse(0);
        if (metadataSize > MAX_METADATA_SIZE) {
            log.warn(
                    "Discarding metadata because it is too large",
                    SafeArg.of("metadataSize", metadataSize),
                    SafeArg.of("maxMetadataSize", MAX_METADATA_SIZE));
            metadata = Optional.empty();
        }
        slidingWindow.add(LockEvent.builder(locksTakenOut, lockToken, metadata));
    }

    @Override
    public synchronized void logUnlock(Set<LockDescriptor> locksUnlocked) {
        slidingWindow.add(UnlockEvent.builder(locksUnlocked));
    }

    @Override
    public synchronized void logLockWatchCreated(LockWatches newWatches) {
        Set<LockDescriptor> openLocks = calculateOpenLocks(newWatches.ranges());
        slidingWindow.add(LockWatchCreatedEvent.builder(newWatches.references(), openLocks));
    }

    private Optional<LockWatchStateUpdate> tryGetNextEvents(Optional<LockWatchVersion> fromVersion) {
        if (!fromVersion.isPresent() || !fromVersion.get().id().equals(logId)) {
            return Optional.empty();
        }

        return slidingWindow
                .getNextEvents(fromVersion.get().version())
                .map(events -> LockWatchStateUpdate.success(logId, slidingWindow.lastVersion(), events));
    }

    @Unsafe
    private LockWatchStateUpdate calculateSnapshot() {
        long lastVersion = slidingWindow.lastVersion();
        LockWatches currentWatches = watchesSupplier.get();
        Set<LockWatchReference> watches = new HashSet<>(currentWatches.references());
        Set<LockDescriptor> openLocks = calculateOpenLocks(currentWatches.ranges());
        return LockWatchStateUpdate.snapshot(logId, lastVersion, openLocks, watches);
    }

    /**
     * Iterates through all currently held locks and returns the set of all locks matching the watched ranges.
     * <p>
     * Note that the set of held locks can be modified during the execution of this method. Therefore, this method is
     * NOT guaranteed to return a consistent snapshot of the world.
     */
    private Set<LockDescriptor> calculateOpenLocks(RangeSet<LockDescriptor> watchedRanges) {
        return heldLocksCollection.locksHeld().stream()
                .flatMap(locksHeld -> locksHeld.getLocks().stream().map(AsyncLock::getDescriptor))
                .filter(watchedRanges::contains)
                .collect(Collectors.toSet());
    }
}
