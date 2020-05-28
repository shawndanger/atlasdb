/*
 * (c) Copyright 2020 Palantir Technologies Inc. All rights reserved.
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

package com.palantir.lock.watch;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.palantir.logsafe.exceptions.SafeNullPointerException;

@RunWith(MockitoJUnitRunner.class)
public final class LockWatchEventCacheImplTest {
    private static final UUID LEADER = UUID.randomUUID();
    private static final IdentifiedVersion VERSION_1 = IdentifiedVersion.of(LEADER, 17L);
    private static final IdentifiedVersion VERSION_2 = IdentifiedVersion.of(LEADER, 26L);
    private static final IdentifiedVersion VERSION_3 = IdentifiedVersion.of(LEADER, 38L);
    private static final LockWatchStateUpdate.Success SUCCESS_1 =
            LockWatchStateUpdate.success(VERSION_1.id(), VERSION_1.version(), ImmutableList.of());
    private static final LockWatchStateUpdate.Success SUCCESS_2 =
            LockWatchStateUpdate.success(VERSION_2.id(), VERSION_2.version(), ImmutableList.of());
    private static final LockWatchStateUpdate.Snapshot SNAPSHOT =
            LockWatchStateUpdate.snapshot(VERSION_3.id(), VERSION_3.version(), ImmutableSet.of(), ImmutableSet.of());
    private static final Set<Long> TIMESTAMPS_1 = ImmutableSet.of(1L, 2L, 1337L);
    private static final Set<Long> TIMESTAMPS_2 = ImmutableSet.of(3L, 10110101L);
    private static final Set<Long> TIMESTAMPS_COMBINED = ImmutableSet.of(1L, 2L, 3L, 1337L, 10110101L);

    @Mock
    private ClientLockWatchEventLog eventLog;

    private LockWatchEventCacheImpl eventCache;

    @Before
    public void before() {
        eventCache = LockWatchEventCacheImpl.create(eventLog);
    }

    @Test
    public void processStartTransactionUpdateAddsToCache() {
        Map<Long, IdentifiedVersion> expectedMap = constructExpectedMap(TIMESTAMPS_1, VERSION_1);

        when(eventLog.getLatestKnownVersion()).thenReturn(Optional.empty());
        when(eventLog.processUpdate(SUCCESS_1)).thenReturn(Optional.of(VERSION_1));
        eventCache.processTransactionUpdate(TIMESTAMPS_1, SUCCESS_1);
        verify(eventLog).processUpdate(SUCCESS_1);
        assertThat(eventCache.getTimestampToVersionMap(TIMESTAMPS_1)).containsExactlyEntriesOf(expectedMap);

        expectedMap.putAll(constructExpectedMap(TIMESTAMPS_2, VERSION_2));

        when(eventLog.getLatestKnownVersion()).thenReturn(Optional.of(VERSION_1));
        when(eventLog.processUpdate(SUCCESS_2)).thenReturn(Optional.of(VERSION_2));
        eventCache.processTransactionUpdate(TIMESTAMPS_2, SUCCESS_2);
        verify(eventLog).processUpdate(SUCCESS_2);
        assertThat(eventCache.getTimestampToVersionMap(TIMESTAMPS_COMBINED)).containsExactlyEntriesOf(expectedMap);
    }

    @Test
    public void previousTimestampsClearedOnSnapshotUpdate() {
        Map<Long, IdentifiedVersion> expectedMap = constructExpectedMap(TIMESTAMPS_COMBINED, VERSION_1);

        when(eventLog.processUpdate(SUCCESS_1)).thenReturn(Optional.of(VERSION_1));
        eventCache.processTransactionUpdate(TIMESTAMPS_COMBINED, SUCCESS_1);
        assertThat(eventCache.getTimestampToVersionMap(TIMESTAMPS_COMBINED)).containsExactlyEntriesOf(expectedMap);

        when(eventLog.processUpdate(SNAPSHOT)).thenReturn(Optional.of(VERSION_3));
        Set<Long> secondBatch = ImmutableSet.of(666L, 12545L);
        eventCache.processTransactionUpdate(secondBatch, SNAPSHOT);

        Map<Long, IdentifiedVersion> newExpectedMap = constructExpectedMap(secondBatch, VERSION_3);

        assertThat(eventCache.getTimestampToVersionMap(secondBatch)).containsExactlyEntriesOf(newExpectedMap);
        assertThatThrownBy(() -> eventCache.getTimestampToVersionMap(TIMESTAMPS_COMBINED))
                .isInstanceOf(SafeNullPointerException.class)
                .hasMessage("Timestamp missing from cache");
    }

    @Test
    public void removeFromCacheUpdatesEarliestVersion() {
        Map<Long, IdentifiedVersion> expectedMap1 = constructExpectedMap(TIMESTAMPS_1, VERSION_1);

        when(eventLog.getLatestKnownVersion()).thenReturn(Optional.empty());
        when(eventLog.processUpdate(SUCCESS_1)).thenReturn(Optional.of(VERSION_1));
        eventCache.processTransactionUpdate(TIMESTAMPS_1, SUCCESS_1);
        assertThat(eventCache.getTimestampToVersionMap(TIMESTAMPS_1)).containsExactlyInAnyOrderEntriesOf(expectedMap1);

        Map<Long, IdentifiedVersion> expectedMap2 = constructExpectedMap(TIMESTAMPS_2, VERSION_2);
        Map<Long, IdentifiedVersion> combinedMap = new HashMap<>(expectedMap1);
        combinedMap.putAll(expectedMap2);

        when(eventLog.getLatestKnownVersion()).thenReturn(Optional.of(VERSION_1));
        when(eventLog.processUpdate(SUCCESS_2)).thenReturn(Optional.of(VERSION_2));
        eventCache.processTransactionUpdate(TIMESTAMPS_2, SUCCESS_2);
        assertThat(eventCache.getTimestampToVersionMap(TIMESTAMPS_2)).containsExactlyInAnyOrderEntriesOf(expectedMap2);
        assertThat(eventCache.getTimestampToVersionMap(TIMESTAMPS_COMBINED)).containsExactlyInAnyOrderEntriesOf(combinedMap);
        assertThat(eventCache.getEarliestVersion()).hasValue(VERSION_1);

        removeTimestampAndCheckEarliestVersion(2L, VERSION_1);
        removeTimestampAndCheckEarliestVersion(3L, VERSION_1);
        removeTimestampAndCheckEarliestVersion(1L, VERSION_1);
        removeTimestampAndCheckEarliestVersion(1337L, VERSION_2);
    }

    private static Map<Long, IdentifiedVersion> constructExpectedMap(Set<Long> timestamps, IdentifiedVersion version) {
        Map<Long, IdentifiedVersion> expectedMap = new HashMap<>();
        timestamps.forEach(timestamp -> expectedMap.put(timestamp, version));
        return expectedMap;
    }

    private void removeTimestampAndCheckEarliestVersion(long timestamp, IdentifiedVersion version) {
        eventCache.removeTimestampFromCache(timestamp);
        assertThat(eventCache.getEarliestVersion()).hasValue(version);
    }
}
