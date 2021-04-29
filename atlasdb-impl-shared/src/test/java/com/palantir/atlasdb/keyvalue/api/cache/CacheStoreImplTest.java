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

package com.palantir.atlasdb.keyvalue.api.cache;

import static org.assertj.core.api.Assertions.assertThat;

import com.google.common.collect.ImmutableSet;
import com.palantir.atlasdb.keyvalue.api.watch.Sequence;
import com.palantir.atlasdb.keyvalue.api.watch.StartTimestamp;
import io.vavr.collection.HashMap;
import io.vavr.collection.HashSet;
import org.junit.Test;

public final class CacheStoreImplTest {
    private static final StartTimestamp TIMESTAMP_1 = StartTimestamp.of(1L);
    private static final StartTimestamp TIMESTAMP_2 = StartTimestamp.of(22L);

    @Test
    public void updatesToSnapshotStoreReflectedInCacheStore() {
        SnapshotStoreImpl snapshotStore = new SnapshotStoreImpl();
        CacheStore cacheStore = new CacheStoreImpl(snapshotStore);

        assertThat(cacheStore.createCache(TIMESTAMP_1)).isEmpty();

        snapshotStore.storeSnapshot(
                Sequence.of(5L),
                ImmutableSet.of(TIMESTAMP_2),
                ValueCacheSnapshotImpl.of(HashMap.empty(), HashSet.empty()));
        assertThat(cacheStore.createCache(TIMESTAMP_2)).isPresent();
    }
}
