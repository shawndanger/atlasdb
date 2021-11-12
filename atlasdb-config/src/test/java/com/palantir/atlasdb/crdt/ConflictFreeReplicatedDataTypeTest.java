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

package com.palantir.atlasdb.crdt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.util.concurrent.Futures;
import com.palantir.atlasdb.crdt.bucket.ShotgunSeriesBucketSelector;
import com.palantir.atlasdb.crdt.generated.CrdtTable;
import com.palantir.atlasdb.crdt.generated.CrdtTableFactory;
import com.palantir.atlasdb.factory.TransactionManagers;
import com.palantir.atlasdb.table.description.ValueType;
import com.palantir.atlasdb.transaction.api.TransactionConflictException;
import com.palantir.atlasdb.transaction.api.TransactionManager;
import com.palantir.common.concurrent.PTExecutors;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.function.BinaryOperator;
import java.util.function.Function;
import org.junit.Test;

public class ConflictFreeReplicatedDataTypeTest {
    private static final Series TOM = ImmutableSeries.of("tom");

    private final TransactionManager txMgr =
            TransactionManagers.createInMemory(ImmutableSet.of(CrdtSchema.INSTANCE.getLatestSchema()));

    @Test
    public void sanityCheck() {
        for (int i = 0; i < 100; i++) {
            txMgr.runTaskWithRetry(txn -> {
                CrdtTable crdtTable = CrdtTableFactory.of().getCrdtTable(txn);
                ConflictFreeReplicatedDataTypeWriter<Long> writer = new ConflictFreeReplicatedDataTypeWriter<>(
                        crdtTable, MergingLongAdapter.INSTANCE, new ShotgunSeriesBucketSelector(100));
                writer.aggregateValue(TOM, 1L);
                return null;
            });
        }
        long mergedLongs = txMgr.runTaskWithRetry(txn -> {
            CrdtTable crdtTable = CrdtTableFactory.of().getCrdtTable(txn);
            ConflictFreeReplicatedDataTypeReader<Long> reader =
                    new ConflictFreeReplicatedDataTypeReader<>(crdtTable, MergingLongAdapter.INSTANCE);
            return reader.read(ImmutableList.of(TOM)).get(TOM);
        });
        assertThat(mergedLongs).as("there were no lost updates").isEqualTo(100L);
        txMgr.runTaskWithRetry(txn -> {
            CrdtTable crdtTable = CrdtTableFactory.of().getCrdtTable(txn);
            assertThat(crdtTable.getRowColumns(CrdtTable.CrdtRow.of(TOM.value())))
                    .as("we didn't just write a single value to each bucket")
                    .hasSizeLessThan(100);
            return null;
        });
    }

    @Test
    public void concurrentIncrementsAreTransactional() {
        ExecutorService executorService = PTExecutors.newFixedThreadPool(100);
        CountDownLatch latch = new CountDownLatch(100);

        List<Future<Void>> futures = new ArrayList<>();
        for (int i = 0; i < 100; i++) {
            Future<Void> future = executorService.submit(() -> {
                txMgr.runTaskWithRetry(txn -> {
                    CrdtTable crdtTable = CrdtTableFactory.of().getCrdtTable(txn);
                    ConflictFreeReplicatedDataTypeWriter<Long> writer = new ConflictFreeReplicatedDataTypeWriter<>(
                            crdtTable, MergingLongAdapter.INSTANCE, new ShotgunSeriesBucketSelector(100));
                    latch.countDown();
                    latch.await();
                    writer.aggregateValue(TOM, 1L);
                    return null;
                });
                return null;
            });
            futures.add(future);
        }

        futures.forEach(Futures::getUnchecked);
        long mergedLongs = txMgr.runTaskWithRetry(txn -> {
            CrdtTable crdtTable = CrdtTableFactory.of().getCrdtTable(txn);
            ConflictFreeReplicatedDataTypeReader<Long> reader =
                    new ConflictFreeReplicatedDataTypeReader<>(crdtTable, MergingLongAdapter.INSTANCE);
            return reader.read(ImmutableList.of(TOM)).get(TOM);
        });
        assertThat(mergedLongs).as("there were no lost updates").isEqualTo(100L);
        txMgr.runTaskWithRetry(txn -> {
            CrdtTable crdtTable = CrdtTableFactory.of().getCrdtTable(txn);
            assertThat(crdtTable.getRowColumns(CrdtTable.CrdtRow.of(TOM.value())))
                    .as("we didn't just write a single value to each bucket")
                    .hasSizeLessThan(100);
            return null;
        });
    }

    @Test
    public void concurrentRowIncrementsDoNotWork() {
        ExecutorService executorService = PTExecutors.newFixedThreadPool(100);
        CountDownLatch latch = new CountDownLatch(100);

        List<Future<Void>> futures = new ArrayList<>();
        for (int i = 0; i < 100; i++) {
            Future<Void> future = executorService.submit(() -> {
                txMgr.runTaskWithRetry(txn -> {
                    CrdtTable crdtTable = CrdtTableFactory.of().getCrdtTable(txn);
                    crdtTable.getRowColumns(CrdtTable.CrdtRow.of(TOM.value()));
                    ConflictFreeReplicatedDataTypeWriter<Long> writer = new ConflictFreeReplicatedDataTypeWriter<>(
                            crdtTable, MergingLongAdapter.INSTANCE, new ShotgunSeriesBucketSelector(1));
                    latch.countDown();
                    latch.await();
                    writer.aggregateValue(TOM, 1L);
                    return null;
                });
                return null;
            });
            futures.add(future);
        }

        assertThatThrownBy(() -> futures.forEach(Futures::getUnchecked))
                .hasCauseInstanceOf(TransactionConflictException.class);
    }

    private enum MergingLongAdapter implements ConflictFreeReplicatedDataTypeAdapter<Long> {
        INSTANCE;

        @Override
        public Function<Long, byte[]> serializer() {
            return ValueType.VAR_LONG::convertFromJava;
        }

        @Override
        public Function<byte[], Long> deserializer() {
            return v -> (Long) ValueType.VAR_LONG.convertToJava(v, 0);
        }

        @Override
        public BinaryOperator<Long> merge() {
            return Long::sum;
        }

        @Override
        public Long identity() {
            return 0L;
        }
    }
}
