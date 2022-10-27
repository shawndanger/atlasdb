/*
 * (c) Copyright 2022 Palantir Technologies Inc. All rights reserved.
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

package com.palantir.atlasdb.atomic.mcas;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.palantir.atlasdb.autobatch.BatchElement;
import com.palantir.atlasdb.encoding.PtBytes;
import com.palantir.atlasdb.keyvalue.api.Cell;
import com.palantir.atlasdb.keyvalue.api.KeyAlreadyExistsException;
import com.palantir.atlasdb.keyvalue.api.MultiCheckAndSetException;
import com.palantir.atlasdb.keyvalue.api.TableReference;
import com.palantir.atlasdb.keyvalue.impl.InMemoryKeyValueService;
import com.palantir.atlasdb.logging.LoggingArgs;
import com.palantir.atlasdb.transaction.encoding.TwoPhaseEncodingStrategy;
import com.palantir.atlasdb.transaction.impl.TransactionConstants;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import org.junit.Test;

public class MarkAndCasConsensusForgettingStoreTest {
    private static final byte[] SAD = PtBytes.toBytes("sad");
    private static final byte[] HAPPY = PtBytes.toBytes("happy");

    private static final byte[] ROW = PtBytes.toBytes("r");
    private static final ByteBuffer BUFFERED_SAD = ByteBuffer.wrap(SAD);
    private static final ByteBuffer BUFFERED_HAPPY = ByteBuffer.wrap(HAPPY);

    private static final Cell CELL = Cell.create(ROW, PtBytes.toBytes("col1"));
    private static final Cell CELL_2 = Cell.create(ROW, PtBytes.toBytes("col2"));
    public static final TableReference TABLE = TableReference.createFromFullyQualifiedName("test.table");

    private static final ByteBuffer BUFFERED_IN_PROGRESS_MARKER =
            ByteBuffer.wrap(TransactionConstants.TTS_IN_PROGRESS_MARKER);

    private final InMemoryKeyValueService kvs = spy(new InMemoryKeyValueService(true));
    private final MarkAndCasConsensusForgettingStore store =
            new MarkAndCasConsensusForgettingStore(TransactionConstants.TTS_IN_PROGRESS_MARKER, kvs, TABLE);

    @Test
    public void canMarkCell() throws ExecutionException, InterruptedException {
        store.mark(CELL);
        assertThat(store.get(CELL).get()).hasValue(TransactionConstants.TTS_IN_PROGRESS_MARKER);
        assertThat(kvs.getAllTimestamps(TABLE, ImmutableSet.of(CELL), Long.MAX_VALUE)
                        .size())
                .isEqualTo(1);
    }

    @Test
    public void updatesMarkedCell() throws ExecutionException, InterruptedException {
        store.mark(CELL);
        store.processBatch(
                kvs, TABLE, ImmutableList.of(TestBatchElement.of(CELL, BUFFERED_IN_PROGRESS_MARKER, BUFFERED_HAPPY)));
        assertThat(store.get(CELL).get()).hasValue(HAPPY);
    }

    @Test
    public void updatesMultipleMarkedCells() throws ExecutionException, InterruptedException {
        store.mark(ImmutableSet.of(CELL, CELL_2));

        store.atomicUpdate(ImmutableMap.of(CELL, HAPPY, CELL_2, HAPPY));
        TestBatchElement elem1 = TestBatchElement.of(CELL, BUFFERED_IN_PROGRESS_MARKER, BUFFERED_HAPPY);
        TestBatchElement elem2 = TestBatchElement.of(CELL_2, BUFFERED_IN_PROGRESS_MARKER, BUFFERED_SAD);

        store.processBatch(kvs, TABLE, ImmutableList.of(elem1, elem2));
        assertThat(store.get(CELL).get()).hasValue(elem1.argument().update().array());
        assertThat(store.get(CELL_2).get()).hasValue(elem2.argument().update().array());
    }

    @Test
    public void cannotUpdateUnmarkedCell() throws ExecutionException, InterruptedException {
        TestBatchElement element = TestBatchElement.of(CELL, BUFFERED_IN_PROGRESS_MARKER, BUFFERED_HAPPY);
        store.processBatch(kvs, TABLE, ImmutableList.of(element));
        assertThatThrownBy(() -> element.result().get())
                .hasCauseInstanceOf(KeyAlreadyExistsException.class)
                .hasMessageContaining("Atomic update cannot go through as the key already exists in the KVS.");
        assertThat(store.get(CELL).get()).isEmpty();
    }

    @Test
    public void failsAllButOneRequestsWithSameParams() throws ExecutionException, InterruptedException {
        store.mark(CELL);
        int totalRequests = 100;

        List<BatchElement<CasRequest, Void>> requests = IntStream.range(0, totalRequests)
                .mapToObj(_idx -> TestBatchElement.of(CELL, BUFFERED_IN_PROGRESS_MARKER, BUFFERED_HAPPY))
                .collect(Collectors.toList());
        MarkAndCasConsensusForgettingStore.processBatch(kvs, TABLE, requests);
        verify(kvs).multiCheckAndSet(any());
        assertThat(store.get(CELL).get()).hasValue(HAPPY);

        int success = 0;
        int failures = 0;

        for (BatchElement<CasRequest, Void> elem : requests) {
            try {
                elem.result().get();
                success++;
            } catch (Exception ex) {
                Throwable cause = ex.getCause();
                assertThat(cause)
                        .isInstanceOf(KeyAlreadyExistsException.class)
                        .hasMessageContaining("Atomic update cannot go through as the key already exists in the KVS.");
                failures++;
            }
        }

        assertThat(success).isEqualTo(1);
        assertThat(failures).isEqualTo(totalRequests - 1);
    }

    @Test
    public void canServeMultipleRequestsForSameRowWithOneQuery() throws ExecutionException, InterruptedException {
        store.mark(CELL);
        store.mark(CELL_2);

        TestBatchElement req1 = TestBatchElement.of(CELL, BUFFERED_IN_PROGRESS_MARKER, BUFFERED_HAPPY);
        TestBatchElement req2 = TestBatchElement.of(CELL_2, BUFFERED_IN_PROGRESS_MARKER, BUFFERED_HAPPY);

        CasRequestBatch casRequestBatch = new CasRequestBatch(TABLE, ROW, ImmutableList.of(req1, req2));

        MarkAndCasConsensusForgettingStore.serveMcasRequest(kvs, casRequestBatch);

        verify(kvs).multiCheckAndSet(any());

        assertThatCode(() -> req1.result().get()).doesNotThrowAnyException();
        assertThat(store.get(CELL).get()).hasValue(HAPPY);

        assertThatCode(() -> req2.result().get()).doesNotThrowAnyException();
        assertThat(store.get(CELL_2).get()).hasValue(HAPPY);

        assertThat(casRequestBatch.isBatchServed()).isTrue();
    }

    @Test
    public void correctlyJudgesIfReqShouldBeRetried() {
        store.mark(CELL);
        store.mark(CELL_2);
        TestBatchElement reqShouldBeRetried = TestBatchElement.of(CELL, BUFFERED_IN_PROGRESS_MARKER, BUFFERED_HAPPY);
        TestBatchElement reqShouldNotBeRetried =
                TestBatchElement.of(CELL_2, BUFFERED_IN_PROGRESS_MARKER, BUFFERED_HAPPY);

        MultiCheckAndSetException ex = new MultiCheckAndSetException(
                LoggingArgs.tableRef(TABLE),
                ROW,
                ImmutableMap.of(CELL, BUFFERED_IN_PROGRESS_MARKER.array(), CELL_2, BUFFERED_IN_PROGRESS_MARKER.array()),
                ImmutableMap.of(CELL, BUFFERED_IN_PROGRESS_MARKER.array()));

        assertThat(MarkAndCasConsensusForgettingStore.shouldRetry(reqShouldBeRetried, ex))
                .isTrue();
        assertThat(MarkAndCasConsensusForgettingStore.shouldRetry(reqShouldNotBeRetried, ex))
                .isFalse();
    }

    @Test
    public void retriesRequestsIfCanBeRetried() throws ExecutionException, InterruptedException {
        store.mark(CELL);
        TestBatchElement req1 = TestBatchElement.of(CELL, BUFFERED_IN_PROGRESS_MARKER, BUFFERED_HAPPY);
        TestBatchElement req2 = TestBatchElement.of(CELL_2, BUFFERED_IN_PROGRESS_MARKER, BUFFERED_HAPPY);

        MarkAndCasConsensusForgettingStore.processBatch(kvs, TABLE, ImmutableList.of(req1, req2));
        // first try will fail as cell_2 has not been marked
        verify(kvs, times(2)).multiCheckAndSet(any());

        assertThatCode(() -> req1.result().get()).doesNotThrowAnyException();
        assertThat(store.get(CELL).get()).hasValue(HAPPY);

        assertThatThrownBy(() -> req2.result().get()).hasCauseInstanceOf(KeyAlreadyExistsException.class);
        assertThat(store.get(CELL_2).get()).isEmpty();
    }

    @Test
    public void choosesCommitOverAbort() throws ExecutionException, InterruptedException {
        store.mark(CELL);
        ByteBuffer commitVal = ByteBuffer.wrap(new byte[] {9, 23, 45, 27, 0});
        TestBatchElement commit = TestBatchElement.of(CELL, BUFFERED_IN_PROGRESS_MARKER, commitVal);
        TestBatchElement abort = TestBatchElement.of(
                CELL,
                BUFFERED_IN_PROGRESS_MARKER,
                ByteBuffer.wrap(TwoPhaseEncodingStrategy.ABORTED_TRANSACTION_STAGING_VALUE));

        store.processBatch(kvs, TABLE, ImmutableList.of(commit, abort));
        verify(kvs).multiCheckAndSet(any());
        assertThat(store.get(CELL).get()).hasValue(commitVal.array());
    }

    @Test
    public void choosesTouchOverAbort() throws ExecutionException, InterruptedException {
        ByteBuffer commitVal = ByteBuffer.wrap(new byte[] {9, 23, 45, 27, 0});
        kvs.put(TABLE, ImmutableMap.of(CELL, commitVal.array()), 0);

        TestBatchElement touch = TestBatchElement.of(CELL, commitVal, commitVal);
        TestBatchElement abort = TestBatchElement.of(
                CELL,
                BUFFERED_IN_PROGRESS_MARKER,
                ByteBuffer.wrap(TwoPhaseEncodingStrategy.ABORTED_TRANSACTION_STAGING_VALUE));

        assertThatCode(() -> store.processBatch(kvs, TABLE, ImmutableList.of(touch, abort)))
                .doesNotThrowAnyException();
        verify(kvs).multiCheckAndSet(any());
        assertThat(store.get(CELL).get()).hasValue(commitVal.array());
    }

    @Test
    public void choosesTouchOverCommit() throws ExecutionException, InterruptedException {
        ByteBuffer abortVal = ByteBuffer.wrap(TwoPhaseEncodingStrategy.ABORTED_TRANSACTION_STAGING_VALUE);
        kvs.put(TABLE, ImmutableMap.of(CELL, abortVal.array()), 0);

        TestBatchElement touch = TestBatchElement.of(CELL, abortVal, abortVal);
        TestBatchElement commit =
                TestBatchElement.of(CELL, BUFFERED_IN_PROGRESS_MARKER, ByteBuffer.wrap(new byte[] {27, 9, 81, 63, 0}));

        assertThatCode(() -> store.processBatch(kvs, TABLE, ImmutableList.of(touch, commit)))
                .doesNotThrowAnyException();
        verify(kvs).multiCheckAndSet(any());
        assertThat(store.get(CELL).get()).hasValue(abortVal.array());
    }
}
