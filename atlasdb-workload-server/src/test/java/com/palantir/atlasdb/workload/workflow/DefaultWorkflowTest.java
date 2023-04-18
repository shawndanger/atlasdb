/*
 * (c) Copyright 2023 Palantir Technologies Inc. All rights reserved.
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

package com.palantir.atlasdb.workload.workflow;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.google.common.collect.ImmutableList;
import com.google.common.util.concurrent.ListeningExecutorService;
import com.google.common.util.concurrent.MoreExecutors;
import com.palantir.atlasdb.workload.store.TransactionStore;
import com.palantir.atlasdb.workload.transaction.witnessed.FullyWitnessedTransaction;
import com.palantir.atlasdb.workload.transaction.witnessed.MaybeWitnessedTransaction;
import com.palantir.atlasdb.workload.transaction.witnessed.WitnessedTransaction;
import com.palantir.common.concurrent.PTExecutors;
import java.util.List;
import java.util.concurrent.ScheduledExecutorService;
import org.junit.Test;

public class DefaultWorkflowTest {
    private final TransactionStore store = mock(TransactionStore.class);

    private final KeyedTransactionTask<TransactionStore> transactionTask = mock(KeyedTransactionTask.class);

    private final ScheduledExecutorService scheduler = PTExecutors.newSingleThreadScheduledExecutor();
    private final ListeningExecutorService executionExecutor = MoreExecutors.listeningDecorator(scheduler);

    private final DefaultWorkflow<TransactionStore> workflow =
            DefaultWorkflow.create(store, transactionTask, createWorkflowConfiguration(2), executionExecutor);

    @Test
    public void handlesExceptionsInUnderlyingTasks() {
        RuntimeException transactionException = new RuntimeException("boo");
        when(transactionTask.apply(eq(store), anyInt())).thenThrow(transactionException);
        assertThatThrownBy(workflow::run)
                .hasMessage("Error when running workflow task")
                .hasCause(transactionException);
    }

    @Test
    public void returnsUnderlyingWitnessedTransactions() {
        WitnessedTransaction twoToEight = createWitnessedTransactionWithoutActions(2, 8);
        WitnessedTransaction readOnlyAtFive = createReadOnlyWitnessedTransactionWithoutActions(5);

        assertThat(workflow.sortAndFilterTransactions(ImmutableList.of(twoToEight)))
                .containsExactly(twoToEight);
        assertThat(workflow.sortAndFilterTransactions(ImmutableList.of(readOnlyAtFive)))
                .containsExactly(readOnlyAtFive);
    }

    @Test
    public void sortsResultsOfWriteTransactionsByCommitTimestamp() {
        WitnessedTransaction twoToEight = createWitnessedTransactionWithoutActions(2, 8);
        WitnessedTransaction threeToSeven = createWitnessedTransactionWithoutActions(3, 7);
        WitnessedTransaction fourToSix = createWitnessedTransactionWithoutActions(4, 6);

        assertThat(workflow.sortAndFilterTransactions(ImmutableList.of(twoToEight, threeToSeven, fourToSix)))
                .containsExactly(fourToSix, threeToSeven, twoToEight);
    }

    @Test
    public void sortsReadOnlyTransactionsByStartTimestamp() {
        WitnessedTransaction readOnlyAtThree = createReadOnlyWitnessedTransactionWithoutActions(3);
        WitnessedTransaction readOnlyAtSeven = createReadOnlyWitnessedTransactionWithoutActions(7);
        WitnessedTransaction readOnlyAtFortyTwo = createReadOnlyWitnessedTransactionWithoutActions(42);

        assertThat(workflow.sortAndFilterTransactions(
                        ImmutableList.of(readOnlyAtSeven, readOnlyAtFortyTwo, readOnlyAtThree)))
                .containsExactly(readOnlyAtThree, readOnlyAtSeven, readOnlyAtFortyTwo);
    }

    @Test
    public void sortsReadAndWriteTransactionsByEffectiveTimestamp() {
        WitnessedTransaction twoToEight = createWitnessedTransactionWithoutActions(2, 8);
        WitnessedTransaction fourToSix = createWitnessedTransactionWithoutActions(4, 6);

        WitnessedTransaction readOnlyAtThree = createReadOnlyWitnessedTransactionWithoutActions(3);
        WitnessedTransaction readOnlyAtFive = createReadOnlyWitnessedTransactionWithoutActions(5);
        WitnessedTransaction readOnlyAtSeven = createReadOnlyWitnessedTransactionWithoutActions(7);
        WitnessedTransaction readOnlyAtNine = createReadOnlyWitnessedTransactionWithoutActions(9);

        assertThat(workflow.sortAndFilterTransactions(ImmutableList.of(
                        twoToEight, readOnlyAtNine, fourToSix, readOnlyAtFive, readOnlyAtThree, readOnlyAtSeven)))
                .containsExactly(
                        readOnlyAtThree, readOnlyAtFive, fourToSix, readOnlyAtSeven, twoToEight, readOnlyAtNine);
    }

    @Test
    public void filterRemovesUncommittedTransactions() {
        WitnessedTransaction committedMaybeWitnessedTransaction =
                createMaybeWitnessedTransactionWithoutActions(1, 3, true);
        WitnessedTransaction notCommittedTransaction = createMaybeWitnessedTransactionWithoutActions(2, 8, false);
        WitnessedTransaction readOnlyAtFive = createReadOnlyWitnessedTransactionWithoutActions(5);
        WitnessedTransaction fourToSix = createWitnessedTransactionWithoutActions(4, 6);
        assertThat(workflow.sortAndFilterTransactions(List.of(
                        committedMaybeWitnessedTransaction, notCommittedTransaction, readOnlyAtFive, fourToSix)))
                .containsExactly(committedMaybeWitnessedTransaction, readOnlyAtFive, fourToSix);
    }

    private WorkflowConfiguration createWorkflowConfiguration(int iterationCount) {
        return new WorkflowConfiguration() {
            @Override
            public int iterationCount() {
                return iterationCount;
            }
        };
    }

    private MaybeWitnessedTransaction createMaybeWitnessedTransactionWithoutActions(
            long start, long commit, boolean committed) {
        when(store.isCommitted(eq(start))).thenReturn(committed);
        return MaybeWitnessedTransaction.builder()
                .startTimestamp(start)
                .commitTimestamp(commit)
                .build();
    }

    private static WitnessedTransaction createReadOnlyWitnessedTransactionWithoutActions(long start) {
        return FullyWitnessedTransaction.builder().startTimestamp(start).build();
    }

    private static WitnessedTransaction createWitnessedTransactionWithoutActions(long start, long commit) {
        return FullyWitnessedTransaction.builder()
                .startTimestamp(start)
                .commitTimestamp(commit)
                .build();
    }
}
