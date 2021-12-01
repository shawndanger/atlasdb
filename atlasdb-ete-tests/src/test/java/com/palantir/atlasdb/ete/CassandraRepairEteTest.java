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

package com.palantir.atlasdb.ete;

import static org.assertj.core.api.Assertions.assertThat;

import com.codahale.metrics.MetricRegistry;
import com.google.common.collect.ImmutableMap;
import com.palantir.atlasdb.AtlasDbConstants;
import com.palantir.atlasdb.cassandra.CassandraKeyValueServiceConfig;
import com.palantir.atlasdb.cassandra.backup.CassandraRepairHelper;
import com.palantir.atlasdb.cassandra.backup.LightweightOppTokenRange;
import com.palantir.atlasdb.containers.ThreeNodeCassandraCluster;
import com.palantir.atlasdb.encoding.PtBytes;
import com.palantir.atlasdb.keyvalue.api.Cell;
import com.palantir.atlasdb.keyvalue.api.TableReference;
import com.palantir.atlasdb.keyvalue.cassandra.CassandraKeyValueService;
import com.palantir.atlasdb.keyvalue.cassandra.CassandraKeyValueServiceImpl;
import com.palantir.atlasdb.timelock.api.Namespace;
import com.palantir.atlasdb.util.MetricsManager;
import com.palantir.common.streams.KeyedStream;
import com.palantir.tritium.metrics.registry.DefaultTaggedMetricRegistry;
import java.net.InetSocketAddress;
import java.util.Map;
import java.util.Set;
import org.junit.Before;
import org.junit.Test;

public class CassandraRepairEteTest {
    private static final byte[] FIRST_COLUMN = PtBytes.toBytes("col1");
    private static final Cell NONEMPTY_CELL = Cell.create(PtBytes.toBytes("nonempty"), FIRST_COLUMN);
    private static final byte[] CONTENTS = PtBytes.toBytes("default_value");
    private static final String NAMESPACE = "ns";
    private static final String TABLE_1 = "table1";

    private CassandraRepairHelper cassandraRepairHelper;
    private CassandraKeyValueService kvs;

    @Before
    public void setUp() {
        MetricsManager metricsManager =
                new MetricsManager(new MetricRegistry(), new DefaultTaggedMetricRegistry(), _unused -> true);

        CassandraKeyValueServiceConfig config = ThreeNodeCassandraCluster.getKvsConfig(2);
        kvs = CassandraKeyValueServiceImpl.createForTesting(config);

        TableReference table1 =
                TableReference.create(com.palantir.atlasdb.keyvalue.api.Namespace.create(NAMESPACE), TABLE_1);
        kvs.createTable(table1, AtlasDbConstants.GENERIC_TABLE_METADATA);
        kvs.putUnlessExists(table1, ImmutableMap.of(NONEMPTY_CELL, CONTENTS));

        cassandraRepairHelper = new CassandraRepairHelper(metricsManager, _unused -> config, _unused -> kvs);
    }

    @Test
    public void getThriftTokenRange() {
        Map<InetSocketAddress, Set<LightweightOppTokenRange>> ranges =
                cassandraRepairHelper.getRangesToRepair(Namespace.of(NAMESPACE), TABLE_1);
        assertThat(ranges).isNotEmpty();
    }

    @Test
    public void getCqlTokenRange() {
        Map<InetSocketAddress, Set<LightweightOppTokenRange>> ranges =
                cassandraRepairHelper.getLwRangesToRepairCql(Namespace.of(NAMESPACE), TABLE_1);
        assertThat(ranges).isNotEmpty();
    }

    @Test
    public void equalRanges() {
        Map<InetSocketAddress, Set<LightweightOppTokenRange>> thriftRanges =
                cassandraRepairHelper.getRangesToRepair(Namespace.of(NAMESPACE), TABLE_1);

        Map<InetSocketAddress, Set<LightweightOppTokenRange>> cqlRanges =
                cassandraRepairHelper.getLwRangesToRepairCql(Namespace.of(NAMESPACE), TABLE_1);

        KeyedStream.stream(thriftRanges).forEach((addr, range) -> {
            Set<LightweightOppTokenRange> cqlRange = cqlRanges.get(addr);
            assertThat(range).isEqualTo(cqlRange);
        });
    }
}
