package com.palantir.atlasdb.schema.generated;

import java.util.Arrays;
import java.util.Collection;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.SortedMap;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.TimeUnit;
import java.util.function.BiFunction;
import java.util.function.Supplier;
import java.util.stream.Stream;

import javax.annotation.Nullable;
import javax.annotation.processing.Generated;

import com.google.common.base.Function;
import com.google.common.base.Joiner;
import com.google.common.base.MoreObjects;
import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.Collections2;
import com.google.common.collect.ComparisonChain;
import com.google.common.collect.HashMultimap;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableMultimap;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Iterables;
import com.google.common.collect.Iterators;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.google.common.collect.Multimap;
import com.google.common.collect.Multimaps;
import com.google.common.collect.Sets;
import com.google.common.hash.Hashing;
import com.google.common.primitives.Bytes;
import com.google.common.primitives.UnsignedBytes;
import com.google.protobuf.InvalidProtocolBufferException;
import com.palantir.atlasdb.compress.CompressionUtils;
import com.palantir.atlasdb.encoding.PtBytes;
import com.palantir.atlasdb.keyvalue.api.BatchColumnRangeSelection;
import com.palantir.atlasdb.keyvalue.api.Cell;
import com.palantir.atlasdb.keyvalue.api.ColumnRangeSelection;
import com.palantir.atlasdb.keyvalue.api.ColumnRangeSelections;
import com.palantir.atlasdb.keyvalue.api.ColumnSelection;
import com.palantir.atlasdb.keyvalue.api.Namespace;
import com.palantir.atlasdb.keyvalue.api.Prefix;
import com.palantir.atlasdb.keyvalue.api.RangeRequest;
import com.palantir.atlasdb.keyvalue.api.RowResult;
import com.palantir.atlasdb.keyvalue.api.TableReference;
import com.palantir.atlasdb.keyvalue.impl.Cells;
import com.palantir.atlasdb.ptobject.EncodingUtils;
import com.palantir.atlasdb.table.api.AtlasDbDynamicMutablePersistentTable;
import com.palantir.atlasdb.table.api.AtlasDbMutablePersistentTable;
import com.palantir.atlasdb.table.api.AtlasDbNamedMutableTable;
import com.palantir.atlasdb.table.api.AtlasDbNamedPersistentSet;
import com.palantir.atlasdb.table.api.ColumnValue;
import com.palantir.atlasdb.table.api.TypedRowResult;
import com.palantir.atlasdb.table.description.ColumnValueDescription.Compression;
import com.palantir.atlasdb.table.description.ValueType;
import com.palantir.atlasdb.table.generation.ColumnValues;
import com.palantir.atlasdb.table.generation.Descending;
import com.palantir.atlasdb.table.generation.NamedColumnValue;
import com.palantir.atlasdb.transaction.api.AtlasDbConstraintCheckingMode;
import com.palantir.atlasdb.transaction.api.ConstraintCheckingTransaction;
import com.palantir.atlasdb.transaction.api.ImmutableGetRangesQuery;
import com.palantir.atlasdb.transaction.api.Transaction;
import com.palantir.common.base.AbortingVisitor;
import com.palantir.common.base.AbortingVisitors;
import com.palantir.common.base.BatchingVisitable;
import com.palantir.common.base.BatchingVisitableView;
import com.palantir.common.base.BatchingVisitables;
import com.palantir.common.base.Throwables;
import com.palantir.common.collect.IterableView;
import com.palantir.common.persist.Persistable;
import com.palantir.common.persist.Persistable.Hydrator;
import com.palantir.common.persist.Persistables;
import com.palantir.util.AssertUtils;
import com.palantir.util.crypto.Sha256Hash;

@Generated("com.palantir.atlasdb.table.description.render.TableRenderer")
@SuppressWarnings({"all", "deprecation"})
public final class SweepShardProgressTable implements
        AtlasDbMutablePersistentTable<SweepShardProgressTable.SweepShardProgressRow,
                                         SweepShardProgressTable.SweepShardProgressNamedColumnValue<?>,
                                         SweepShardProgressTable.SweepShardProgressRowResult>,
        AtlasDbNamedMutableTable<SweepShardProgressTable.SweepShardProgressRow,
                                    SweepShardProgressTable.SweepShardProgressNamedColumnValue<?>,
                                    SweepShardProgressTable.SweepShardProgressRowResult> {
    private final Transaction t;
    private final List<SweepShardProgressTrigger> triggers;
    private final static String rawTableName = "sweepProgressPerShard";
    private final TableReference tableRef;
    private final static ColumnSelection allColumns = getColumnSelection(SweepShardProgressNamedColumn.values());

    static SweepShardProgressTable of(Transaction t, Namespace namespace) {
        return new SweepShardProgressTable(t, namespace, ImmutableList.<SweepShardProgressTrigger>of());
    }

    static SweepShardProgressTable of(Transaction t, Namespace namespace, SweepShardProgressTrigger trigger, SweepShardProgressTrigger... triggers) {
        return new SweepShardProgressTable(t, namespace, ImmutableList.<SweepShardProgressTrigger>builder().add(trigger).add(triggers).build());
    }

    static SweepShardProgressTable of(Transaction t, Namespace namespace, List<SweepShardProgressTrigger> triggers) {
        return new SweepShardProgressTable(t, namespace, triggers);
    }

    private SweepShardProgressTable(Transaction t, Namespace namespace, List<SweepShardProgressTrigger> triggers) {
        this.t = t;
        this.tableRef = TableReference.create(namespace, rawTableName);
        this.triggers = triggers;
    }

    public static String getRawTableName() {
        return rawTableName;
    }

    public TableReference getTableRef() {
        return tableRef;
    }

    public String getTableName() {
        return tableRef.getQualifiedName();
    }

    public Namespace getNamespace() {
        return tableRef.getNamespace();
    }

    /**
     * <pre>
     * SweepShardProgressRow {
     *   {@literal Long hashOfRowComponents};
     *   {@literal Long shard};
     *   {@literal byte[] sweepConservative};
     * }
     * </pre>
     */
    public static final class SweepShardProgressRow implements Persistable, Comparable<SweepShardProgressRow> {
        private final long hashOfRowComponents;
        private final long shard;
        private final byte[] sweepConservative;

        public static SweepShardProgressRow of(long shard, byte[] sweepConservative) {
            long hashOfRowComponents = computeHashFirstComponents(shard);
            return new SweepShardProgressRow(hashOfRowComponents, shard, sweepConservative);
        }

        private SweepShardProgressRow(long hashOfRowComponents, long shard, byte[] sweepConservative) {
            this.hashOfRowComponents = hashOfRowComponents;
            this.shard = shard;
            this.sweepConservative = sweepConservative;
        }

        public long getShard() {
            return shard;
        }

        public byte[] getSweepConservative() {
            return sweepConservative;
        }

        public static Function<SweepShardProgressRow, Long> getShardFun() {
            return new Function<SweepShardProgressRow, Long>() {
                @Override
                public Long apply(SweepShardProgressRow row) {
                    return row.shard;
                }
            };
        }

        public static Function<SweepShardProgressRow, byte[]> getSweepConservativeFun() {
            return new Function<SweepShardProgressRow, byte[]>() {
                @Override
                public byte[] apply(SweepShardProgressRow row) {
                    return row.sweepConservative;
                }
            };
        }

        @Override
        public byte[] persistToBytes() {
            byte[] hashOfRowComponentsBytes = PtBytes.toBytes(Long.MIN_VALUE ^ hashOfRowComponents);
            byte[] shardBytes = EncodingUtils.encodeSignedVarLong(shard);
            byte[] sweepConservativeBytes = sweepConservative;
            return EncodingUtils.add(hashOfRowComponentsBytes, shardBytes, sweepConservativeBytes);
        }

        public static final Hydrator<SweepShardProgressRow> BYTES_HYDRATOR = new Hydrator<SweepShardProgressRow>() {
            @Override
            public SweepShardProgressRow hydrateFromBytes(byte[] __input) {
                int __index = 0;
                long hashOfRowComponents = Long.MIN_VALUE ^ PtBytes.toLong(__input, __index);
                __index += 8;
                long shard = EncodingUtils.decodeSignedVarLong(__input, __index);
                __index += EncodingUtils.sizeOfSignedVarLong(shard);
                byte[] sweepConservative = EncodingUtils.getBytesFromOffsetToEnd(__input, __index);
                return new SweepShardProgressRow(hashOfRowComponents, shard, sweepConservative);
            }
        };

        public static long computeHashFirstComponents(long shard) {
            byte[] shardBytes = EncodingUtils.encodeSignedVarLong(shard);
            return Hashing.murmur3_128().hashBytes(EncodingUtils.add(shardBytes)).asLong();
        }

        @Override
        public String toString() {
            return MoreObjects.toStringHelper(getClass().getSimpleName())
                .add("hashOfRowComponents", hashOfRowComponents)
                .add("shard", shard)
                .add("sweepConservative", sweepConservative)
                .toString();
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj == null) {
                return false;
            }
            if (getClass() != obj.getClass()) {
                return false;
            }
            SweepShardProgressRow other = (SweepShardProgressRow) obj;
            return Objects.equals(hashOfRowComponents, other.hashOfRowComponents) && Objects.equals(shard, other.shard) && Arrays.equals(sweepConservative, other.sweepConservative);
        }

        @Override
        public int hashCode() {
            return Arrays.deepHashCode(new Object[]{ hashOfRowComponents, shard, sweepConservative });
        }

        @Override
        public int compareTo(SweepShardProgressRow o) {
            return ComparisonChain.start()
                .compare(this.hashOfRowComponents, o.hashOfRowComponents)
                .compare(this.shard, o.shard)
                .compare(this.sweepConservative, o.sweepConservative, UnsignedBytes.lexicographicalComparator())
                .result();
        }
    }

    public interface SweepShardProgressNamedColumnValue<T> extends NamedColumnValue<T> { /* */ }

    /**
     * <pre>
     * Column value description {
     *   type: Long;
     * }
     * </pre>
     */
    public static final class Value implements SweepShardProgressNamedColumnValue<Long> {
        private final Long value;

        public static Value of(Long value) {
            return new Value(value);
        }

        private Value(Long value) {
            this.value = value;
        }

        @Override
        public String getColumnName() {
            return "value";
        }

        @Override
        public String getShortColumnName() {
            return "v";
        }

        @Override
        public Long getValue() {
            return value;
        }

        @Override
        public byte[] persistValue() {
            byte[] bytes = EncodingUtils.encodeUnsignedVarLong(value);
            return CompressionUtils.compress(bytes, Compression.NONE);
        }

        @Override
        public byte[] persistColumnName() {
            return PtBytes.toCachedBytes("v");
        }

        public static final Hydrator<Value> BYTES_HYDRATOR = new Hydrator<Value>() {
            @Override
            public Value hydrateFromBytes(byte[] bytes) {
                bytes = CompressionUtils.decompress(bytes, Compression.NONE);
                return of(EncodingUtils.decodeUnsignedVarLong(bytes, 0));
            }
        };

        @Override
        public String toString() {
            return MoreObjects.toStringHelper(getClass().getSimpleName())
                .add("Value", this.value)
                .toString();
        }
    }

    public interface SweepShardProgressTrigger {
        public void putSweepShardProgress(Multimap<SweepShardProgressRow, ? extends SweepShardProgressNamedColumnValue<?>> newRows);
    }

    public static final class SweepShardProgressRowResult implements TypedRowResult {
        private final RowResult<byte[]> row;

        public static SweepShardProgressRowResult of(RowResult<byte[]> row) {
            return new SweepShardProgressRowResult(row);
        }

        private SweepShardProgressRowResult(RowResult<byte[]> row) {
            this.row = row;
        }

        @Override
        public SweepShardProgressRow getRowName() {
            return SweepShardProgressRow.BYTES_HYDRATOR.hydrateFromBytes(row.getRowName());
        }

        public static Function<SweepShardProgressRowResult, SweepShardProgressRow> getRowNameFun() {
            return new Function<SweepShardProgressRowResult, SweepShardProgressRow>() {
                @Override
                public SweepShardProgressRow apply(SweepShardProgressRowResult rowResult) {
                    return rowResult.getRowName();
                }
            };
        }

        public static Function<RowResult<byte[]>, SweepShardProgressRowResult> fromRawRowResultFun() {
            return new Function<RowResult<byte[]>, SweepShardProgressRowResult>() {
                @Override
                public SweepShardProgressRowResult apply(RowResult<byte[]> rowResult) {
                    return new SweepShardProgressRowResult(rowResult);
                }
            };
        }

        public boolean hasValue() {
            return row.getColumns().containsKey(PtBytes.toCachedBytes("v"));
        }

        public Long getValue() {
            byte[] bytes = row.getColumns().get(PtBytes.toCachedBytes("v"));
            if (bytes == null) {
                return null;
            }
            Value value = Value.BYTES_HYDRATOR.hydrateFromBytes(bytes);
            return value.getValue();
        }

        public static Function<SweepShardProgressRowResult, Long> getValueFun() {
            return new Function<SweepShardProgressRowResult, Long>() {
                @Override
                public Long apply(SweepShardProgressRowResult rowResult) {
                    return rowResult.getValue();
                }
            };
        }

        @Override
        public String toString() {
            return MoreObjects.toStringHelper(getClass().getSimpleName())
                .add("RowName", getRowName())
                .add("Value", getValue())
                .toString();
        }
    }

    public enum SweepShardProgressNamedColumn {
        VALUE {
            @Override
            public byte[] getShortName() {
                return PtBytes.toCachedBytes("v");
            }
        };

        public abstract byte[] getShortName();

        public static Function<SweepShardProgressNamedColumn, byte[]> toShortName() {
            return new Function<SweepShardProgressNamedColumn, byte[]>() {
                @Override
                public byte[] apply(SweepShardProgressNamedColumn namedColumn) {
                    return namedColumn.getShortName();
                }
            };
        }
    }

    public static ColumnSelection getColumnSelection(Collection<SweepShardProgressNamedColumn> cols) {
        return ColumnSelection.create(Collections2.transform(cols, SweepShardProgressNamedColumn.toShortName()));
    }

    public static ColumnSelection getColumnSelection(SweepShardProgressNamedColumn... cols) {
        return getColumnSelection(Arrays.asList(cols));
    }

    private static final Map<String, Hydrator<? extends SweepShardProgressNamedColumnValue<?>>> shortNameToHydrator =
            ImmutableMap.<String, Hydrator<? extends SweepShardProgressNamedColumnValue<?>>>builder()
                .put("v", Value.BYTES_HYDRATOR)
                .build();

    public Map<SweepShardProgressRow, Long> getValues(Collection<SweepShardProgressRow> rows) {
        Map<Cell, SweepShardProgressRow> cells = Maps.newHashMapWithExpectedSize(rows.size());
        for (SweepShardProgressRow row : rows) {
            cells.put(Cell.create(row.persistToBytes(), PtBytes.toCachedBytes("v")), row);
        }
        Map<Cell, byte[]> results = t.get(tableRef, cells.keySet());
        Map<SweepShardProgressRow, Long> ret = Maps.newHashMapWithExpectedSize(results.size());
        for (Entry<Cell, byte[]> e : results.entrySet()) {
            Long val = Value.BYTES_HYDRATOR.hydrateFromBytes(e.getValue()).getValue();
            ret.put(cells.get(e.getKey()), val);
        }
        return ret;
    }

    public void putValue(SweepShardProgressRow row, Long value) {
        put(ImmutableMultimap.of(row, Value.of(value)));
    }

    public void putValue(Map<SweepShardProgressRow, Long> map) {
        Map<SweepShardProgressRow, SweepShardProgressNamedColumnValue<?>> toPut = Maps.newHashMapWithExpectedSize(map.size());
        for (Entry<SweepShardProgressRow, Long> e : map.entrySet()) {
            toPut.put(e.getKey(), Value.of(e.getValue()));
        }
        put(Multimaps.forMap(toPut));
    }

    @Override
    public void put(Multimap<SweepShardProgressRow, ? extends SweepShardProgressNamedColumnValue<?>> rows) {
        t.useTable(tableRef, this);
        t.put(tableRef, ColumnValues.toCellValues(rows));
        for (SweepShardProgressTrigger trigger : triggers) {
            trigger.putSweepShardProgress(rows);
        }
    }

    public void deleteValue(SweepShardProgressRow row) {
        deleteValue(ImmutableSet.of(row));
    }

    public void deleteValue(Iterable<SweepShardProgressRow> rows) {
        byte[] col = PtBytes.toCachedBytes("v");
        Set<Cell> cells = Cells.cellsWithConstantColumn(Persistables.persistAll(rows), col);
        t.delete(tableRef, cells);
    }

    @Override
    public void delete(SweepShardProgressRow row) {
        delete(ImmutableSet.of(row));
    }

    @Override
    public void delete(Iterable<SweepShardProgressRow> rows) {
        List<byte[]> rowBytes = Persistables.persistAll(rows);
        Set<Cell> cells = Sets.newHashSetWithExpectedSize(rowBytes.size());
        cells.addAll(Cells.cellsWithConstantColumn(rowBytes, PtBytes.toCachedBytes("v")));
        t.delete(tableRef, cells);
    }

    public Optional<SweepShardProgressRowResult> getRow(SweepShardProgressRow row) {
        return getRow(row, allColumns);
    }

    public Optional<SweepShardProgressRowResult> getRow(SweepShardProgressRow row, ColumnSelection columns) {
        byte[] bytes = row.persistToBytes();
        RowResult<byte[]> rowResult = t.getRows(tableRef, ImmutableSet.of(bytes), columns).get(bytes);
        if (rowResult == null) {
            return Optional.empty();
        } else {
            return Optional.of(SweepShardProgressRowResult.of(rowResult));
        }
    }

    @Override
    public List<SweepShardProgressRowResult> getRows(Iterable<SweepShardProgressRow> rows) {
        return getRows(rows, allColumns);
    }

    @Override
    public List<SweepShardProgressRowResult> getRows(Iterable<SweepShardProgressRow> rows, ColumnSelection columns) {
        SortedMap<byte[], RowResult<byte[]>> results = t.getRows(tableRef, Persistables.persistAll(rows), columns);
        List<SweepShardProgressRowResult> rowResults = Lists.newArrayListWithCapacity(results.size());
        for (RowResult<byte[]> row : results.values()) {
            rowResults.add(SweepShardProgressRowResult.of(row));
        }
        return rowResults;
    }

    @Override
    public List<SweepShardProgressNamedColumnValue<?>> getRowColumns(SweepShardProgressRow row) {
        return getRowColumns(row, allColumns);
    }

    @Override
    public List<SweepShardProgressNamedColumnValue<?>> getRowColumns(SweepShardProgressRow row, ColumnSelection columns) {
        byte[] bytes = row.persistToBytes();
        RowResult<byte[]> rowResult = t.getRows(tableRef, ImmutableSet.of(bytes), columns).get(bytes);
        if (rowResult == null) {
            return ImmutableList.of();
        } else {
            List<SweepShardProgressNamedColumnValue<?>> ret = Lists.newArrayListWithCapacity(rowResult.getColumns().size());
            for (Entry<byte[], byte[]> e : rowResult.getColumns().entrySet()) {
                ret.add(shortNameToHydrator.get(PtBytes.toString(e.getKey())).hydrateFromBytes(e.getValue()));
            }
            return ret;
        }
    }

    @Override
    public Multimap<SweepShardProgressRow, SweepShardProgressNamedColumnValue<?>> getRowsMultimap(Iterable<SweepShardProgressRow> rows) {
        return getRowsMultimapInternal(rows, allColumns);
    }

    @Override
    public Multimap<SweepShardProgressRow, SweepShardProgressNamedColumnValue<?>> getRowsMultimap(Iterable<SweepShardProgressRow> rows, ColumnSelection columns) {
        return getRowsMultimapInternal(rows, columns);
    }

    private Multimap<SweepShardProgressRow, SweepShardProgressNamedColumnValue<?>> getRowsMultimapInternal(Iterable<SweepShardProgressRow> rows, ColumnSelection columns) {
        SortedMap<byte[], RowResult<byte[]>> results = t.getRows(tableRef, Persistables.persistAll(rows), columns);
        return getRowMapFromRowResults(results.values());
    }

    private static Multimap<SweepShardProgressRow, SweepShardProgressNamedColumnValue<?>> getRowMapFromRowResults(Collection<RowResult<byte[]>> rowResults) {
        Multimap<SweepShardProgressRow, SweepShardProgressNamedColumnValue<?>> rowMap = ArrayListMultimap.create();
        for (RowResult<byte[]> result : rowResults) {
            SweepShardProgressRow row = SweepShardProgressRow.BYTES_HYDRATOR.hydrateFromBytes(result.getRowName());
            for (Entry<byte[], byte[]> e : result.getColumns().entrySet()) {
                rowMap.put(row, shortNameToHydrator.get(PtBytes.toString(e.getKey())).hydrateFromBytes(e.getValue()));
            }
        }
        return rowMap;
    }

    @Override
    public Map<SweepShardProgressRow, BatchingVisitable<SweepShardProgressNamedColumnValue<?>>> getRowsColumnRange(Iterable<SweepShardProgressRow> rows, BatchColumnRangeSelection columnRangeSelection) {
        Map<byte[], BatchingVisitable<Map.Entry<Cell, byte[]>>> results = t.getRowsColumnRange(tableRef, Persistables.persistAll(rows), columnRangeSelection);
        Map<SweepShardProgressRow, BatchingVisitable<SweepShardProgressNamedColumnValue<?>>> transformed = Maps.newHashMapWithExpectedSize(results.size());
        for (Entry<byte[], BatchingVisitable<Map.Entry<Cell, byte[]>>> e : results.entrySet()) {
            SweepShardProgressRow row = SweepShardProgressRow.BYTES_HYDRATOR.hydrateFromBytes(e.getKey());
            BatchingVisitable<SweepShardProgressNamedColumnValue<?>> bv = BatchingVisitables.transform(e.getValue(), result -> {
                return shortNameToHydrator.get(PtBytes.toString(result.getKey().getColumnName())).hydrateFromBytes(result.getValue());
            });
            transformed.put(row, bv);
        }
        return transformed;
    }

    @Override
    public Iterator<Map.Entry<SweepShardProgressRow, SweepShardProgressNamedColumnValue<?>>> getRowsColumnRange(Iterable<SweepShardProgressRow> rows, ColumnRangeSelection columnRangeSelection, int batchHint) {
        Iterator<Map.Entry<Cell, byte[]>> results = t.getRowsColumnRange(getTableRef(), Persistables.persistAll(rows), columnRangeSelection, batchHint);
        return Iterators.transform(results, e -> {
            SweepShardProgressRow row = SweepShardProgressRow.BYTES_HYDRATOR.hydrateFromBytes(e.getKey().getRowName());
            SweepShardProgressNamedColumnValue<?> colValue = shortNameToHydrator.get(PtBytes.toString(e.getKey().getColumnName())).hydrateFromBytes(e.getValue());
            return Maps.immutableEntry(row, colValue);
        });
    }

    @Override
    public Map<SweepShardProgressRow, Iterator<SweepShardProgressNamedColumnValue<?>>> getRowsColumnRangeIterator(Iterable<SweepShardProgressRow> rows, BatchColumnRangeSelection columnRangeSelection) {
        Map<byte[], Iterator<Map.Entry<Cell, byte[]>>> results = t.getRowsColumnRangeIterator(tableRef, Persistables.persistAll(rows), columnRangeSelection);
        Map<SweepShardProgressRow, Iterator<SweepShardProgressNamedColumnValue<?>>> transformed = Maps.newHashMapWithExpectedSize(results.size());
        for (Entry<byte[], Iterator<Map.Entry<Cell, byte[]>>> e : results.entrySet()) {
            SweepShardProgressRow row = SweepShardProgressRow.BYTES_HYDRATOR.hydrateFromBytes(e.getKey());
            Iterator<SweepShardProgressNamedColumnValue<?>> bv = Iterators.transform(e.getValue(), result -> {
                return shortNameToHydrator.get(PtBytes.toString(result.getKey().getColumnName())).hydrateFromBytes(result.getValue());
            });
            transformed.put(row, bv);
        }
        return transformed;
    }

    private ColumnSelection optimizeColumnSelection(ColumnSelection columns) {
        if (columns.allColumnsSelected()) {
            return allColumns;
        }
        return columns;
    }

    public BatchingVisitableView<SweepShardProgressRowResult> getAllRowsUnordered() {
        return getAllRowsUnordered(allColumns);
    }

    public BatchingVisitableView<SweepShardProgressRowResult> getAllRowsUnordered(ColumnSelection columns) {
        return BatchingVisitables.transform(t.getRange(tableRef, RangeRequest.builder()
                .retainColumns(optimizeColumnSelection(columns)).build()),
                new Function<RowResult<byte[]>, SweepShardProgressRowResult>() {
            @Override
            public SweepShardProgressRowResult apply(RowResult<byte[]> input) {
                return SweepShardProgressRowResult.of(input);
            }
        });
    }

    @Override
    public List<String> findConstraintFailures(Map<Cell, byte[]> writes,
                                               ConstraintCheckingTransaction transaction,
                                               AtlasDbConstraintCheckingMode constraintCheckingMode) {
        return ImmutableList.of();
    }

    @Override
    public List<String> findConstraintFailuresNoRead(Map<Cell, byte[]> writes,
                                                     AtlasDbConstraintCheckingMode constraintCheckingMode) {
        return ImmutableList.of();
    }

    /**
     * This exists to avoid unused import warnings
     * {@link AbortingVisitor}
     * {@link AbortingVisitors}
     * {@link ArrayListMultimap}
     * {@link Arrays}
     * {@link AssertUtils}
     * {@link AtlasDbConstraintCheckingMode}
     * {@link AtlasDbDynamicMutablePersistentTable}
     * {@link AtlasDbMutablePersistentTable}
     * {@link AtlasDbNamedMutableTable}
     * {@link AtlasDbNamedPersistentSet}
     * {@link BatchColumnRangeSelection}
     * {@link BatchingVisitable}
     * {@link BatchingVisitableView}
     * {@link BatchingVisitables}
     * {@link BiFunction}
     * {@link Bytes}
     * {@link Callable}
     * {@link Cell}
     * {@link Cells}
     * {@link Collection}
     * {@link Collections2}
     * {@link ColumnRangeSelection}
     * {@link ColumnRangeSelections}
     * {@link ColumnSelection}
     * {@link ColumnValue}
     * {@link ColumnValues}
     * {@link ComparisonChain}
     * {@link Compression}
     * {@link CompressionUtils}
     * {@link ConstraintCheckingTransaction}
     * {@link Descending}
     * {@link EncodingUtils}
     * {@link Entry}
     * {@link EnumSet}
     * {@link Function}
     * {@link Generated}
     * {@link HashMultimap}
     * {@link HashSet}
     * {@link Hashing}
     * {@link Hydrator}
     * {@link ImmutableGetRangesQuery}
     * {@link ImmutableList}
     * {@link ImmutableMap}
     * {@link ImmutableMultimap}
     * {@link ImmutableSet}
     * {@link InvalidProtocolBufferException}
     * {@link IterableView}
     * {@link Iterables}
     * {@link Iterator}
     * {@link Iterators}
     * {@link Joiner}
     * {@link List}
     * {@link Lists}
     * {@link Map}
     * {@link Maps}
     * {@link MoreObjects}
     * {@link Multimap}
     * {@link Multimaps}
     * {@link NamedColumnValue}
     * {@link Namespace}
     * {@link Nullable}
     * {@link Objects}
     * {@link Optional}
     * {@link Persistable}
     * {@link Persistables}
     * {@link Prefix}
     * {@link PtBytes}
     * {@link RangeRequest}
     * {@link RowResult}
     * {@link Set}
     * {@link Sets}
     * {@link Sha256Hash}
     * {@link SortedMap}
     * {@link Stream}
     * {@link Supplier}
     * {@link TableReference}
     * {@link Throwables}
     * {@link TimeUnit}
     * {@link Transaction}
     * {@link TypedRowResult}
     * {@link UUID}
     * {@link UnsignedBytes}
     * {@link ValueType}
     */
    static String __CLASS_HASH = "XVjeSk48z1yhodAQP8wW2Q==";
}
