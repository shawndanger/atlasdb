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

package com.palantir.lock.watch;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.annotation.JsonTypeName;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.palantir.atlasdb.encoding.PtBytes;
import com.palantir.conjure.java.serialization.ObjectMappers;
import com.palantir.lock.LockDescriptor;
import com.palantir.lock.StringLockDescriptor;
import com.palantir.lock.v2.LockToken;
import com.palantir.logsafe.exceptions.SafeIllegalArgumentException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import org.immutables.value.Value;
import org.junit.Test;

public class LockEventTest {
    private static final String BASE = "src/test/resources/lock-event-wire-format/";
    private static final boolean REWRITE_JSON_BLOBS = true;

    private static final LockDescriptor LOCK_1 = StringLockDescriptor.of("abc");
    private static final LockDescriptor LOCK_2 = StringLockDescriptor.of("def");
    private static final LockDescriptor LOCK_3 = StringLockDescriptor.of("ghi");
    private static final LockDescriptor LOCK_4 = StringLockDescriptor.of("jkl");
    private static final long SEQUENCE = 10L;
    private static final LockToken LOCK_TOKEN = LockToken.of(new UUID(1337, 42));
    private static final Set<LockDescriptor> LOCK_SET = ImmutableSet.of(LOCK_1, LOCK_2, LOCK_3, LOCK_4);
    private static final OldLockEvent OLD_LOCK_EVENT = ImmutableOldLockEvent.builder()
            .sequence(SEQUENCE)
            .lockDescriptors(LOCK_SET)
            .lockToken(LOCK_TOKEN)
            .build();
    private static final LockEvent BASELINE_LOCK_EVENT = ImmutableLockEvent.builder()
            .sequence(SEQUENCE)
            .lockDescriptors(LOCK_SET)
            .lockToken(LOCK_TOKEN)
            .build();
    private static final byte[] BYTES_OLD = PtBytes.toBytes("old");
    private static final byte[] BYTES_NEW = PtBytes.toBytes("new");
    private static final byte[] BYTES_DELETED = PtBytes.toBytes("deleted");
    private static final byte[] BYTES_CREATED = PtBytes.toBytes("created");
    private static final List<ChangeMetadata> CHANGE_METADATA_LIST = ImmutableList.of(
            ChangeMetadata.unchanged(),
            ChangeMetadata.updated(BYTES_OLD, BYTES_NEW),
            ChangeMetadata.deleted(BYTES_DELETED),
            ChangeMetadata.created(BYTES_CREATED));
    private static final LockRequestMetadata LOCK_REQUEST_METADATA = LockRequestMetadata.of(ImmutableMap.of(
            LOCK_1,
            CHANGE_METADATA_LIST.get(0),
            LOCK_2,
            CHANGE_METADATA_LIST.get(1),
            LOCK_3,
            CHANGE_METADATA_LIST.get(2),
            LOCK_4,
            CHANGE_METADATA_LIST.get(3)));

    // TimeLock (Server) serializes and AtlasDB (Client) deserializes.
    // These are the respective mappers used internally by Conjure.
    private static final ObjectMapper SERIALIZATION_MAPPER =
            ObjectMappers.newServerObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
    private static final ObjectMapper DESERIALIZATION_MAPPER =
            ObjectMappers.newClientObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
    // This mapper is used to ensure that two JSONs are equal excluding indentation
    private static final ObjectMapper VERIFYING_MAPPER = new ObjectMapper();

    @Test
    public void oldLockEventIsBaseline() {
        assertSerializedEquals(OLD_LOCK_EVENT, "baseline");
        assertDeserializedEquals("baseline", OLD_LOCK_EVENT, OldLockEvent.class);
    }

    @Test
    public void serializedFormatIsUnchangedForAbsentMetadata() {
        assertSerializedEquals(BASELINE_LOCK_EVENT, "baseline");
        assertDeserializedEquals("baseline", BASELINE_LOCK_EVENT, LockEvent.class);
    }

    @Test
    public void serializesMetadataIfPresent() {
        LockEvent lockEventWithMetadata =
                ImmutableLockEvent.copyOf(BASELINE_LOCK_EVENT).withMetadata(LOCK_REQUEST_METADATA);
        assertSerializedEquals(lockEventWithMetadata, "baseline-with-metadata");
        assertDeserializedEquals("baseline-with-metadata", lockEventWithMetadata, LockEvent.class);
    }

    @Test
    public void serializesAsLockWatchEventWithMetadata() {
        LockWatchEvent asLockWatchEvent =
                ImmutableLockEvent.copyOf(BASELINE_LOCK_EVENT).withMetadata(LOCK_REQUEST_METADATA);
        assertSerializedEquals(asLockWatchEvent, "baseline-with-metadata");
        assertDeserializedEquals("baseline-with-metadata", asLockWatchEvent, LockWatchEvent.class);
    }

    @Test
    public void serializesEmptyMetadataMap() {
        LockEvent lockEventWithMetadata =
                ImmutableLockEvent.copyOf(BASELINE_LOCK_EVENT).withMetadata(LockRequestMetadata.of(ImmutableMap.of()));
        assertSerializedEquals(lockEventWithMetadata, "baseline-empty-metadata-map");
        assertDeserializedEquals("baseline-empty-metadata-map", lockEventWithMetadata, LockEvent.class);
    }

    // This property should be guaranteed by the Conjure spec
    @Test
    public void oldClientIgnoresMetadata() {
        assertDeserializedEquals("baseline-with-metadata", OLD_LOCK_EVENT, OldLockEvent.class);
    }

    @Test
    public void serializesSparseMetadata() {
        List<LockDescriptor> tenLocks = IntStream.range(0, 10)
                .mapToObj(Integer::toString)
                .map(StringLockDescriptor::of)
                .collect(Collectors.toList());
        // Unique metadata on less than 50% of locks
        LockRequestMetadata sparseMetadata = LockRequestMetadata.of(ImmutableMap.of(
                tenLocks.get(0), ChangeMetadata.created(PtBytes.toBytes(0)),
                tenLocks.get(4), ChangeMetadata.created(PtBytes.toBytes(4)),
                tenLocks.get(9), ChangeMetadata.created(PtBytes.toBytes(9)),
                tenLocks.get(5), ChangeMetadata.created(PtBytes.toBytes(5))));
        LockEvent lockEventWithSparseMetadata = ImmutableLockEvent.builder()
                .lockDescriptors(tenLocks)
                .sequence(SEQUENCE)
                .lockToken(LOCK_TOKEN)
                .metadata(sparseMetadata)
                .build();

        assertSerializedEquals(lockEventWithSparseMetadata, "sparse-metadata");
        assertDeserializedEquals("sparse-metadata", lockEventWithSparseMetadata, LockEvent.class);
    }

    @Test
    public void shufflingLockDescriptorsOnTheWireIsDetectedByClient() {
        assertThatThrownBy(() ->
                        // The order of the lock descriptors in this JSON file is swapped
                        DESERIALIZATION_MAPPER.readValue(
                                Files.readString(getJsonPath("shuffled-locks")), LockEvent.class))
                .rootCause()
                .isInstanceOf(SafeIllegalArgumentException.class)
                .hasMessageStartingWith("Key list integrity check failed");
    }

    private static <T> void assertSerializedEquals(T object, String jsonFileName) {
        try {
            Path path = getJsonPath(jsonFileName);
            if (REWRITE_JSON_BLOBS) {
                SERIALIZATION_MAPPER.writeValue(path.toFile(), object);
            }
            String serialized = SERIALIZATION_MAPPER.writeValueAsString(object);
            assertThat(VERIFYING_MAPPER.readTree(serialized))
                    .as("Serialization yields semantically identical JSON representation")
                    .isEqualTo(VERIFYING_MAPPER.readTree(Files.readString(path)));
        } catch (Throwable t) {
            throw new RuntimeException(t);
        }
    }

    private static <T> void assertDeserializedEquals(String jsonFileName, T object, Class<T> clazz) {
        try {
            assertThat(DESERIALIZATION_MAPPER.readValue(Files.readString(getJsonPath(jsonFileName)), clazz))
                    .as("Deserialization yields identical object")
                    .isEqualTo(object);
        } catch (Throwable t) {
            throw new RuntimeException(t);
        }
    }

    // This is a copy of the LockEvent class before metadata was added
    @Value.Immutable
    @JsonSerialize(as = ImmutableOldLockEvent.class)
    @JsonDeserialize(as = ImmutableOldLockEvent.class)
    @JsonTypeInfo(use = JsonTypeInfo.Id.NAME, property = "type")
    @JsonTypeName(LockEvent.TYPE)
    public interface OldLockEvent {
        long sequence();

        Set<LockDescriptor> lockDescriptors();

        LockToken lockToken();
    }

    private static Path getJsonPath(String jsonFileName) {
        return Paths.get(BASE + jsonFileName + ".json");
    }
}
