/*
 * (c) Copyright 2024 Palantir Technologies Inc. All rights reserved.
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

import static org.assertj.core.api.Assertions.assertThat;

import com.palantir.docker.compose.DockerComposeExtension;
import com.palantir.docker.compose.configuration.DockerComposeFiles;
import com.palantir.docker.compose.connection.waiting.SuccessOrFailure;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicBoolean;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

public class AntithesisDockerTest {

    @RegisterExtension
    public static DockerComposeExtension dockerComposeExtension = DockerComposeExtension.builder()
            .files(DockerComposeFiles.from("var/docker-compose.yml"))
            .waitingForService("workload-server", container -> {
                try {
                    return SuccessOrFailure.fromBoolean(container.state().isHealthy(), "Some container is not up");
                } catch (IOException | InterruptedException e) {
                    throw new RuntimeException(e);
                }
            })
            .build();

    @Test
    public void workloadServerHasInitializedTransactionStoreFactorySuccessfully() throws IOException {
        AtomicBoolean hasRunSuccessfully = new AtomicBoolean(false);

        String successMessage = "Finished running desired workflows successfully";
        String failureMessage = "Workflow will now exit.";

        Awaitility.await()
                .atMost(Duration.ofMinutes(5))
                .pollInterval(Duration.ofSeconds(10))
                .until(() -> {
                    OutputStream logStream = new ByteArrayOutputStream();
                    dockerComposeExtension
                            .dockerComposeExecutable()
                            .execute("logs", "workload-server")
                            .getInputStream()
                            .transferTo(logStream);

                    String logs = logStream.toString();

                    if (logs.contains(successMessage)) {
                        hasRunSuccessfully.set(true);
                        return true;
                    }

                    return logs.contains(failureMessage);
                });

        assertThat(hasRunSuccessfully.get()).isTrue();
    }
}