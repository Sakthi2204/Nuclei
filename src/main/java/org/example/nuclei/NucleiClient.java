package org.example.nuclei;

import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import org.example.nuclei.NucleiApiGrpc;
import org.example.nuclei.ScanRequest;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.List;
import java.util.ArrayList;
import java.util.concurrent.*;

public class NucleiClient {

    private static final String URL_FILE_PATH = "C:\\Users\\SAKTHIPRIYA\\nuclei\\input_urls.txt";
    private static final List<String> TEMPLATES = List.of("misconfiguration", "exposures", "cves", "vulnerabilities", "ssl", "technologies");
    private static final int THREAD_POOL_SIZE = 6;
    private static final int TASK_TIMEOUT_SECONDS = 360;  // Timeout for each task (per URL scan)

    public static void main(String[] args) {
        // Create the gRPC channel
        ManagedChannel channel = ManagedChannelBuilder.forAddress("localhost", 8555)
                .usePlaintext()
                .build();

        NucleiApiGrpc.NucleiApiBlockingStub stub = NucleiApiGrpc.newBlockingStub(channel);
        List<String> urls = readUrlsFromFile(URL_FILE_PATH);

        if (urls.isEmpty()) {
            System.out.println("No URLs found in the file.");
            shutdownChannel(channel);
            return;
        }

        // Create a thread pool to parallelize scans
        ExecutorService executorService = Executors.newFixedThreadPool(THREAD_POOL_SIZE);

        // Submit scan tasks and track with Future objects
        List<Future<?>> futures = new ArrayList<>();
        for (String url : urls) {
            Future<?> future = executorService.submit(() -> {
                try {
                    scanUrl(stub, url);
                } catch (InterruptedException e) {
                    System.err.println("Scan task interrupted for URL: " + url);
                    Thread.currentThread().interrupt();  // Re-interrupt the thread to propagate interruption
                }
            });
            futures.add(future);
        }

        // Handle each task individually with timeout
        for (Future<?> future : futures) {
            try {
                future.get(TASK_TIMEOUT_SECONDS, TimeUnit.SECONDS);  // Wait up to the task timeout
            } catch (TimeoutException e) {
                System.err.println("A scan task timed out and will be cancelled.");
                future.cancel(true);  // Cancel the task if it exceeds the timeout
            } catch (InterruptedException e) {
                System.err.println("Main thread was interrupted while waiting for a task.");
                Thread.currentThread().interrupt();
            } catch (ExecutionException e) {
                System.err.println("An error occurred during the scan: " + e.getMessage());
            }
        }

        // Shutdown thread pool after all tasks are handled
        executorService.shutdown();
        try {
            // Wait for tasks to terminate
            if (!executorService.awaitTermination(60, TimeUnit.SECONDS)) {
                System.out.println("Forcing shutdown of remaining tasks...");
                executorService.shutdownNow();
            }
        } catch (InterruptedException e) {
            System.err.println("Main thread interrupted during ExecutorService shutdown.");
            executorService.shutdownNow();
            Thread.currentThread().interrupt();
        }

        // Only shutdown the channel after the thread pool has completed
        shutdownChannel(channel);
    }

    private static void scanUrl(NucleiApiGrpc.NucleiApiBlockingStub stub, String url) throws InterruptedException {
        for (String template : TEMPLATES) {
            if (Thread.currentThread().isInterrupted()) {
                throw new InterruptedException("Thread interrupted, stopping further scans.");
            }

            ScanRequest request = ScanRequest.newBuilder()
                    .addTargets(url)
                    .addTemplates(template)
                    .setAutomaticScan(true)
                    .build();

            try {
                stub.scan(request).forEachRemaining(scanResult -> {
                    System.out.println(scanResult.toString());
                });
            } catch (Exception e) {
                System.err.println("Error during scan for URL " + url + " with template " + template + ": " + e.getMessage());
            }
        }
    }

    private static List<String> readUrlsFromFile(String filePath) {
        List<String> urls = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = reader.readLine()) != null) {
                urls.add(line.trim());
            }
        } catch (IOException e) {
            System.err.println("Error reading URLs from file: " + e.getMessage());
        }
        return urls;
    }

    private static void shutdownChannel(ManagedChannel channel) {
        try {
            if (!channel.isShutdown()) {
                channel.shutdown().awaitTermination(5, TimeUnit.SECONDS);
            }
        } catch (InterruptedException e) {
            System.err.println("Error shutting down channel: " + e.getMessage());
        }
    }
}
