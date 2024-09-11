package org.example.nuclei;

import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import org.example.nuclei.NucleiApiGrpc;
import org.example.nuclei.ScanRequest;
import org.example.nuclei.ScanResult;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class NucleiClient {
    private static final String URL_FILE_PATH = "C:\\Users\\SAKTHIPRIYA\\nuclei\\input_urls.txt"; // Path to your URL file
    private static final List<String> TEMPLATES = List.of("misconfiguration", "exposures", "cves","vulnerabilities","ssl","technologies"); // Add all your templates here

    public static void main(String[] args) {
        // Create a channel to communicate with the server
        ManagedChannel channel = ManagedChannelBuilder.forAddress("localhost", 8555)
                .usePlaintext()
                .build();

        NucleiApiGrpc.NucleiApiBlockingStub stub = NucleiApiGrpc.newBlockingStub(channel);

        List<String> urls = readUrlsFromFile(URL_FILE_PATH);

        if (urls.isEmpty()) {
            System.out.println("No URLs found in the file.");
            return;
        }

        for (String url : urls) {
            for (String template : TEMPLATES) {
                ScanRequest request = ScanRequest.newBuilder()
                        .addTargets(url)
                        .addTemplates(template)
                        .setAutomaticScan(true)
                        .build();

                stub.scan(request).forEachRemaining(scanResult -> {
                    System.out.println(scanResult.toString());
                    //System.out.println("Scan result for target: " + scanResult.getHost());
                    //System.out.println("Template: " + scanResult.getTemplate());
                    //System.out.println("Timestamp: " + scanResult.getTimestamp());
                });
            }
        }

        // Shutdown the channel
        channel.shutdown();
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
}



