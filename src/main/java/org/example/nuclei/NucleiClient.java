package org.example.nuclei;

import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import org.example.nuclei.NucleiApiGrpc;
import org.example.nuclei.ScanRequest;
import org.example.nuclei.ScanResult;

public class NucleiClient {
    public static void main(String[] args) {
        // Create a channel to communicate with the server
        ManagedChannel channel = ManagedChannelBuilder.forAddress("localhost", 8555)
                .usePlaintext()
                .build();

        // Create a stub to interact with the Nuclei API service
        NucleiApiGrpc.NucleiApiBlockingStub stub = NucleiApiGrpc.newBlockingStub(channel);

        // Build a ScanRequest
        ScanRequest request = ScanRequest.newBuilder()
                .addTargets("http://ulc.wa.gov/")
                .addTemplates("Exposures")
                .setAutomaticScan(true)
                .addSeverities("high")
                .build();

        // Send the request and receive a stream of responses
        stub.scan(request).forEachRemaining(scanResult -> {
            System.out.println("Scan result for target: " + scanResult.getHost());
            System.out.println("Template: " + scanResult.getTemplate());
            System.out.println("Timestamp: " + scanResult.getTimestamp());
        });

        // Shutdown the channel
        channel.shutdown();
    }
}
