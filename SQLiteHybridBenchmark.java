package org.example;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

// 외부 클래스 임포트
import org.example.SQLiteConnection; // MySQLConnection 대신 SQLiteConnection 사용
import org.example.HybridCipher;

public class SQLiteHybridBenchmark {

    // 워밍업 횟수를 3회로 증가시켜 JVM 최적화를 돕습니다.
    private static final int WARMUP_ITERATIONS = 50;
    // 실제 벤치마크 횟수를 5회로 증가시켜 더 안정적인 평균값을 얻습니다.
    private static final int BENCHMARK_ITERATIONS = 1000;
    private static final int MAX_IMAGE_SIZE_BYTES = 1048576; // 1MB

    public static void main(String[] args) {
        System.out.println("SQLite 하이브리드 암호화/복호화 벤치마크를 시작합니다...");

        try {
            // RSA 키 페어 생성은 가장 비싼 작업이므로, 전체 벤치마크 동안 한 번만 수행합니다.
            // HybridCipher 인스턴스를 미리 생성합니다.
            HybridCipher hybridCipher = new HybridCipher();

            benchmark(hybridCipher); // public으로 변경된 benchmark() 메서드 호출

        } catch (Exception e) {
            System.err.println("벤치마크 실행 중 치명적인 오류가 발생했습니다: " + e.getMessage());
            e.printStackTrace();
        }
    }

    public static void benchmark(HybridCipher hybridCipher) throws Exception {
        System.out.println("워밍업 단계: " + WARMUP_ITERATIONS + "회 반복.");
        System.out.println("벤치마크 단계: " + BENCHMARK_ITERATIONS + "회 반복.");

        // --- 워밍업 단계 ---
        for (int i = 0; i < WARMUP_ITERATIONS; i++) {
            runSingleIteration(hybridCipher, false); // 측정하지 않음
            if (i == 0) {
                System.out.println("초기 워밍업 실행 완료. 추가 워밍업 반복이 코드 최적화를 진행합니다.");
            }
        }
        System.out.println("워밍업 단계 완료.\n");

        System.out.println("--- 실제 벤치마크 시작 ---");

        // --- 실제 벤치마크 단계 ---
        long totalEncryptionTimeSum = 0;
        long totalDecryptionTimeSum = 0;
        long totalMemoryUsageSum = 0;
        int totalProcessedImages = 0;

        MemoryMXBean memoryBean = ManagementFactory.getMemoryMXBean();
        System.gc();
        long initialOverallHeapMemory = memoryBean.getHeapMemoryUsage().getUsed();

        for (int i = 0; i < BENCHMARK_ITERATIONS; i++) {
            System.out.println("벤치마크 반복 " + (i + 1) + "회차...");

            long currentIterationEncryptionTime = 0;
            long currentIterationDecryptionTime = 0;
            long currentIterationMemoryUsage = 0;
            int currentIterationImagesCount = 0;

            // SQLiteConnection을 사용하여 데이터베이스에 연결
            try (Connection conn = SQLiteConnection.connect();
                 PreparedStatement stmt = conn.prepareStatement("SELECT 튜플 이름 FROM 테이블 이름");
                 ResultSet rs = stmt.executeQuery()) {

                // 쿼리 결과의 모든 행을 처리합니다. (외부에서 삽입된 모든 이미지를 처리함)
                while (rs.next()) {
                    try (InputStream imageStream = rs.getBinaryStream("튜플 이름");
                         ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {

                        byte[] buffer = new byte[4096];
                        int bytesRead;

                        // InputStream이 null이 아닌지 확인하여 SQLite 데이터 읽기 처리
                        if (imageStream != null) {
                            while ((bytesRead = imageStream.read(buffer)) != -1) {
                                outputStream.write(buffer, 0, bytesRead);
                            }
                        }

                        byte[] imageData = outputStream.toByteArray();

                        if (imageData.length > MAX_IMAGE_SIZE_BYTES) {
                            System.out.println("경고: 이미지가 너무 커서 건너뜁니다 (크기: " + imageData.length + " 바이트).");
                            continue;
                        }

                        long beforeOperationMemory = memoryBean.getHeapMemoryUsage().getUsed();

                        // 암호화
                        long startTimeEncryption = System.nanoTime();
                        byte[] encryptedData = hybridCipher.encrypt(imageData);
                        long encryptionTime = System.nanoTime() - startTimeEncryption;
                        currentIterationEncryptionTime += encryptionTime;

                        // 복호화
                        long startTimeDecryption = System.nanoTime();
                        byte[] decryptedData = hybridCipher.decrypt(encryptedData);
                        long decryptionTime = System.nanoTime() - startTimeDecryption;
                        currentIterationDecryptionTime += decryptionTime;

                        long afterOperationMemory = memoryBean.getHeapMemoryUsage().getUsed();
                        currentIterationMemoryUsage += Math.max(0, afterOperationMemory - beforeOperationMemory);
                        currentIterationImagesCount++;
                    }
                }
            } catch (SQLException e) {
                System.err.println("데이터베이스 작업 중 오류 발생 (SQLite 연결/쿼리 확인 필요): " + e.getMessage());
                e.printStackTrace();
            }

            totalEncryptionTimeSum += currentIterationEncryptionTime;
            totalDecryptionTimeSum += currentIterationDecryptionTime;
            totalMemoryUsageSum += currentIterationMemoryUsage;
            totalProcessedImages = currentIterationImagesCount;
        }

        // --- 최종 결과 출력 ---
        System.gc();
        long finalOverallHeapMemory = memoryBean.getHeapMemoryUsage().getUsed();
        long overallMemoryIncrease = Math.max(0, finalOverallHeapMemory - initialOverallHeapMemory);

        System.out.println("\n--- 최종 SQLite 하이브리드 벤치마크 평균 결과 ---");
        System.out.printf("처리된 이미지 수 (각 회차당): %d%n", totalProcessedImages);
        System.out.printf("평균 암호화 시간 (회차당): %.3f ms%n", (double) totalEncryptionTimeSum / BENCHMARK_ITERATIONS / 1_000_000.0);
        System.out.printf("평균 복호화 시간 (회차당): %.3f ms%n", (double) totalDecryptionTimeSum / BENCHMARK_ITERATIONS / 1_000_000.0);
        System.out.printf("평균 메모리 사용량 변화 (작업당): %.3f MB%n", (double) totalMemoryUsageSum / (BENCHMARK_ITERATIONS * totalProcessedImages) / (1024.0 * 1024.0));
        System.out.printf("벤치마크 전체 동안의 총 힙 메모리 사용량 증가: %.3f MB%n", (double) overallMemoryIncrease / (1024.0 * 1024.0));
    }

    private static void runSingleIteration(HybridCipher hybridCipher, boolean log) throws Exception {
        // SQLiteConnection을 사용하여 데이터베이스에 연결
        try (Connection conn = SQLiteConnection.connect();
             PreparedStatement stmt = conn.prepareStatement("SELECT 튜플 이름 FROM 테이블 이름");
             ResultSet rs = stmt.executeQuery()) {

            while (rs.next()) {
                try (InputStream imageStream = rs.getBinaryStream("튜플 이름");
                     ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {

                    byte[] buffer = new byte[4096];
                    int bytesRead;

                    if (imageStream != null) {
                        while ((bytesRead = imageStream.read(buffer)) != -1) {
                            outputStream.write(buffer, 0, bytesRead);
                        }
                    }

                    byte[] imageData = outputStream.toByteArray();

                    if (imageData.length > MAX_IMAGE_SIZE_BYTES) {
                        continue;
                    }

                    byte[] encryptedData = hybridCipher.encrypt(imageData);
                    byte[] decryptedData = hybridCipher.decrypt(encryptedData);
                }
            }
        }
    }
}
