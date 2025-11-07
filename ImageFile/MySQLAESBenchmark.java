package org.example; // 패키지 이름을 org.example로 통일하여 사용합니다.

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.util.ArrayList;
import java.util.List;
import java.util.Arrays; // 데이터 검증을 위해 사용

// org.example 패키지에 있는 MySQLConnection 및 AESCipher 클래스 임포트를 가정합니다.

public class MySQLAESBenchmark {

    private static final int WARMUP_ITERATIONS = 50;      // 워밍업 반복 횟수 조정 (JIT 컴파일에 적합한 수준)
    private static final int BENCHMARK_ITERATIONS = 1000;  // 실제 벤치마크 반복 횟수 조정 (빠른 테스트를 위해)
    private static final String SELECT_SQL = "SELECT 튜플 이름 FROM 테이블 이름";
    private static final int MAX_IMAGE_SIZE_BYTES = 1048576; // 1 MB (너무 큰 이미지를 건너뛰기 위함)

    public static void main(String[] args) {
        try {
            benchmark();
        } catch (Exception e) {
            System.err.println("벤치마크 실행 중 오류가 발생했습니다: " + e.getMessage());
            e.printStackTrace();
        }
    }

    public static void benchmark() throws Exception {
        System.out.println("MySQL AES 암호화/복호화 벤치마크를 시작합니다...");
        System.out.printf("워밍업 단계: %d회 반복.\n", WARMUP_ITERATIONS);
        System.out.printf("벤치마크 단계: %d회 반복.\n", BENCHMARK_ITERATIONS);
        System.out.printf("1MB(%d bytes)를 초과하는 데이터는 건너뜁니다.\n", MAX_IMAGE_SIZE_BYTES);

        List<Long> encryptionTimes = new ArrayList<>();
        List<Long> decryptionTimes = new ArrayList<>();
        List<Long> perIterationMemoryIncreases = new ArrayList<>();

        MemoryMXBean memoryBean = ManagementFactory.getMemoryMXBean();
        System.gc();
        long initialOverallHeapMemory = memoryBean.getHeapMemoryUsage().getUsed();
        int totalProcessedImages = 0;

        // AESCipher 인스턴스는 벤치마크 루프 바깥에서 한 번만 생성
        AESCipher aesCipher = new AESCipher();

        // --- 워밍업 및 실제 벤치마크 통합 루프 ---
        for (int i = 0; i < WARMUP_ITERATIONS + BENCHMARK_ITERATIONS; i++) {
            boolean isWarmup = i < WARMUP_ITERATIONS;
            if (!isWarmup) {
                System.out.println("\n--- 벤치마크 반복 " + (i - WARMUP_ITERATIONS + 1) + "회차 ---");
            } else if (i == 0) {
                System.out.println("워밍업 시작...");
            }

            long currentIterationEncryptionTime = 0;
            long currentIterationDecryptionTime = 0;
            long currentIterationMemoryUsage = 0;
            int currentIterationImagesCount = 0;

            // try-with-resources를 사용하여 JDBC 리소스를 안전하게 관리합니다.
            try (Connection conn = MySQLConnection.connect();
                 PreparedStatement stmt = conn.prepareStatement(SELECT_SQL);
                 ResultSet rs = stmt.executeQuery()) {

                while (rs.next()) {
                    byte[] originalImageData = rs.getBytes("튜플 이름");

                    if (originalImageData.length > MAX_IMAGE_SIZE_BYTES) {
                        if (!isWarmup) {
                            System.out.printf("경고: 이미지 크기 %d bytes. 1MB 초과로 건너뜁니다.\n", originalImageData.length);
                        }
                        continue;
                    }

                    long beforeOperationMemory = memoryBean.getHeapMemoryUsage().getUsed();

                    // --- 1. 암호화 벤치마크 ---
                    long startTimeEncryption = System.nanoTime();
                    byte[] encryptedData = aesCipher.encrypt(originalImageData);
                    long encryptionTime = System.nanoTime() - startTimeEncryption;
                    currentIterationEncryptionTime += encryptionTime;

                    // --- 2. 복호화 벤치마크 ---
                    long startTimeDecryption = System.nanoTime();
                    byte[] decryptedData = aesCipher.decrypt(encryptedData);
                    long decryptionTime = System.nanoTime() - startTimeDecryption;
                    currentIterationDecryptionTime += decryptionTime;

                    // --- 3. 데이터 무결성 검증 ---
                    if (!Arrays.equals(originalImageData, decryptedData)) {
                        throw new IllegalStateException("FATAL: 복호화된 데이터가 원본과 일치하지 않습니다!");
                    }

                    long afterOperationMemory = memoryBean.getHeapMemoryUsage().getUsed();
                    currentIterationMemoryUsage += Math.max(0, afterOperationMemory - beforeOperationMemory);

                    currentIterationImagesCount++;
                }

            } catch (SQLException e) {
                System.err.println("Database error during iteration: " + e.getMessage());
                throw e; // 예외 전파
            }

            // 벤치마크 결과만 누적
            if (!isWarmup) {
                encryptionTimes.add(currentIterationEncryptionTime);
                decryptionTimes.add(currentIterationDecryptionTime);
                perIterationMemoryIncreases.add(currentIterationMemoryUsage);
            }
            totalProcessedImages = currentIterationImagesCount; // 마지막 반복의 이미지 수로 업데이트
        }

        System.out.println("\n벤치마크 측정 완료.");

        // --- 최종 결과 출력 ---
        System.gc();
        long finalOverallHeapMemory = memoryBean.getHeapMemoryUsage().getUsed();
        long overallMemoryIncrease = Math.max(0, finalOverallHeapMemory - initialOverallHeapMemory);

        // 평균 계산
        double avgEncryptionTime = encryptionTimes.stream().mapToLong(Long::longValue).average().orElse(0.0);
        double avgDecryptionTime = decryptionTimes.stream().mapToLong(Long::longValue).average().orElse(0.0);
        double avgPerIterationMemoryIncrease = perIterationMemoryIncreases.stream().mapToLong(Long::longValue).average().orElse(0.0);


        System.out.println("\n--- 최종 MySQL AES 벤치마크 평균 결과 ---");
        System.out.printf("처리된 이미지 수 (각 회차당): %d개%n", totalProcessedImages);
        System.out.printf("전체 데이터셋 처리 당 평균 암호화 시간: %.3f ms%n", (avgEncryptionTime / 1_000_000.0));
        System.out.printf("전체 데이터셋 처리 당 평균 복호화 시간: %.3f ms%n", (avgDecryptionTime / 1_000_000.0));
        System.out.printf("이미지당 평균 암호화 시간: %.6f ms%n", (avgEncryptionTime / totalProcessedImages / 1_000_000.0));
        System.out.printf("이미지당 평균 복호화 시간: %.6f ms%n", (avgDecryptionTime / totalProcessedImages / 1_000_000.0));
        System.out.printf("평균 메모리 사용량 변화 (데이터셋 한 바퀴 처리당): %.3f MB%n", (avgPerIterationMemoryIncrease / (1024.0 * 1024.0)));
        System.out.printf("벤치마크 전체 동안의 총 힙 메모리 사용량 증가: %.3f MB%n", (double) overallMemoryIncrease / (1024.0 * 1024.0));
    }

    // runSingleBenchmarkIteration 메서드는 main 루프에 통합되었으므로 삭제합니다.
}