package org.example;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.security.SecureRandom;

// 외부 클래스 임포트
// MySQLConnection 및 RSACipher 클래스는 org.example 패키지에 존재한다고 가정합니다.
import org.example.MySQLConnection;
import org.example.RSACipher;

/**
 * 순수 RSA 2048비트 암호화/복호화 성능을 측정하는 벤치마크 클래스입니다.
 * MySQLConnection의 정적 메서드를 사용하도록 수정되었습니다.
 */
public class MySQLRSABenchmark {

    // AES 벤치마크와 동일하게 워밍업 및 벤치마크 횟수 조정
    private static final int WARMUP_ITERATIONS = 50;
    private static final int BENCHMARK_ITERATIONS = 1000;

    // RSA 2048비트 키 + PKCS1Padding 시 암호화 가능한 최대 데이터 크기 (바이트)
    private static final int RSA_MAX_DATA_SIZE = 256 - 11;

    // 벤치마크에 사용될 테이블 이름 (하이브리드/AES 벤치마크와 동일하게 수정)
    private static final String TABLE_NAME = "테이블 이름";

    // 데이터 조회 쿼리 (AES 벤치마크 예시처럼 상수로 정의)
    private static final String SELECT_SQL = "SELECT 튜플 이름 FROM 테이블 이름";

    // 처리할 샘플 데이터 개수를 10,000개로 대폭 증가
    private static final int SAMPLE_DATA_COUNT = 10000;

    public static void main(String[] args) {
        System.out.println("--- MySQL RSA 단독 암호화 벤치마크 시작 ---");
        System.out.printf("경고: RSA는 대칭 암호화와 달리 한 번에 암호화할 수 있는 데이터 크기가 매우 제한적입니다 (최대 %d바이트).\n", RSA_MAX_DATA_SIZE);
        System.out.println("이 벤치마크에서는 원본 데이터를 이 크기에 맞춰 잘라서 처리합니다.\n");

        // Connection 객체는 main 메서드에서 정의 후 finally에서 닫도록 합니다.
        Connection conn = null;

        try {
            // MySQLConnection 정적 메서드를 사용하여 연결 객체를 얻습니다.
            conn = MySQLConnection.connect();
            // 트랜잭션 수동 관리를 위해 AutoCommit 비활성화
            conn.setAutoCommit(false);
            setupDatabase(conn); // 데이터베이스 셋업
            benchmark(conn);
        } catch (Exception e) {
            System.err.println("벤치마크 실행 중 오류가 발생했습니다: " + e.getMessage());
            e.printStackTrace();
        } finally {
            // 마지막에 Connection을 닫습니다.
            MySQLConnection.close(conn, null, null);
        }
    }

    /**
     * 벤치마크 실행에 필요한 테이블을 생성하고 샘플 데이터를 삽입합니다.
     * @param conn 데이터베이스 연결 객체
     */
    private static void setupDatabase(Connection conn) throws SQLException {
        // try-with-resources를 사용하여 Statement 리소스를 자동 해제합니다.
        try (Statement stmt = conn.createStatement()) {
            // 1. 테이블 생성
            // 테이블 이름은 TABLE_NAME을 사용하되, 기존에 테이블이 있다면 생성하지 않음.
            String createTableSql = String.format("CREATE TABLE IF NOT EXISTS %s (id INT AUTO_INCREMENT PRIMARY KEY, 튜플 이름 BLOB NOT NULL);", TABLE_NAME);
            stmt.execute(createTableSql);

            // 2. 샘플 데이터 삽입/확인
            String countSql = String.format("SELECT COUNT(*) FROM %s", TABLE_NAME);
            try (ResultSet rs = stmt.executeQuery(countSql)) { // ResultSet도 try-with-resources로 관리
                if (rs.next()) {
                    int currentCount = rs.getInt(1);

                    // 목표 레코드 수에 도달하지 않았으면 INSERT 수행
                    if (currentCount < SAMPLE_DATA_COUNT) {
                        int recordsToAdd = SAMPLE_DATA_COUNT - currentCount;
                        System.out.printf("벤치마크를 위해 %d개의 샘플 데이터 추가 삽입 중...\n", recordsToAdd);

                        // 데이터 삽입은 SAMPLE_DATA_COUNT만큼 수행합니다.
                        byte[] sampleData = new byte[300]; // RSA 최대 크기보다 큰 300바이트 데이터
                        new SecureRandom().nextBytes(sampleData);

                        String insertSql = String.format("INSERT INTO %s (튜플 이름) VALUES (?)", TABLE_NAME);
                        try (PreparedStatement ps = conn.prepareStatement(insertSql)) {
                            for (int i = 0; i < recordsToAdd; i++) {
                                ps.setBytes(1, sampleData);
                                ps.addBatch();
                            }
                            ps.executeBatch();
                            conn.commit(); // 대량 삽입 후 커밋
                            System.out.printf("샘플 데이터 %d개 삽입 완료 (총 레코드 수: %d).\n", recordsToAdd, SAMPLE_DATA_COUNT);
                        }
                    } else {
                        System.out.printf("테이블에 이미 %d개의 데이터가 존재합니다. 기존 데이터를 사용하여 벤치마크를 실행합니다.\n", currentCount);
                    }
                }
            }
        }
        // setupDatabase 완료 후 AutoCommit은 끄지 않은 상태로 유지 (main에서 껐으므로)
    }


    /**
     * RSA 암호화/복호화 벤치마크를 실행합니다.
     * @param conn 데이터베이스 연결 객체 (AutoCommit은 비활성화되어 있어야 함)
     */
    public static void benchmark(Connection conn) throws Exception {
        System.out.println("\nMySQL RSA 단독 암호화/복호화 벤치마크를 시작합니다...");
        System.out.printf("워밍업: %d회, 벤치마크: %d회 반복.\n", WARMUP_ITERATIONS, BENCHMARK_ITERATIONS);

        // 결과 저장을 위한 리스트
        RSACipher rsaCipher = new RSACipher();
        List<Long> encryptionTimes = new ArrayList<>();
        List<Long> decryptionTimes = new ArrayList<>();
        List<Long> perIterationMemoryIncreases = new ArrayList<>(); // 델타 메모리 저장

        MemoryMXBean memoryBean = ManagementFactory.getMemoryMXBean();
        System.gc();
        long initialOverallHeapMemory = memoryBean.getHeapMemoryUsage().getUsed();
        int totalProcessedRecords = 0;

        // --- 워밍업 및 실제 벤치마크 통합 루프 ---
        for (int i = 0; i < WARMUP_ITERATIONS + BENCHMARK_ITERATIONS; i++) {
            boolean isWarmup = i < WARMUP_ITERATIONS;
            if (!isWarmup) {
                System.out.println("\n--- 벤치마크 반복 " + (i - WARMUP_ITERATIONS + 1) + "회차 ---");
            } else if (i == 0) {
                System.out.println("워밍업 시작.");
            }

            long currentIterationEncryptionTime = 0;
            long currentIterationDecryptionTime = 0;
            long currentIterationMemoryUsage = 0; // 델타 메모리 누적
            int currentIterationRecordsCount = 0;

            // try-with-resources로 PreparedStatement와 ResultSet을 자동 관리
            // SELECT_SQL 상수를 사용하여 쿼리 통일
            try (PreparedStatement stmt = conn.prepareStatement(SELECT_SQL);
                 ResultSet rs = stmt.executeQuery()) {

                while (rs.next()) {
                    byte[] originalImageData = rs.getBytes("튜플 이름");

                    // RSA 제한 크기로 데이터 자르기 (RSA는 큰 파일에 부적합함을 시연)
                    byte[] imageDataToProcess;
                    if (originalImageData.length > RSA_MAX_DATA_SIZE) {
                        imageDataToProcess = Arrays.copyOfRange(originalImageData, 0, RSA_MAX_DATA_SIZE);
                    } else {
                        imageDataToProcess = originalImageData;
                    }

                    // --- 메모리 델타 측정 시작 ---
                    long beforeOperationMemory = memoryBean.getHeapMemoryUsage().getUsed();

                    // --- 1. RSA 암호화 ---
                    long startTimeEncryption = System.nanoTime();
                    byte[] rsaEncryptedData = rsaCipher.encrypt(imageDataToProcess);
                    long encryptionTime = System.nanoTime() - startTimeEncryption;
                    currentIterationEncryptionTime += encryptionTime;

                    // --- 2. RSA 복호화 ---
                    long startTimeDecryption = System.nanoTime();
                    byte[] rsaDecryptedData = rsaCipher.decrypt(rsaEncryptedData);
                    long decryptionTime = System.nanoTime() - startTimeDecryption;
                    currentIterationDecryptionTime += decryptionTime;

                    // --- 3. 데이터 무결성 검증 ---
                    if (!Arrays.equals(imageDataToProcess, rsaDecryptedData)) {
                        throw new IllegalStateException("FATAL: 복호화된 데이터가 원본과 일치하지 않습니다! RSA 구현 오류 가능성.");
                    }

                    // --- 메모리 델타 측정 종료 및 누적 ---
                    long afterOperationMemory = memoryBean.getHeapMemoryUsage().getUsed();
                    currentIterationMemoryUsage += Math.max(0, afterOperationMemory - beforeOperationMemory);

                    currentIterationRecordsCount++;
                }

            } // try-with-resources: stmt와 rs 자동 close

            totalProcessedRecords = currentIterationRecordsCount;

            if (!isWarmup) {
                encryptionTimes.add(currentIterationEncryptionTime);
                decryptionTimes.add(currentIterationDecryptionTime);
                perIterationMemoryIncreases.add(currentIterationMemoryUsage);
            }
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


        System.out.println("\n--- 최종 MySQL RSA 단독 벤치마크 평균 결과 ---");
        System.out.printf("처리된 레코드 수 (각 회차당): %d개%n", totalProcessedRecords);
        System.out.printf("전체 데이터셋 처리 당 평균 암호화 시간: %.3f ms%n", (avgEncryptionTime / 1_000_000.0));
        System.out.printf("전체 데이터셋 처리 당 평균 복호화 시간: %.3f ms%n", (avgDecryptionTime / 1_000_000.0));
        System.out.printf("레코드당 평균 암호화 시간: %.6f ms%n", (avgEncryptionTime / totalProcessedRecords / 1_000_000.0));
        System.out.printf("레코드당 평균 복호화 시간: %.6f ms%n", (avgDecryptionTime / totalProcessedRecords / 1_000_000.0));
        System.out.printf("평균 메모리 사용량 변화 (데이터셋 한 바퀴 처리당): %.3f MB%n", (avgPerIterationMemoryIncrease / (1024.0 * 1024.0)));
        System.out.printf("벤치마크 전체 동안의 총 힙 메모리 사용량 증가: %.3f MB%n", (double) overallMemoryIncrease / (1024.0 * 1024.0));
    }
}
