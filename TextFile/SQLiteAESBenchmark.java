package org.example;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.ResultSet;
import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.nio.charset.StandardCharsets;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;

//찐막 확정
public class SQLiteAESBenchmark {

    private static final int WARMUP_ITERATIONS = 50;
    private static final int BENCHMARK_ITERATIONS = 1000;

    public static void main(String[] args) {
        // 🔑 SQLite 경로를 예시 이름으로 변경했습니다. (실제 경로는 환경에 맞게 수정 필요)
        SQLiteConnection dbConnection = new SQLiteConnection("jdbc:sqlite:/path/to/example_db.db");
        dbConnection.connect();

        long totalEncryptionTimeAESSum = 0;
        long totalDecryptionTimeAESSum = 0;
        long totalMemoryUsageAESSum = 0;
        long totalAESHeapIncreaseSum = 0;
        MemoryMXBean memoryBean = ManagementFactory.getMemoryMXBean();
        long initialMemoryOverall = memoryBean.getHeapMemoryUsage().getUsed();

        try {
            AESCipher aesCipher = new AESCipher();

            // --- 웜업 시작 ---
            System.out.println("AES 성능 웜업을 시작합니다. 총 " + WARMUP_ITERATIONS + "회 반복됩니다.");
            for (int i = 0; i < WARMUP_ITERATIONS; i++) {
                // 🔑 통일된 테이블 이름으로 쿼리
                ResultSet rs = dbConnection.executeQuery("SELECT * FROM example_data");
                while (rs.next()) {
                    // 🔑 'category' 컬럼에 해당 (id가 1, category가 2번째 컬럼)
                    String data = rs.getString(2);
                    byte[] aesEncryptedData = aesCipher.encrypt(data);
                    String aesDecryptedData = aesCipher.decrypt(aesEncryptedData);
                }
                rs.close();
            }
            System.out.println("웜업 완료.\n");

            // --- 벤치마크 시작 ---
            System.out.println("AES 성능 벤치마킹을 시작합니다. 총 " + BENCHMARK_ITERATIONS + "회 반복됩니다.");
            for (int i = 0; i < BENCHMARK_ITERATIONS; i++) {
                System.out.println("--- 벤치마크 " + (i + 1) + "회차 ---");
                long currentEncryptionTimeAES = 0;
                long currentDecryptionTimeAES = 0;
                long currentAESHeapIncrease = 0;

                // 🔑 통일된 테이블 이름으로 쿼리
                ResultSet rs = dbConnection.executeQuery("SELECT * FROM example_data");
                while (rs.next()) {
                    String data = rs.getString(2); // 'category' 컬럼 사용

                    long initialMemoryForAESOperation = memoryBean.getHeapMemoryUsage().getUsed();

                    long startTimeEncryptionAES = System.nanoTime();
                    byte[] aesEncryptedData = aesCipher.encrypt(data);
                    long encryptionTimeAES = System.nanoTime() - startTimeEncryptionAES;
                    currentEncryptionTimeAES += encryptionTimeAES;

                    long startTimeDecryptionAES = System.nanoTime();
                    String aesDecryptedData = aesCipher.decrypt(aesEncryptedData);
                    long decryptionTimeAES = System.nanoTime() - startTimeDecryptionAES;
                    currentDecryptionTimeAES += decryptionTimeAES;

                    long finalMemoryForAESOperation = memoryBean.getHeapMemoryUsage().getUsed();
                    long aesOperationMemoryIncrease = finalMemoryForAESOperation - initialMemoryForAESOperation;
                    totalMemoryUsageAESSum += aesOperationMemoryIncrease;
                    currentAESHeapIncrease += aesOperationMemoryIncrease;
                }
                rs.close();
                totalEncryptionTimeAESSum += currentEncryptionTimeAES;
                totalDecryptionTimeAESSum += currentDecryptionTimeAES;
                totalAESHeapIncreaseSum += currentAESHeapIncrease;
            }

            long finalMemoryOverall = memoryBean.getHeapMemoryUsage().getUsed();
            long overallMemoryIncrease = finalMemoryOverall - initialMemoryOverall;

            // 최종 평균 결과 출력
            System.out.println("\n--- 최종 AES 성능 벤치마크 평균 결과 ---");
            System.out.printf("총 AES 암호화 시간 (평균): %.3f ms\n", (double) totalEncryptionTimeAESSum / BENCHMARK_ITERATIONS / 1_000_000.0);
            System.out.printf("총 AES 복호화 시간 (평균): %.3f ms\n", (double) totalDecryptionTimeAESSum / BENCHMARK_ITERATIONS / 1_000_000.0);
            System.out.printf("총 AES 관련 메모리 사용량 (평균): %.3f MB\n", (double) totalMemoryUsageAESSum / BENCHMARK_ITERATIONS / (1024.0 * 1024.0));
            System.out.printf("전체 AES 작업 동안의 총 힙 메모리 사용량 증가 (평균): %.3f MB\n", (double) totalAESHeapIncreaseSum / BENCHMARK_ITERATIONS / (1024.0 * 1024.0));
            System.out.printf("전체 벤치마크 동안의 총 힙 메모리 사용량 증가: %.3f MB\n", (double) overallMemoryIncrease / (1024.0 * 1024.0));

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            dbConnection.close();
        }
    }

    public static class SQLiteConnection {
        private String dbUrl;
        private Connection connection;
        // 🔑 테이블 이름 통일
        private static final String TABLE_NAME = "example_data";

        public SQLiteConnection(String dbUrl) {
            this.dbUrl = dbUrl;
        }

        public void connect() {
            try {
                // SQLite JDBC 드라이버 로드
                Class.forName("org.sqlite.JDBC");
                connection = DriverManager.getConnection(dbUrl);
                System.out.println("SQLite 데이터베이스에 연결되었습니다: " + dbUrl);
                createTableIfNotExist();
                insertSampleDataIfEmpty();
            } catch (ClassNotFoundException e) {
                System.err.println("SQLite JDBC 드라이버를 찾을 수 없습니다. Maven/Gradle 의존성을 확인하세요.");
                e.printStackTrace();
            } catch (SQLException e) {
                System.err.println("데이터베이스 연결 오류: " + e.getMessage());
                e.printStackTrace();
            }
        }

        private void createTableIfNotExist() throws SQLException {
            // 🔑 컬럼 이름 통일 ('category', 'value')
            String sql = "CREATE TABLE IF NOT EXISTS " + TABLE_NAME + " (\n" +
                    " id INTEGER PRIMARY KEY AUTOINCREMENT,\n" +
                    " category TEXT NOT NULL,\n" +
                    " value INTEGER NOT NULL\n" +
                    ");";
            try (Statement stmt = connection.createStatement()) {
                stmt.execute(sql);
                System.out.println("테이블 '" + TABLE_NAME + "'이(가) 존재하거나 생성되었습니다.");
            }
        }

        private void insertSampleDataIfEmpty() throws SQLException {
            String countSql = "SELECT COUNT(*) FROM " + TABLE_NAME + ";";
            try (Statement stmt = connection.createStatement();
                 ResultSet rs = stmt.executeQuery(countSql)) {
                if (rs.next() && rs.getInt(1) == 0) {
                    System.out.println("샘플 데이터 삽입 중...");
                    // 🔑 샘플 데이터를 통일된 카테고리/값 데이터로 변경 (5개 행)
                    String insertSql = "INSERT INTO " + TABLE_NAME + " (category, value) VALUES\n" +
                            "('Alpha', 101),\n" +
                            "('Beta', 202),\n" +
                            "('Gamma', 303),\n" +
                            "('Delta', 404),\n" +
                            "('Epsilon', 505);";
                    try (Statement insertStmt = connection.createStatement()) {
                        insertStmt.execute(insertSql);
                        System.out.println("샘플 데이터 5개 삽입 완료.");
                    }
                } else {
                    System.out.println("테이블에 이미 데이터가 존재합니다. 샘플 데이터 삽입을 건너킵니다.");
                }
            }
        }

        public ResultSet executeQuery(String query) throws SQLException {
            if (connection == null) {
                throw new SQLException("데이터베이스에 연결되어 있지 않습니다.");
            }
            return connection.createStatement().executeQuery(query);
        }

        public void close() {
            if (connection != null) {
                try {
                    connection.close();
                    System.out.println("데이터베이스 연결이 종료되었습니다.");
                } catch (SQLException e) {
                    System.err.println("데이터베이스 연결 종료 오류: " + e.getMessage());
                    e.printStackTrace();
                }
            }
        }
    }

    public static class AESCipher {
        private SecretKey secretKey;
        private IvParameterSpec ivParameterSpec;

        public AESCipher() throws Exception {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128);
            this.secretKey = keyGen.generateKey();
            SecureRandom secureRandom = new SecureRandom();
            byte[] iv = new byte[16];
            secureRandom.nextBytes(iv);
            this.ivParameterSpec = new IvParameterSpec(iv);
        }

        public byte[] encrypt(String data) throws Exception {
            Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            aesCipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
            return aesCipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
        }

        public String decrypt(byte[] encryptedData) throws Exception {
            Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            aesCipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
            byte[] decryptedBytes = aesCipher.doFinal(encryptedData);
            return new String(decryptedBytes, StandardCharsets.UTF_8);
        }
    }
}