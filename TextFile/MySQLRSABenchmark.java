package org.example;

import java.sql.ResultSet;
import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import java.util.Arrays;
import java.util.Base64;

//찐막 확정
public class MySQLRSABenchmark {
    private static final int WARMUP_ITERATIONS = 50;
    private static final int BENCHMARK_ITERATIONS = 1000;
    private static final int RSA_MAX_CHUNK_SIZE = 245;

    public static void main(String[] args) {
        System.out.println("--- RSA 단독 암호화 벤치마크 (수정됨) ---");
        System.out.println("RSA는 한 번에 암호화할 수 있는 데이터 크기가 제한적입니다 (최대 " + RSA_MAX_CHUNK_SIZE + "바이트).");
        System.out.println("이 벤치마크에서는 큰 데이터를 **여러 덩어리로 나누어** 암호화/복호화합니다.\n");

        // 🔑 데이터베이스 연결 정보를 예시로 통일합니다.
        MySQLConnection dbConnection = new MySQLConnection("jdbc:mysql://localhost:3306/example_db", "sample_user", "sample_password");
        dbConnection.connect();

        List<Long> encryptionTimes = new ArrayList<>();
        List<Long> decryptionTimes = new ArrayList<>();
        List<Long> iterationMemoryChanges = new ArrayList<>();

        MemoryMXBean memoryBean = ManagementFactory.getMemoryMXBean();
        System.gc();
        long initialOverallMemoryUsed = memoryBean.getHeapMemoryUsage().getUsed();

        try {
            System.out.println("RSA 단독 벤치마킹을 시작합니다...");
            System.out.println("웜업 " + WARMUP_ITERATIONS + "회, 벤치마크 " + BENCHMARK_ITERATIONS + "회를 수행합니다.");

            RSACipher rsaCipher = new RSACipher();

            for (int i = 0; i < WARMUP_ITERATIONS + BENCHMARK_ITERATIONS; i++) {
                long totalEncryptionTimeForIteration = 0;
                long totalDecryptionTimeForIteration = 0;

                long memoryBeforeIteration = memoryBean.getHeapMemoryUsage().getUsed();

                // 🔑 통일된 테이블 이름으로 쿼리
                try (ResultSet rs = dbConnection.executeQuery("SELECT * FROM example_data")) {
                    while (rs.next()) {
                        // 🔑 통일된 컬럼 이름 ('category', 'value')을 사용하여 데이터 문자열 조합
                        String data = rs.getString("category") + " - " +
                                rs.getString("value");

                        String largeData = data.repeat(50); // 데이터 길이를 늘려 대용량 암호화 효과 시뮬레이션

                        long startTimeEncryption = System.nanoTime();
                        byte[] rsaEncryptedData = rsaCipher.encryptLargeData(largeData);
                        totalEncryptionTimeForIteration += (System.nanoTime() - startTimeEncryption);

                        long startTimeDecryption = System.nanoTime();
                        String rsaDecryptedData = rsaCipher.decryptLargeData(rsaEncryptedData);
                        totalDecryptionTimeForIteration += (System.nanoTime() - startTimeDecryption);
                    }
                }

                long memoryAfterIteration = memoryBean.getHeapMemoryUsage().getUsed();
                long currentIterationHeapChange = Math.max(0, memoryAfterIteration - memoryBeforeIteration);

                if (i >= WARMUP_ITERATIONS) {
                    encryptionTimes.add(totalEncryptionTimeForIteration);
                    decryptionTimes.add(totalDecryptionTimeForIteration);
                    iterationMemoryChanges.add(currentIterationHeapChange);
                }
            }
            System.out.println("벤치마크 측정 완료.");

            System.gc();
            long finalOverallMemoryUsed = memoryBean.getHeapMemoryUsage().getUsed();
            long totalBenchmarkHeapMemoryIncrease = Math.max(0, finalOverallMemoryUsed - initialOverallMemoryUsed);

            double avgEncryptionTimePerDataset = encryptionTimes.stream().mapToLong(Long::longValue).average().orElse(0.0);
            double avgDecryptionTimePerDataset = decryptionTimes.stream().mapToLong(Long::longValue).average().orElse(0.0);
            double avgIterationHeapMemoryChange = iterationMemoryChanges.stream().mapToLong(Long::longValue).average().orElse(0.0);

            System.out.println("\n--- 최종 RSA 단독 성능 벤치마크 평균 결과 ---");
            System.out.printf("데이터셋(5개 행) 암호화 당 평균 시간: %.3f ms\n", (avgEncryptionTimePerDataset / 1_000_000.0));
            System.out.printf("데이터셋(5개 행) 복호화 당 평균 시간: %.3f ms\n", (avgDecryptionTimePerDataset / 1_000_000.0));
            System.out.println("\n--- 메모리 사용량 경고 ---");
            System.out.println("개별 작업 및 반복의 힙 메모리 사용량 측정은 JVM의 가비지 컬렉션 및 힙 공유 특성상 매우 부정확할 수 있습니다.");
            System.out.printf("각 벤치마크 반복 (데이터셋 한 바퀴 처리) 동안의 평균 힙 메모리 증가량: %.3f MB\n", (avgIterationHeapMemoryChange / (1024.0 * 1024.0)));
            System.out.printf("전체 벤치마크 세션 동안의 총 힙 메모리 사용량 증가: %.3f MB\n", (double) totalBenchmarkHeapMemoryIncrease / (1024.0 * 1024.0));
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            dbConnection.close();
        }
    }

    public static class MySQLConnection {
        private String dbUrl;
        private String user;
        private String password;
        private Connection connection;
        // 🔑 테이블 이름 통일
        private static final String TABLE_NAME = "example_data";

        public MySQLConnection(String dbUrl, String user, String password) {
            this.dbUrl = dbUrl;
            this.user = user;
            this.password = password;
        }

        public void connect() {
            try {
                Class.forName("com.mysql.cj.jdbc.Driver");
                connection = DriverManager.getConnection(dbUrl, user, password);
                System.out.println("MySQL 데이터베이스에 연결되었습니다: " + dbUrl);
                createTableIfNotExist();
                insertSampleDataIfEmpty();
            } catch (ClassNotFoundException e) {
                System.err.println("MySQL JDBC 드라이버를 찾을 수 없습니다. Maven/Gradle 의존성을 확인하세요.");
                e.printStackTrace();
                throw new RuntimeException("MySQL JDBC 드라이버 로드 실패", e);
            } catch (SQLException e) {
                System.err.println("데이터베이스 연결 오류: " + e.getMessage());
                e.printStackTrace();
                throw new RuntimeException("MySQL 데이터베이스 연결 실패", e);
            }
        }

        private void createTableIfNotExist() throws SQLException {
            // 🔑 컬럼 이름 통일 ('category', 'value')
            String sql = "CREATE TABLE IF NOT EXISTS " + TABLE_NAME + " (\n"
                    + "    `id` INT AUTO_INCREMENT PRIMARY KEY,\n"
                    + "    `category` VARCHAR(255) NOT NULL,\n"
                    + "    `value` INT NOT NULL\n"
                    + ");";
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
                    String insertSql = "INSERT INTO " + TABLE_NAME + " (`category`, `value`) VALUES\n"
                            + "('Alpha', 101),\n"
                            + "('Beta', 202),\n"
                            + "('Gamma', 303),\n"
                            + "('Delta', 404),\n"
                            + "('Epsilon', 505);";
                    try (Statement insertStmt = connection.createStatement()) {
                        insertStmt.execute(insertSql);
                        System.out.println("샘플 데이터 5개 삽입 완료.");
                    }
                } else {
                    System.out.println("테이블에 이미 데이터가 존재합니다. 샘플 데이터 삽입을 건너갑니다.");
                }
            }
        }

        public ResultSet executeQuery(String query) throws SQLException {
            if (connection == null) {
                throw new SQLException("데이터베이스에 연결되어 있지 않습니다.");
            }
            // 쿼리 문자열은 'SELECT * FROM example_data'가 되도록 설정
            return connection.createStatement().executeQuery("SELECT * FROM " + TABLE_NAME);
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

    public static class RSACipher {
        private final PublicKey publicKey;
        private final PrivateKey privateKey;
        private static final int RSA_MAX_CHUNK_SIZE = 245;

        public RSACipher() throws Exception {
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
            SecureRandom secureRandom = new SecureRandom();
            keyPairGen.initialize(2048, secureRandom);
            KeyPair pair = keyPairGen.generateKeyPair();
            this.publicKey = pair.getPublic();
            this.privateKey = pair.getPrivate();
        }

        public byte[] encryptLargeData(String data) throws Exception {
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);

            byte[] dataBytes = data.getBytes(StandardCharsets.UTF_8);
            int dataLength = dataBytes.length;
            int numChunks = (int) Math.ceil((double) dataLength / RSA_MAX_CHUNK_SIZE);
            List<byte[]> encryptedChunks = new ArrayList<>();

            for (int i = 0; i < numChunks; i++) {
                int start = i * RSA_MAX_CHUNK_SIZE;
                int end = Math.min(start + RSA_MAX_CHUNK_SIZE, dataLength);
                byte[] chunk = Arrays.copyOfRange(dataBytes, start, end);
                byte[] encryptedChunk = rsaCipher.doFinal(chunk);
                encryptedChunks.add(encryptedChunk);
            }

            int totalEncryptedSize = 0;
            for (byte[] chunk : encryptedChunks) {
                totalEncryptedSize += chunk.length;
            }

            // 모든 암호화된 청크를 하나의 바이트 배열로 결합
            byte[] combinedEncryptedData = new byte[totalEncryptedSize];
            int offset = 0;
            for (byte[] chunk : encryptedChunks) {
                System.arraycopy(chunk, 0, combinedEncryptedData, offset, chunk.length);
                offset += chunk.length;
            }

            return combinedEncryptedData;
        }

        public String decryptLargeData(byte[] encryptedCombinedData) throws Exception {
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);

            StringBuilder decryptedString = new StringBuilder();
            // RSA 2048비트에서 PKCS1Padding을 사용하면 암호화된 각 청크의 크기는 256바이트입니다.
            int encryptedChunkSize = 256;

            for (int i = 0; i < encryptedCombinedData.length; i += encryptedChunkSize) {
                int end = Math.min(i + encryptedChunkSize, encryptedCombinedData.length);
                byte[] encryptedChunk = Arrays.copyOfRange(encryptedCombinedData, i, end);
                byte[] decryptedChunk = rsaCipher.doFinal(encryptedChunk);
                decryptedString.append(new String(decryptedChunk, StandardCharsets.UTF_8));
            }

            return decryptedString.toString();
        }
    }
}