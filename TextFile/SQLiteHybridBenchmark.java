package org.example;

import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.nio.charset.StandardCharsets;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Arrays;

//8/6 18:34
public class SQLiteHybridBenchmark {
    // 1. 벤치마킹 회수 설정
    private static final int WARMUP_ITERATIONS = 50; // 웜업 반복 횟수: 50회
    private static final int MEASUREMENT_ITERATIONS = 1000; // 실제 측정 반복 횟수: 1000회

    public static void main(String[] args) {
        // 🔑 SQLite 경로를 예시 이름으로 변경했습니다.
        SQLiteConnection dbConnection = new SQLiteConnection("jdbc:sqlite:/path/to/example_db.db");
        dbConnection.connect();

        // 2. 각 측정 결과를 저장할 리스트 생성
        List<Long> encryptionTimes = new ArrayList<>();
        List<Long> decryptionTimes = new ArrayList<>();
        // 각 데이터셋 처리 시의 힙 메모리 증가량을 저장할 리스트
        List<Long> perOperationHeapMemoryIncreases = new ArrayList<>();
        MemoryMXBean memoryBean = ManagementFactory.getMemoryMXBean();

        // ** 전체 벤치마크 시작 전의 초기 힙 메모리 사용량 측정 **
        // 초기 메모리 사용량을 안정화하기 위해 GC를 한 번 호출합니다.
        System.gc();
        long initialOverallMemoryUsed = memoryBean.getHeapMemoryUsage().getUsed();

        try {
            System.out.println("--- 하이브리드 암호화 벤치마킹 시작 ---");
            System.out.println("웜업 " + WARMUP_ITERATIONS + "회, 실제 측정 " + MEASUREMENT_ITERATIONS + "회를 수행합니다.");
            // **업데이트된 설명**: 매 작업마다 RSA 키 연산이 포함됨을 명시
            System.out.println("이 벤치마크는 **매 작업마다** RSA 키 암호화/복호화 오버헤드가 포함된 **전체 하이브리드 사이클**의 효율성을 측정합니다.");


            // HybridCipher 객체를 벤치마크 루프 외부에서 한 번만 생성하여 키 쌍 생성 오버헤드를 제외합니다.
            HybridCipher hybridCipher = new HybridCipher();

            // 3. 웜업(Warm-up)과 실제 측정을 함께 실행
            for (int i = 0; i < WARMUP_ITERATIONS + MEASUREMENT_ITERATIONS; i++) {
                // 각 시행마다 DB에서 데이터를 새로 읽어오도록 ResultSet을 다시 얻음
                // 🔑 통일된 테이블 이름으로 쿼리
                ResultSet rs = dbConnection.executeQuery("SELECT * FROM example_data");
                long totalEncryptionTime = 0; // 전체 암호화 시간 (RSA + AES)
                long totalDecryptionTime = 0; // 전체 복호화 시간 (RSA + AES)

                // 5. 정확한 메모리 측정을 위해 루프 시작 전 힙 메모리 기록
                long memoryBeforeOperation = memoryBean.getHeapMemoryUsage().getUsed();

                while (rs.next()) {
                    // 🔑 통일된 컬럼 이름 ('category', 'value')을 사용하여 데이터 문자열 조합
                    String data = rs.getString("category") + "|" +
                            rs.getString("value");

                    String largeData = data.repeat(50); // 데이터를 50배 반복하여 큰 데이터로 만듦

                    // 암호화 (전체 하이브리드 사이클: AES 키 생성 -> RSA 키 암호화 -> AES 데이터 암호화)
                    long startTimeEnc = System.nanoTime();
                    byte[] encryptedData = hybridCipher.encrypt(largeData);
                    totalEncryptionTime += (System.nanoTime() - startTimeEnc);

                    // 복호화 (전체 하이브리드 사이클: RSA 키 복호화 -> AES 데이터 복호화)
                    long startTimeDec = System.nanoTime();
                    hybridCipher.decrypt(encryptedData);
                    totalDecryptionTime += (System.nanoTime() - startTimeDec);
                }

                // 루프 종료 후 힙 메모리 기록
                long memoryAfterOperation = memoryBean.getHeapMemoryUsage().getUsed();
                long currentOperationHeapIncrease = memoryAfterOperation - memoryBeforeOperation;
                currentOperationHeapIncrease = Math.max(0, currentOperationHeapIncrease);

                rs.close();

                // 6. 웜업 구간이 끝나면 결과 기록
                if (i >= WARMUP_ITERATIONS) {
                    encryptionTimes.add(totalEncryptionTime);
                    decryptionTimes.add(totalDecryptionTime);
                    perOperationHeapMemoryIncreases.add(currentOperationHeapIncrease);
                } else {
                    System.out.println("웜업 " + (i + 1) + "회 완료.");
                }
            }

            System.out.println("벤치마크 측정 완료.");

            // 전체 벤치마크 완료 후의 최종 힙 메모리 사용량 측정
            System.gc();
            long finalOverallMemoryUsed = memoryBean.getHeapMemoryUsage().getUsed();
            long totalBenchmarkHeapMemoryIncrease = finalOverallMemoryUsed - initialOverallMemoryUsed;
            totalBenchmarkHeapMemoryIncrease = Math.max(0, totalBenchmarkHeapMemoryIncrease);

            // 7. 최종 평균 결과 계산 및 출력
            double avgEncryptionTime = encryptionTimes.stream().mapToLong(Long::longValue).average().orElse(0.0);
            double avgDecryptionTime = decryptionTimes.stream().mapToLong(Long::longValue).average().orElse(0.0);
            double avgPerOperationHeapMemoryIncrease = perOperationHeapMemoryIncreases.stream().mapToLong(Long::longValue).average().orElse(0.0);


            System.out.println("\n--- 최종 하이브리드 성능 벤치마크 평균 결과 ---");
            System.out.printf("데이터셋(5개 행) 암호화 당 평균 시간: %.3f ms\n", (avgEncryptionTime / 1_000_000.0));
            System.out.printf("데이터셋(5개 행) 복호화 당 평균 시간: %.3f ms\n", (avgDecryptionTime / 1_000_000.0));
            System.out.println("참고: 이 시간은 AES 데이터 암복호화 외에도 **매 작업마다 RSA 키 암복호화** 시간이 포함된 결과입니다.");

            System.out.println("\n--- 메모리 사용량 ---");
            System.out.printf("전체 벤치마크 동안의 총 힙 메모리 사용량 증가: %.3f MB\n", (double) totalBenchmarkHeapMemoryIncrease / (1024.0 * 1024.0));
            System.out.printf("각 벤치마크 반복 (데이터셋 한 바퀴 처리) 동안의 평균 힙 메모리 증가량: %.3f MB\n", (avgPerOperationHeapMemoryIncrease / (1024.0 * 1024.0)));


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
                Class.forName("org.sqlite.JDBC");
                connection = DriverManager.getConnection(dbUrl);
                System.out.println("데이터베이스에 연결되었습니다: " + dbUrl);
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


    /**
     * 표준 Hybrid 암호화 클래스.
     * 이 구현은 매 암호화/복호화 작업마다 일회용 AES 키를 생성하고 RSA로 암호화/복호화하는
     * 전체 하이브리드 사이클을 수행합니다.
     */
    public static class HybridCipher {

        private final PrivateKey privateKey;
        private final PublicKey publicKey;

        /**
         * 생성자: RSA 키 쌍(공개키/개인키)을 생성하여 저장합니다.
         */
        public HybridCipher() throws Exception {
            // RSA 키 쌍 생성 (2048비트)
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
            SecureRandom secureRandom = new SecureRandom();
            // 2048비트는 현재 보안 환경에서 권장되는 RSA 키 크기입니다.
            keyPairGen.initialize(2048, secureRandom);
            KeyPair pair = keyPairGen.generateKeyPair();
            this.publicKey = pair.getPublic();
            this.privateKey = pair.getPrivate();
        }

        /**
         * 데이터를 하이브리드 방식으로 암호화합니다.
         * 1. 일회용 AES 키(128비트)와 IV를 생성합니다.
         * 2. AES 키와 IV로 데이터를 암호화합니다 (AES/CBC/PKCS5Padding).
         * 3. RSA 공개키로 AES 키와 IV를 함께 암호화합니다 (RSA/ECB/PKCS1Padding).
         * 4. 암호화된 AES 키의 길이를 프리픽스(4바이트)로, 뒤이어 암호화된 AES 키/IV, 그리고 암호화된 데이터를 결합하여 반환합니다.
         *
         * @param data 암호화할 원본 문자열
         * @return 암호화된 AES 키, IV, 데이터를 결합한 바이트 배열
         * @throws Exception 암호화 중 오류 발생 시
         */
        public byte[] encrypt(String data) throws Exception {
            // 1. 일회용 AES 키 (128비트) 생성 및 IV 생성
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            // AES-128bit를 사용합니다.
            keyGen.init(128);
            SecretKey aesKey = keyGen.generateKey();
            byte[] aesKeyBytes = aesKey.getEncoded(); // 16 bytes (128 bit)

            SecureRandom secureRandom = new SecureRandom();
            byte[] ivBytes = new byte[16]; // 16 bytes (AES/CBC 표준)
            secureRandom.nextBytes(ivBytes);
            IvParameterSpec iv = new IvParameterSpec(ivBytes);

            // 2. AES로 데이터 암호화
            Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
            byte[] encryptedData = aesCipher.doFinal(data.getBytes(StandardCharsets.UTF_8));

            // 3. RSA로 AES 키와 IV를 암호화 (두 바이트 배열을 합쳐서 암호화)
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);

            byte[] keyIvBytes = new byte[aesKeyBytes.length + ivBytes.length]; // 총 32 바이트
            System.arraycopy(aesKeyBytes, 0, keyIvBytes, 0, aesKeyBytes.length);
            System.arraycopy(ivBytes, 0, keyIvBytes, aesKeyBytes.length, ivBytes.length);

            byte[] encryptedKeyIv = rsaCipher.doFinal(keyIvBytes); // RSA 암호화 (2048bit 키 사용 시 보통 256 바이트)

            // 4. 암호화된 데이터를 결합
            int encryptedKeyLen = encryptedKeyIv.length; // 암호화된 RSA 키의 길이 (예: 256)
            byte[] output = new byte[4 + encryptedKeyLen + encryptedData.length]; // [길이(4)] [암호화된 키/IV] [암호화된 데이터]

            // 길이 정보(int)를 4바이트 배열로 변환하여 삽입
            output[0] = (byte) ((encryptedKeyLen >> 24) & 0xFF);
            output[1] = (byte) ((encryptedKeyLen >> 16) & 0xFF);
            output[2] = (byte) ((encryptedKeyLen >> 8) & 0xFF);
            output[3] = (byte) (encryptedKeyLen & 0xFF);

            // 암호화된 키/IV 삽입
            System.arraycopy(encryptedKeyIv, 0, output, 4, encryptedKeyLen);
            // 암호화된 데이터 삽입
            System.arraycopy(encryptedData, 0, output, 4 + encryptedKeyLen, encryptedData.length);

            return output;
        }

        /**
         * 하이브리드 방식으로 암호화된 데이터를 복호화합니다.
         * 1. 암호화된 AES 키와 IV를 추출합니다.
         * 2. RSA 개인키로 AES 키와 IV를 복호화합니다.
         * 3. 복호화된 AES 키와 IV로 암호화된 데이터를 복호화합니다.
         *
         * @param encryptedData 하이브리드 암호화된 데이터 바이트 배열
         * @return 복호화된 원본 문자열
         * @throws Exception 복호화 중 오류 발생 시
         */
        public String decrypt(byte[] encryptedData) throws Exception {
            // 1. 암호화된 AES 키 길이 추출
            int encryptedKeyLen = ((encryptedData[0] & 0xFF) << 24) |
                    ((encryptedData[1] & 0xFF) << 16) |
                    ((encryptedData[2] & 0xFF) << 8) |
                    (encryptedData[3] & 0xFF);

            // 암호화된 AES 키/IV 추출
            byte[] encryptedKeyIv = Arrays.copyOfRange(encryptedData, 4, 4 + encryptedKeyLen);
            // 암호화된 데이터 추출
            byte[] encryptedPayload = Arrays.copyOfRange(encryptedData, 4 + encryptedKeyLen, encryptedData.length);

            // 2. RSA로 AES 키와 IV 복호화 (매 복호화 시마다 RSA 연산이 발생)
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decryptedKeyIv = rsaCipher.doFinal(encryptedKeyIv); // 32 바이트 (16바이트 AES 키 + 16바이트 IV)

            // AES 키와 IV 분리
            // AES-128bit를 사용했으므로 키 길이는 16바이트입니다.
            byte[] aesKeyBytes = Arrays.copyOfRange(decryptedKeyIv, 0, 16);
            byte[] ivBytes = Arrays.copyOfRange(decryptedKeyIv, 16, 32);

            SecretKey originalAesKey = new SecretKeySpec(aesKeyBytes, "AES");
            IvParameterSpec iv = new IvParameterSpec(ivBytes);

            // 3. AES로 데이터 복호화
            Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            aesCipher.init(Cipher.DECRYPT_MODE, originalAesKey, iv);
            byte[] decryptedBytes = aesCipher.doFinal(encryptedPayload);

            return new String(decryptedBytes, StandardCharsets.UTF_8);
        }
    }
}