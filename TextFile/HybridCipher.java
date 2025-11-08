package org.example;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.nio.charset.StandardCharsets;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;
import java.util.Base64;

/**
 * 표준 Hybrid 암호화 클래스.
 * 이 구현은 매 암호화/복호화 작업마다 일회용 AES 키를 생성하고 RSA로 암호화/복호화하는
 * 전체 하이브리드 사이클을 수행합니다.
 */
public class HybridCipher {

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
