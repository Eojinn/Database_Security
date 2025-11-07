package org.example; // 패키지 이름을 org.example로 통일하여 사용합니다.

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;

/**
 * AES (Advanced Encryption Standard) - 128비트 키를 사용한 대칭 키 블록 암호화 구현체입니다.
 * 이 클래스는 AES-128의 키 확장 및 10개 라운드를 Java Cryptography Extension (JCE)를 통해 처리합니다.
 */
public class AESCipher {

    private final SecretKey secretKey;
    private final IvParameterSpec ivParameterSpec;
    private static final int KEY_SIZE_BITS = 128; // AES-128 키 길이
    private static final int BLOCK_SIZE_BYTES = 16; // AES 블록 크기 (128비트)
    private static final String ALGORITHM_MODE = "AES/CBC/PKCS5Padding";

    /**
     * AESCipher 생성자.
     * 128비트 AES 키와 무작위 IV(Initialization Vector)를 생성합니다.
     * @throws Exception 키 및 IV 생성 중 오류 발생 시
     */
    public AESCipher() throws Exception {
        // 1. 128비트 AES 키를 생성합니다. (키 확장 과정에 사용될 초기 키)
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(KEY_SIZE_BITS);
        this.secretKey = keyGen.generateKey();

        // 2. IV 생성 (AES 블록 크기와 동일한 16바이트)
        SecureRandom secureRandom = new SecureRandom();
        byte[] iv = new byte[BLOCK_SIZE_BYTES];
        secureRandom.nextBytes(iv);
        this.ivParameterSpec = new IvParameterSpec(iv);
    }

    /**
     * 바이트 배열 데이터를 AES 알고리즘(CBC/PKCS5Padding)으로 암호화합니다.
     * (AES-128의 경우, 내부적으로 키 확장을 거쳐 10개 라운드를 수행합니다.)
     * @param data 암호화할 원본 데이터 (바이트 배열)
     * @return 암호화된 데이터 (바이트 배열)
     * @throws Exception 암호화 중 오류 발생 시
     */
    public byte[] encrypt(byte[] data) throws Exception {
        Cipher aesCipher = Cipher.getInstance(ALGORITHM_MODE);
        // 초기 키와 평문의 XOR 연산에 해당하는 초기 변환을 포함하여 암호화 시작
        aesCipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
        return aesCipher.doFinal(data);
    }

    /**
     * AES 알고리즘으로 암호화된 데이터를 복호화합니다.
     * @param encryptedData 복호화할 암호화된 데이터 (바이트 배열)
     * @return 복호화된 원본 데이터 (바이트 배열)
     * @throws Exception 복호화 중 오류 발생 시
     */
    public byte[] decrypt(byte[] encryptedData) throws Exception {
        Cipher aesCipher = Cipher.getInstance(ALGORITHM_MODE);
        aesCipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
        return aesCipher.doFinal(encryptedData);
    }
}
