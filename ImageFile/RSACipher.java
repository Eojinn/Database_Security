package org.example;

import javax.crypto.Cipher;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

/**
 * RSA 공개 키 암호화 알고리즘을 구현하는 클래스입니다.
 * 2048비트 키 쌍을 생성하고 암호화 및 복호화 기능을 제공합니다.
 * 보안은 큰 소수 p, q의 곱 N에 대한 인수분해의 계산적 어려움에 기반합니다.
 */
public class RSACipher {

    private final PublicKey publicKey;
    private final PrivateKey privateKey;
    private static final String ALGORITHM_MODE = "RSA/ECB/PKCS1Padding";
    private static final int KEY_SIZE = 2048;

    /**
     * RSACipher 생성자.
     * RSA 2048비트 키 쌍을 생성합니다. (키 생성 과정은 텍스트의 절차에 따름)
     * @throws Exception 키 쌍 생성 중 오류 발생 시
     */
    public RSACipher() throws Exception {
        // 텍스트의 절차: p, q 선택 -> N 계산 -> 오일러 함수 phi(N) 계산 -> e 선택 -> d 계산 -> (e, N) 공개키, (d, N) 개인키
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        SecureRandom secureRandom = new SecureRandom();
        // RSA 키 크기 초기화
        keyPairGen.initialize(KEY_SIZE, secureRandom);
        KeyPair pair = keyPairGen.generateKeyPair();
        this.publicKey = pair.getPublic();
        this.privateKey = pair.getPrivate();
    }

    /**
     * 데이터를 RSA 공개키로 암호화합니다. (C ≡ M^e mod N)
     * @param data 암호화할 평문 데이터 (바이트 배열)
     * @return 암호화된 데이터 (바이트 배열)
     * @throws Exception 암호화 중 오류 발생 시
     */
    public byte[] encrypt(byte[] data) throws Exception {
        Cipher rsaCipher = Cipher.getInstance(ALGORITHM_MODE);
        // 공개키를 이용해 암호화 모드 초기화
        rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        // 암호화 과정은 모듈러 거듭제곱 연산으로 수행됨
        // RSA는 암호화할 수 있는 데이터 크기가 제한됩니다 (2048비트 키 기준 최대 245바이트).
        return rsaCipher.doFinal(data);
    }

    /**
     * 암호화된 데이터를 RSA 개인키로 복호화합니다. (M ≡ C^d mod N)
     * @param encryptedData 복호화할 암호문 데이터 (바이트 배열)
     * @return 복호화된 평문 데이터 (바이트 배열)
     * @throws Exception 복호화 중 오류 발생 시
     */
    public byte[] decrypt(byte[] encryptedData) throws Exception {
        Cipher rsaCipher = Cipher.getInstance(ALGORITHM_MODE);
        // 개인키를 이용해 복호화 모드 초기화
        rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
        return rsaCipher.doFinal(encryptedData);
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }
}