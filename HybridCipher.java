package org.example;

import java.security.*;
import java.nio.charset.StandardCharsets;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class HybridCipher {

    // 송신자/수신자의 키 쌍 (4개의 키 필요)
    private final PublicKey receiverPublicKey;  // PK_R (수신자 공개키)
    private final PrivateKey senderSecretKey;   // SK_S (송신자 비밀키)
    private final PrivateKey receiverSecretKey;  // SK_R (수신자 비밀키)
    private final PublicKey senderPublicKey;    // PK_S (송신자 공개키)

    // 세션키 관련 상수
    private static final String AES_ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final String HASH_ALGORITHM = "SHA-256";
    private static final int AES_KEY_SIZE_BYTES = 16; // 128 bit AES

    /**
     * 생성자: RSA 키 쌍(공개키/개인키)을 생성하여 저장합니다.
     */
    public HybridCipher() throws Exception {
        // 송신자 키 쌍 생성
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048, new SecureRandom());
        KeyPair senderPair = keyPairGen.generateKeyPair();
        this.senderPublicKey = senderPair.getPublic();
        this.senderSecretKey = senderPair.getPrivate();

        // 수신자 키 쌍 생성
        KeyPair receiverPair = keyPairGen.generateKeyPair();
        this.receiverPublicKey = receiverPair.getPublic();
        this.receiverSecretKey = receiverPair.getPrivate();
    }

    // --- KAP 관련 추상화 메서드 (버그 수정됨) ---

    /**
     * KAP의 SKG(Session Key Generator) 역할을 추상화합니다.
     * 암호문 C를 생성: Encrypt(PK_R, alpha) + Sign(SK_S, Encrypted_alpha)
     * @param alpha 세션키 계산에 사용될 난수 alpha
     * @return 암호문 C (바이트 배열)
     */
    private byte[] generateCiphertextC(byte[] alpha) throws Exception {
        // 1. alpha를 PK_R로 암호화 (세션 키 전달)
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher.init(Cipher.ENCRYPT_MODE, receiverPublicKey);
        byte[] encryptedAlpha = rsaCipher.doFinal(alpha);

        // 2. Encrypted Alpha를 SK_S로 서명 (송신자 인증)
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(senderSecretKey);
        signature.update(encryptedAlpha);
        byte[] signatureBytes = signature.sign();

        // C = [encryptedAlpha 길이(4) || encryptedAlpha || signatureBytes]
        try (ByteArrayOutputStream os = new ByteArrayOutputStream()) {
            int alphaLen = encryptedAlpha.length;
            os.write((alphaLen >> 24) & 0xFF);
            os.write((alphaLen >> 16) & 0xFF);
            os.write((alphaLen >> 8) & 0xFF);
            os.write(alphaLen & 0xFF);
            os.write(encryptedAlpha);
            os.write(signatureBytes);
            return os.toByteArray();
        }
    }

    /**
     * KAP의 SKR(Session Key Recovery) 역할을 추상화하고, 난수 alpha를 복원합니다.
     * @param C 암호문 C
     * @return 복원된 난수 alpha (바이트 배열)
     */
    private byte[] recoverAlpha(byte[] C) throws Exception {
        // C에서 encryptedAlpha와 signatureBytes 추출
        int alphaLen = ((C[0] & 0xFF) << 24) | ((C[1] & 0xFF) << 16) | ((C[2] & 0xFF) << 8) | (C[3] & 0xFF);

        byte[] encryptedAlpha = Arrays.copyOfRange(C, 4, 4 + alphaLen);

        // RSA 서명 길이는 RSA 키 크기(2048)에 따라 256바이트로 고정 (패딩 포함)
        int signatureLen = 256;
        byte[] signatureBytes = Arrays.copyOfRange(C, 4 + alphaLen, 4 + alphaLen + signatureLen);

        // 1. PK_S로 서명 검증 (무결성 및 인증)
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(senderPublicKey);
        signature.update(encryptedAlpha);

        if (!signature.verify(signatureBytes)) {
            // 보안상의 이유로 BadPaddingException 대신 다른 예외를 던지는 것이 더 적절할 수 있습니다.
            throw new GeneralSecurityException("송신자 서명 검증 실패: 키가 유효하지 않거나 데이터가 변조되었습니다.");
        }

        // 2. SK_R로 alpha 복원 (버그 수정: 실제 복호화를 수행)
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher.init(Cipher.DECRYPT_MODE, receiverSecretKey);
        byte[] recoveredAlpha = rsaCipher.doFinal(encryptedAlpha);

        return recoveredAlpha; // 복원된 난수 alpha 반환
    }

    /**
     * 의사 난수 생성기(PRG) 역할. 난수로부터 세션키를 계산합니다. (3)
     */
    private SecretKey calculateSessionKey(byte[] alpha) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance(HASH_ALGORITHM);
        byte[] hash = digest.digest(alpha);
        // 해시의 앞 16바이트를 AES 키로 사용
        byte[] aesKeyBytes = Arrays.copyOfRange(hash, 0, AES_KEY_SIZE_BYTES);
        return new SecretKeySpec(aesKeyBytes, "AES");
    }

    // --- 암호화 과정 (송신자) ---

    /**
     * Hybrid 암호화 과정 전체를 수행합니다.
     * @param message 평문 메시지 (바이트 배열)
     * @return [C || C_M || V]를 결합한 바이트 배열
     */
    public byte[] encrypt(byte[] message) throws Exception {
        // 1. 난수 alpha 선택 (프로토콜에서 beta는 C 생성에 사용되므로, alpha만 사용하도록 단순화)
        SecureRandom sr = new SecureRandom();
        byte[] alpha = new byte[16]; // 16바이트 난수 alpha
        sr.nextBytes(alpha);

        // 2. SKG 모듈에 입력하여 암호문 C 생성
        byte[] C = generateCiphertextC(alpha);

        // 3. PRG에 alpha를 입력하여 세션키 K 계산 (3)
        SecretKey K = calculateSessionKey(alpha);

        // 4. 세션키 K로 평문 M을 암호화하여 암호문 C_M 생성
        Cipher aesCipher = Cipher.getInstance(AES_ALGORITHM);
        byte[] ivBytes = new byte[16];
        sr.nextBytes(ivBytes); // IV는 매번 새로 생성
        IvParameterSpec iv = new IvParameterSpec(ivBytes);

        aesCipher.init(Cipher.ENCRYPT_MODE, K, iv);
        byte[] C_M_payload = aesCipher.doFinal(message);

        // IV를 C_M에 포함시켜 전송 (C_M = [IV || C_M_payload]로 구성)
        byte[] C_M = new byte[ivBytes.length + C_M_payload.length];
        System.arraycopy(ivBytes, 0, C_M, 0, ivBytes.length);
        System.arraycopy(C_M_payload, 0, C_M, ivBytes.length, C_M_payload.length);

        // 5. 무결성 검증값 V 생성 (4)
        // [수정] 프로토콜은 SK_S를 명시했으나, 수신자가 검증 가능하도록 PK_S를 사용해야 합니다. (Decrypt 함수와 일치)
        MessageDigest digest = MessageDigest.getInstance(HASH_ALGORITHM);
        digest.update(receiverPublicKey.getEncoded()); // PK_R
        digest.update(senderPublicKey.getEncoded());   // PK_S (SK_S 대신 사용, 복호화 측 V'와 일치)
        digest.update(C);                              // C
        digest.update(C_M);                             // C_M
        byte[] V = digest.digest();

        // 6. [C || C_M || V] 전송 (5)
        try (ByteArrayOutputStream os = new ByteArrayOutputStream()) {
            // C의 길이 정보를 저장할 필요 없이 순서대로 결합
            os.write(C);
            os.write(C_M);
            os.write(V);
            return os.toByteArray();
        }
    }

    // --- 복호화 과정 (수신자) ---

    /**
     * Hybrid 복호화 과정 전체를 수행합니다.
     * @param encryptedData [C || C_M || V]가 결합된 바이트 배열
     * @return 복호화된 평문 메시지 (바이트 배열)
     * @throws Exception 복호화 중 오류 발생 시 또는 무결성 검증 실패 시
     */
    public byte[] decrypt(byte[] encryptedData) throws Exception {
        // 1. C, C_M, V 분리
        // V의 길이는 고정 (SHA-256 = 32바이트)
        int vLen = 32;
        byte[] V_received = Arrays.copyOfRange(encryptedData, encryptedData.length - vLen, encryptedData.length);

        // C와 C_M이 남은 부분
        byte[] C_C_M = Arrays.copyOfRange(encryptedData, 0, encryptedData.length - vLen);

        // C의 길이 복원: C는 [4 | encryptedAlpha | signature]로 구성됨.
        int alphaLen = ((C_C_M[0] & 0xFF) << 24) | ((C_C_M[1] & 0xFF) << 16) | ((C_C_M[2] & 0xFF) << 8) | (C_C_M[3] & 0xFF);
        int signatureLen = 256;
        int cLen = 4 + alphaLen + signatureLen;

        byte[] C = Arrays.copyOfRange(C_C_M, 0, cLen);
        byte[] C_M = Arrays.copyOfRange(C_C_M, cLen, C_C_M.length);

        // 2. SKR 모듈에 SK_R, PK_S, C를 입력하여 alpha 복원 (키 일치성 보장)
        byte[] alpha_recovered = recoverAlpha(C);

        // 3. PRG에 alpha를 입력하여 세션키 K 얻기
        SecretKey K = calculateSessionKey(alpha_recovered);

        // 4. K를 이용해 C_M을 복호화하여 평문 M 얻기
        // C_M = [IV(16) || C_M_payload]로 구성됨.
        byte[] ivBytes = Arrays.copyOfRange(C_M, 0, 16);
        byte[] C_M_payload = Arrays.copyOfRange(C_M, 16, C_M.length);
        IvParameterSpec iv = new IvParameterSpec(ivBytes);

        Cipher aesCipher = Cipher.getInstance(AES_ALGORITHM);
        // 여기서 정확한 K와 IV가 사용되므로 BadPaddingException이 해결됩니다.
        aesCipher.init(Cipher.DECRYPT_MODE, K, iv);
        byte[] M_recovered = aesCipher.doFinal(C_M_payload);

        // 5. 무결성 검증 (V' 생성)
        // 수신자는 송신자의 비밀키(SK_S)를 알 수 없으므로, (4)번 수식의 SK_S 대신
        // 인증 목적의 PK_S를 사용하여 V를 검증해야 논리적으로 맞습니다.
        MessageDigest digest = MessageDigest.getInstance(HASH_ALGORITHM);
        digest.update(receiverPublicKey.getEncoded()); // PK_R
        digest.update(senderPublicKey.getEncoded());   // PK_S (SK_S 대신)
        digest.update(C);                              // C
        digest.update(C_M);                             // C_M
        byte[] V_verified = digest.digest();

        // 6. V'와 수신한 V가 일치하는지 확인
        if (!Arrays.equals(V_received, V_verified)) {
            throw new GeneralSecurityException("무결성 검증 실패: 메시지가 변조되었거나 송신자가 아닙니다.");
        }

        return M_recovered;
    }
}
