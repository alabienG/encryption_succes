package org.example;

import org.example.utils.AESGCMEncryptDescrypt;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class Main {
    public static void main(String[] args) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        byte[] key  = AESGCMEncryptDescrypt.generateKey("Gouchere2020");
       byte[] resul  = AESGCMEncryptDescrypt.encrypt("Hello word", "Gouchere2020", key);
       String resulString = Base64.getEncoder().encodeToString(resul);
        System.out.println(resulString);
        String original = AESGCMEncryptDescrypt.decrypt(resul, "Gouchere2020",key);
        System.out.println(original);

    }
}