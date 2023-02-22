package org.example.utils;

import sun.misc.GC;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.crypto.dsig.keyinfo.KeyName;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class AESGCMEncryptDescrypt {

    // la taille de la clé AES-256
    private static final int AES_KEY_SIZE=256;

    //la taille de l'initialisation GCM
    private static final int GCM_IV_LENGTH=12;

    // la taille du tag GCM
    private static final int GCM_TAG_LENGTH=16;

    //la fonction de chiffrement

    public static byte[] encrypt(String text, String password, byte[] key) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
       // byte[] key  = generateKey(password);
        byte[] iv  = generateIV();

        // création de l'instance de ciphier pour le chiffrement

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

        // création de l'objet GCMParameterSpec avec l'initialisation de la taille du tag
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);

        // initialiser le Cipher en mode chiffrement avec la clé et les paramètres GCM
        cipher.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(key, "AES"), spec);
        byte[] cipherText = cipher.doFinal(text.getBytes(StandardCharsets.UTF_8));

        //concaténer l'initialisation et le texte chiffré en un seul tableau

        byte[] result  = new byte[GCM_IV_LENGTH + cipherText.length];
        System.arraycopy(iv, 0, result, 0, GCM_IV_LENGTH);
        System.arraycopy(cipherText, 0, result, GCM_IV_LENGTH, cipherText.length);
        return result;
    }

    public static byte[] generateKey(String password) throws NoSuchAlgorithmException {
        SecureRandom random = SecureRandom.getInstanceStrong();
        random.setSeed(password.getBytes(StandardCharsets.UTF_8));

        // générer une clé à partir de l'objet SecurRandom
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(AES_KEY_SIZE, random);
        SecretKey secretKey = keyGenerator.generateKey();

        return secretKey.getEncoded();
    }

    private static byte[] generateIV() throws NoSuchAlgorithmException {
        byte[] iv = new byte[GCM_IV_LENGTH];
        SecureRandom random = SecureRandom.getInstanceStrong();
        random.nextBytes(iv);
        return iv;
    }

    public static String decrypt(byte[] ciphiertext, String password, byte[] key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        //byte[] key = generateKey(password);
        // extraire l'initialisation et le texte chiffré du tableau

        byte[] iv = new byte[GCM_IV_LENGTH];
        //byte[] ciphiertext = Base64.getDecoder().decode(text);
        System.arraycopy(ciphiertext, 0, iv,0,  GCM_IV_LENGTH);
        byte[] encrypted = new byte[ciphiertext.length - GCM_IV_LENGTH];
        System.arraycopy(ciphiertext, GCM_IV_LENGTH, encrypted, 0, encrypted.length);

        // créer une instance de cipher pour le déchiffrement

        Cipher cipher =Cipher.getInstance("AES/GCM/NoPadding");

        // créer un objet GCMParameterSpec avec l'initialisation et la taille du tag
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8 , iv);

        // initialiser le ciphier enmode déchiffrement avec la clé et les paramètres GCM
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), parameterSpec);
        byte[] plainttext = cipher.doFinal(encrypted);

        return new String(plainttext, StandardCharsets.UTF_8);

    }

}
