package org.example;
import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.jcajce.*;

import java.io.*;
import java.security.Security;
import java.security.SecureRandom;
import java.security.PrivateKey;
import java.util.Iterator;

public class Main {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    static PGPOps PgpOps = new PGPOps();

    public static void main(String[] args) {


        String executingPath = System.getProperty("user.dir");
        System.out.println("Your Executing Path is  " + executingPath);

        String input_file = executingPath + "/src/main/resources/plaintext.txt";
        String pub_file = executingPath + "/src/main/resources/pub.asc";
        String priv_file = executingPath + "/src/main/resources/priv.asc";
        String encrypted_file = executingPath + "/src/main/resources/encrypted/plaintext.txt.pgp";
        String decrypted_file = executingPath + "/src/main/resources/decrypted/plaintext-decrypted.txt";
        String password ="password2$";
        String PgpOperation ="decrypt";

        if ((PgpOperation.equalsIgnoreCase("encrypt"))) {
            if(input_file == "" || encrypted_file == "" ||pub_file ==null) {
                System.err.println("Usage: PGPFileEncryption <encrypt|decrypt> <inputFile> <keyFile> <outputFile> [password]");
                System.exit(1);
            }
        else {

                if(decrypted_file  == "" || encrypted_file == "" || pub_file ==null || password == null) {
                    System.err.println("Usage: PGPFileEncryption <encrypt|decrypt> <inputFile> <keyFile> <outputFile> [password]");
                    System.exit(1);
                }
            }

        }
        try {
            if (PgpOperation.equalsIgnoreCase("encrypt")) {
                PgpOps.encryptFile(encrypted_file, input_file, pub_file);
                System.out.println("Encryption complete!");
            } else if (PgpOperation.equalsIgnoreCase("decrypt")) {
                if (password == "") {
                    System.err.println("Password is required for decryption.");
                    System.exit(1);
                }
                PgpOps.decryptFile(encrypted_file, priv_file, password.toCharArray(), decrypted_file);
                System.out.println("Decryption complete!");
            } else {
                System.err.println("Invalid operation. Use 'encrypt' or 'decrypt'.");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

