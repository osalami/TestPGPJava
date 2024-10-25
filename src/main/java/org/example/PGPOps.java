package org.example;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.jcajce.*;

import java.io.*;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Iterator;

public class PGPOps {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }


    public static void encryptFile(String outputFileName, String inputFileName, String publicKeyFileName) throws Exception {
        OutputStream out = new BufferedOutputStream(new FileOutputStream(outputFileName));
        PGPPublicKey encKey = readPublicKey(publicKeyFileName);
        encryptFile(out, inputFileName, encKey, true, true);
        out.close();
    }

    private static PGPPublicKey readPublicKey(String publicKeyFileName) throws IOException, PGPException {
        InputStream keyIn = new BufferedInputStream(new FileInputStream(publicKeyFileName));
        PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(keyIn), new JcaKeyFingerprintCalculator());
        Iterator<PGPPublicKeyRing> rIt = pgpPub.getKeyRings();
        while (rIt.hasNext()) {
            PGPPublicKeyRing kRing = rIt.next();
            Iterator<PGPPublicKey> kIt = kRing.getPublicKeys();
            while (kIt.hasNext()) {
                PGPPublicKey key = kIt.next();
                if (key.isEncryptionKey()) {
                    return key;
                }
            }
        }
        throw new IllegalArgumentException("Can't find encryption key in key ring.");
    }

    private static void encryptFile(OutputStream out, String fileName, PGPPublicKey encKey, boolean armor, boolean withIntegrityCheck) throws IOException, PGPException {
        if (armor) {
            out = new ArmoredOutputStream(out);
        }
        byte[] bytes = compressFile(fileName, PGPCompressedData.ZIP);
        PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
                new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5).setWithIntegrityPacket(withIntegrityCheck).setSecureRandom(new SecureRandom()).setProvider("BC"));
        encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(encKey).setProvider("BC"));
        OutputStream cOut = encGen.open(out, bytes.length);
        cOut.write(bytes);
        cOut.close();
        if (armor) {
            out.close();
        }
    }

    private static byte[] compressFile(String fileName, int algorithm) throws IOException {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(algorithm);
        PGPUtil.writeFileToLiteralData(comData.open(bOut), PGPLiteralData.BINARY, new File(fileName));
        comData.close();
        return bOut.toByteArray();
    }

    public static void decryptFile(String inputFileName, String privateKeyFileName, char[] password, String outputFileName) throws Exception {
        InputStream in = PGPUtil.getDecoderStream(new FileInputStream(inputFileName));
        InputStream keyIn = new BufferedInputStream(new FileInputStream(privateKeyFileName));
        OutputStream out = new BufferedOutputStream(new FileOutputStream(outputFileName));

        PGPObjectFactory pgpF = new PGPObjectFactory(in, new JcaKeyFingerprintCalculator());
        Object o = pgpF.nextObject();
        PGPEncryptedDataList enc;

        if (o instanceof PGPEncryptedDataList) {
            enc = (PGPEncryptedDataList) o;
        } else {
            enc = (PGPEncryptedDataList) pgpF.nextObject();
        }

        Iterator<PGPEncryptedData> it = enc.getEncryptedDataObjects();
        PGPPrivateKey sKey = null;
        PGPPublicKeyEncryptedData pbe = null;
        PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(keyIn), new JcaKeyFingerprintCalculator());

        while (sKey == null && it.hasNext()) {
            pbe = (PGPPublicKeyEncryptedData) it.next();
            sKey = findPrivateKey(pgpSec, pbe.getKeyID(), password);
        }

        if (sKey == null) {
            throw new IllegalArgumentException("Secret key for message not found.");
        }

        InputStream clear = pbe.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(sKey));
        PGPObjectFactory plainFact = new PGPObjectFactory(clear, new JcaKeyFingerprintCalculator());
        Object message = plainFact.nextObject();

        if (message instanceof PGPCompressedData) {
            PGPCompressedData cData = (PGPCompressedData) message;
            plainFact = new PGPObjectFactory(cData.getDataStream(), new JcaKeyFingerprintCalculator());
            message = plainFact.nextObject();
        }

        if (message instanceof PGPLiteralData) {
            PGPLiteralData ld = (PGPLiteralData) message;
            InputStream unc = ld.getInputStream();
            int ch;
            while ((ch = unc.read()) >= 0) {
                out.write(ch);
            }
        } else {
            throw new PGPException("Message is not a simple encrypted file.");
        }

        if (pbe.isIntegrityProtected() && !pbe.verify()) {
            throw new PGPException("Message failed integrity check");
        }

        out.close();
        keyIn.close();
        in.close();
    }

    private static PGPPrivateKey findPrivateKey(PGPSecretKeyRingCollection pgpSec, long keyID, char[] pass) throws PGPException {
        PGPSecretKey pgpSecKey = pgpSec.getSecretKey(keyID);
        if (pgpSecKey == null) {
            return null;
        }
        PBESecretKeyDecryptor decryptor = new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(pass);
        return pgpSecKey.extractPrivateKey(decryptor);
    }


}
