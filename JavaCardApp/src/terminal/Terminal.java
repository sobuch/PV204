package terminal;

import applets.JavaCardApplet;
import cardTools.CardManager;
import cardTools.RunConfig;
import cardTools.Util;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

/**
 * Terminal class.
 */
public class Terminal {
    private static String APPLET_AID = "482871d58ab7465e5e05";
    private static byte APPLET_AID_BYTE[] = Util.hexStringToByteArray(APPLET_AID);

    private final CardManager cardManager;
    private final RunConfig runConfig;
    
    private byte[] secret;
    
    public Terminal() {
        this.cardManager = new CardManager(true, APPLET_AID_BYTE);
        this.runConfig = RunConfig.getDefaultConfig();
    }

    public static void main(String[] args) {
        try {
            Terminal terminal = new Terminal();
            
            terminal.connectToCard();
            
            terminal.initEcdhSession();
            
            String text= "Ahoj";    
            byte[] codedtext = terminal.encryptTerminal(text);
            String decodedtext = terminal.decryptTerminal(codedtext);

            System.out.println(codedtext);
            System.out.println(decodedtext); 
            
        } catch (Exception ex) {
            System.out.println("Exception : " + ex);
        }
    }

    private void connectToCard() throws Exception {

        final byte[] cardPIN = {'6', '6', '6', '6'};
        final byte[] wrongCardPIN = {'6', '6', '6', '7'};
        
        this.runConfig.setInstallData(cardPIN);
        this.runConfig.setTestCardType(RunConfig.CARD_TYPE.JCARDSIMLOCAL);

        runConfig.setAppletToSimulate(JavaCardApplet.class);
        // Connect to card
        System.out.print("Connecting to card...");
        if (!cardManager.Connect(runConfig)) {
            System.out.println(" Failed.");
        }
        System.out.println(" Done.");
        // test wrong pin
        final ResponseAPDU testWrongPIN = cardManager.transmit(new CommandAPDU(0x00, 0x20, 0x00, 0x00, wrongCardPIN));
        final ResponseAPDU testOKPIN = cardManager.transmit(new CommandAPDU(0x00, 0x20, 0x00, 0x00, cardPIN));
    }
    
    private void initEcdhSession() throws Exception {
       
        KeyPair keyPair = generateKeyPair();
        
        KeyAgreement dh = KeyAgreement.getInstance("ECDH");
        dh.init(keyPair.getPrivate());
        
        byte[] terminalShare = ((ECPublicKey) keyPair.getPublic()).getEncoded();
                
        final ResponseAPDU response = cardManager.transmit(new CommandAPDU(0x00, 0x21, 0x00, 0x00, terminalShare));
        final byte[] cardResponseData = response.getData();
        System.out.println("TERMINAL: Card public key: " + this.change(cardResponseData));

        java.security.PublicKey cardPK = extractCardPK(cardResponseData);
        
        dh.doPhase(cardPK, true);
        secret = dh.generateSecret();

        System.out.println("Secret on terminal side: " + this.change(secret));
        
        MessageDigest hash = MessageDigest.getInstance("SHA-256");
        hash.update(secret);
        // Simple deterministic ordering
        List<ByteBuffer> keys = Arrays.asList(ByteBuffer.wrap(keyPair.getPublic().getEncoded()), ByteBuffer.wrap(cardPK.getEncoded()));
        Collections.sort(keys);
        hash.update(keys.get(0));
        hash.update(keys.get(1));

        byte[] derivedKey = deriveSessionKey(keyPair.getPublic().getEncoded(), cardPK.getEncoded());
        System.out.printf("Final key: %s%n", change(derivedKey));
    }
    
    private KeyPair generateKeyPair() throws Exception{
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec paramSpec = new ECGenParameterSpec("secp192r1");
        generator.initialize(paramSpec);
        return generator.generateKeyPair();
    }
    
    private java.security.PublicKey extractCardPK(byte[] cardResponseData) throws Exception {
        X509EncodedKeySpec formatted_public = new X509EncodedKeySpec(cardResponseData);
        KeyFactory kf = KeyFactory.getInstance("EC");
        return kf.generatePublic(formatted_public);
    }
    /**
     * https://neilmadden.blog/2016/05/20/ephemeral-elliptic-curve-diffie-hellman-key-agreement-in-java/?fbclid=IwAR24l7jCZR7i9h3gmBRFkjevo1UcN7n1avPc9Npc6IG-4pjScP-aUS8xBws
     */
    private byte[] deriveSessionKey(byte[] terminalPK, byte[] cardPK) throws Exception {
        java.security.MessageDigest hash = java.security.MessageDigest.getInstance("SHA-256");
        hash.update(secret);
        // Simple deterministic ordering
        List<ByteBuffer> keys = Arrays.asList(ByteBuffer.wrap(terminalPK), ByteBuffer.wrap(cardPK));
        Collections.sort(keys);
        hash.update(keys.get(0));
        hash.update(keys.get(1));
        return hash.digest();
    }
    
    private String change(byte[] key) {
        if (key == null) {
            return null;
        }
        return Util.bytesToHex(key);
    }
    
    /*
     * https://stackoverflow.com/questions/20227/how-do-i-use-3des-encryption-decryption-in-java?fbclid=IwAR3pGgJKW7RdwZQyTAgrTEaRbMzsNruCS92fBpici06SHnRNvgWiqtBsmq0
     */
    public byte[] encryptTerminal(String message) throws Exception {
        final MessageDigest md = MessageDigest.getInstance("md5");
        final byte[] digestOfPassword = md.digest(secret);
        final byte[] keyBytes = Arrays.copyOf(digestOfPassword, 24);
        for (int j = 0, k = 16; j < 8;) {
            keyBytes[k++] = keyBytes[j++];
        }

        final SecretKey key = new SecretKeySpec(keyBytes, "DESede");
        final IvParameterSpec iv = new IvParameterSpec(new byte[8]);
        
        ResponseAPDU IVappdu = cardManager.transmit(new CommandAPDU(0x00, 0xd0, 0x00, 0x00, iv.getIV()));
        
        final Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);

        final byte[] plainTextBytes = message.getBytes("utf-8");
        final byte[] cipherText = cipher.doFinal(plainTextBytes);
        // final String encodedCipherText = new sun.misc.BASE64Encoder()
        // .encode(cipherText);
        
        ResponseAPDU testt = cardManager.transmit(new CommandAPDU(0x00, 0xd0, 0x00, 0x00, digestOfPassword));

        return cipherText;
    }
        
    public String decryptTerminal(byte[] message) throws Exception {
        final MessageDigest md = MessageDigest.getInstance("md5");
        final byte[] digestOfPassword = md.digest(secret);
        final byte[] keyBytes = Arrays.copyOf(digestOfPassword, 24);
        for (int j = 0, k = 16; j < 8;) {
            keyBytes[k++] = keyBytes[j++];
        }

        final SecretKey key = new SecretKeySpec(keyBytes, "DESede");
        final IvParameterSpec iv = new IvParameterSpec(new byte[8]);
        final Cipher decipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        decipher.init(Cipher.DECRYPT_MODE, key, iv);

        // final byte[] encData = new
        // sun.misc.BASE64Decoder().decodeBuffer(message);
        final byte[] plainText = decipher.doFinal(message);

        return new String(plainText, "UTF-8");
    }
}
