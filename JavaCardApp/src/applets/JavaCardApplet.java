package applets;

import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

public class JavaCardApplet extends javacard.framework.Applet implements MultiSelectable{

    // usual card values
    private static final byte SEC_PIN_MAX_LENGTH = (byte) 0x04;
    private static final byte SEC_PIN_RETRIES = (byte) 0x03;
    final static short SEC_PIN_VERIFY_FAILED = (short)0x9704;
    
    // instructions
    private static final byte I_PIN_VERIFY = (byte)0x20;
    private static final byte I_ECDH_INIT = (byte) 0x21;
    
    private static final byte INS_SET_DES_KEY              = (byte)0xd0;
    private static final byte INS_SET_DES_ICV              = (byte)0xd1;
    private static final byte INS_DO_DES_CIPHER            = (byte)0xd2;
    
    private static final byte INS_CLEAR_DATA               = (byte)0xff;
    
    private static final byte INS_BALANCE_ADD              = (byte)0xc0;
    private static final byte INS_BALANCE_REMOVE           = (byte)0xc1;
    
    private byte desKeyLen;
    private byte[] desKey = null;
    private byte[] desICV = null;
 
    private Cipher desEcbCipher;
    private Cipher desCbcCipher;
    private Key tempDesKey2 = null;
    private Key tempDesKey3 = null;
    private OwnerPIN accessPIN;
    
    private byte cardBalance = 0;
    private byte[] secret;
    
    public JavaCardApplet(byte[] buffer, short offset, byte length) {
        accessPIN = new OwnerPIN(SEC_PIN_RETRIES, SEC_PIN_MAX_LENGTH);
        accessPIN.update(buffer, offset, length);
        
        tempDesKey3 = KeyBuilder.buildKey(KeyBuilder.TYPE_DES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_DES3_3KEY, false);
        desCbcCipher = Cipher.getInstance(Cipher.ALG_DES_CBC_PKCS5, false);
        
        register();
    }

    
        // with the help of https://javacardos.com/wiki/javacard-api-samples/des
    private void setDesKey(byte[] key) {  
        if (key.length == 16 || key.length == 24) {
            this.desKeyLen = (byte) key.length;
            desKey = new byte[key.length];
            System.out.println("dessss" + this.desKeyLen);
            Util.arrayCopy(key, (short) 0x00, desKey, (short)0, (short)key.length);
        } else {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }    
    }
    
    private Key getDesKey() {
        Key tempDesKey = null;
        switch (desKeyLen)
        {
        case (byte)16:
            tempDesKey = tempDesKey2;
            break;
        case (byte)24:
            tempDesKey = tempDesKey3;
            break;
        default:
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            break;
        }
        //Set the 'desKey' key data value into the internal representation
        ((DESKey)tempDesKey).setKey(desKey, (short)0);
        return tempDesKey;
    }
    
    private void setDesICV(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short bytesLength = apdu.setIncomingAndReceive();
        
        if (bytesLength != 8)
        {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        //Copy the incoming ICV value to the global variable 'desICV'
        desICV = new byte[8];
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, desICV, (short)0, (short)8);
    }
    
    private String change(byte[] key) {
        if (key == null) {
            return null;
        }
        return cardTools.Util.bytesToHex(key);
    }
    
    private void decryptDes(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short bytesLength = apdu.setIncomingAndReceive();
        
        Key key = getDesKey();
        
        byte mode = Cipher.MODE_DECRYPT;
        Cipher cipher = this.desCbcCipher;
        
        System.out.println("ssss card key" + change(this.desKey));
        System.out.println("ssss ICV" + change(this.desICV));
        
        cipher.init(key, mode, desICV, (short) 0, (short) 8);
        
        byte[] output = new byte[buffer[4]]; 
        
        cipher.doFinal(buffer, ISO7816.OFFSET_CDATA, buffer[4], buffer, (short) 0);
        System.out.println("OUTPUT" + change(output) + ", " + buffer[4]);
        
        //Util.arrayCopy(output, (short) 0x00, buffer, (short)0, (short) output.length);
        apdu.setOutgoingAndSend((short)0, bytesLength);
    }
    
    
    
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new JavaCardApplet(bArray, bOffset, bLength);
    }

    public void process(APDU apdu) {
       
        byte[] apduBuffer = apdu.getBuffer();
        byte instruction = apduBuffer[ISO7816.OFFSET_INS];
        try {
            switch (instruction) {
                case INS_CLEAR_DATA:
                    clearSessionData();
                    sendTerminationInfo(apdu);
                    break;
                case I_PIN_VERIFY:
                    verifyPIN(apdu);
                    break;
                case I_ECDH_INIT:
                    initECDH(apdu);
                    break;
                case INS_SET_DES_ICV:
                    //SET_DES_ICV
                    setDesICV(apdu);
                    break;
                case INS_DO_DES_CIPHER:
                    //DO_DES_CIPHER
                    decryptDes(apdu);
                    break;
                case INS_BALANCE_ADD:
                    addBalance(apdu);
                    break;
                case INS_BALANCE_REMOVE:
                    removeBalance(apdu);
                    break;
                  
            }
        } catch (Exception e) {
            e.printStackTrace();
        }    
    }

    @Override
    public boolean select() {
        clearSessionData();
        return true;
    }

    @Override
    public boolean select(boolean appInstAlreadyActive) {
        clearSessionData();
        return true;
    }

    @Override
    public void deselect() {
        clearSessionData();
    }

    @Override
    public void deselect(boolean appInstAlreadyActive) {
        clearSessionData();
    }

    /**
     * Method used to clear session data in RAM.
     */
    private void clearSessionData(){
        if (tempDesKey2 != null) {
            tempDesKey2.clearKey();
        }
        if (tempDesKey3 != null) {
            tempDesKey3.clearKey();
        }
        if (desKey != null) {
            Util.arrayFillNonAtomic(desKey, (short) 0, (short) desKey.length, (byte) 0);
        }
        if (desICV != null) {
            Util.arrayFillNonAtomic(desICV, (short) 0, (short) desICV.length, (byte) 0);
        }
        desKeyLen = (byte) 0x00;
    }
    
    
    private void verifyPIN(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        byte bytesRead = (byte)apdu.setIncomingAndReceive();
        /*
        if (accessPIN.check(buffer, ISO7816.OFFSET_CDATA, bytesRead) == false) {
            ISOException.throwIt(SEC_PIN_VERIFY_FAILED);
        } 
                */
    }
    
    private void initECDH(APDU apdu) throws Exception {
        byte[] buffer = apdu.getBuffer();
        short bytesLength = apdu.setIncomingAndReceive();
        
        byte[] terminalShare = new byte[bytesLength];
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, terminalShare, (short) 0, bytesLength);
        
        java.security.KeyPair keyPair = generateKeyPair();
        
        javax.crypto.KeyAgreement dh = javax.crypto.KeyAgreement.getInstance("ECDH");
        dh.init(keyPair.getPrivate());

        java.security.PublicKey terminalPK = extractTerminalPK(terminalShare);
        
        dh.doPhase((java.security.Key) terminalPK, true);
        
        secret = dh.generateSecret();
        
        Util.arrayCopy(keyPair.getPublic().getEncoded(), (short) 0, buffer, ISO7816.OFFSET_CDATA, (short) 75);
        
        setDesKey(secret);       
        
        System.out.println("Secret on card side: " + this.change(secret));
        System.out.println("CARD: Card public key: " + this.change(keyPair.getPublic().getEncoded()));
        
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) terminalPK.getEncoded().length);
        
        byte[] derivedKey = deriveSessionKey(keyPair.getPublic().getEncoded(), terminalPK.getEncoded());
        System.out.printf("Final key: %s%n", change(derivedKey));
    }
    
    /**
     * https://neilmadden.blog/2016/05/20/ephemeral-elliptic-curve-diffie-hellman-key-agreement-in-java/?fbclid=IwAR24l7jCZR7i9h3gmBRFkjevo1UcN7n1avPc9Npc6IG-4pjScP-aUS8xBws
     */
    private byte[] deriveSessionKey(byte[] cardPK, byte[] terminalPK) throws Exception {
        java.security.MessageDigest hash = java.security.MessageDigest.getInstance("SHA-256");
        hash.update(secret);
        // Simple deterministic ordering
        List<ByteBuffer> keys = Arrays.asList(ByteBuffer.wrap(cardPK), ByteBuffer.wrap(terminalPK));
        Collections.sort(keys);
        hash.update(keys.get(0));
        hash.update(keys.get(1));
        return hash.digest();
    }
    
    private java.security.KeyPair generateKeyPair() throws Exception{
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec paramSpec = new ECGenParameterSpec("secp192r1");
        generator.initialize(paramSpec);
        return generator.generateKeyPair();
    }
    
    private java.security.PublicKey extractTerminalPK(byte[] terminalData) throws Exception {
        X509EncodedKeySpec formatted_public = new X509EncodedKeySpec(terminalData);
        KeyFactory kf = KeyFactory.getInstance("EC");
        return kf.generatePublic(formatted_public);
    }
   
    private void sendTerminationInfo(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short bytesLength = apdu.setIncomingAndReceive();
        byte[] msg = new byte[4];
        msg[0] = (byte) 0xff;
        msg[1] = (byte) 0xff;
        msg[2] = (byte) 0xff;
        msg[3] = (byte) 0xff;
        Util.arrayCopy(msg, (short) 0, buffer, (short) 0x00, (short) 0x04);
        apdu.setOutgoingAndSend((short) 0x00, (short) 0x04);

    }
    
    private void addBalance(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        byte amount = buffer[2];
        
        this.cardBalance += amount;
        
        buffer[0] = this.cardBalance;
        apdu.setOutgoingAndSend((short) 0x00, (short) 0x01);    
    }
    
    private void removeBalance(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        byte amount = buffer[2];
        
        this.cardBalance -= amount;
        if (this.cardBalance < 0) {
            this.cardBalance = 0;
        }
        
        buffer[0] = this.cardBalance;
        apdu.setOutgoingAndSend((short) 0x00, (short) 0x01);   
    }  
}
