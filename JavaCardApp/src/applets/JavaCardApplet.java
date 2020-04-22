package applets;


import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
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
    
    private byte desKeyLen;
    private byte[] desKey = null;
    private byte[] desICV = null;
 
    private Cipher desEcbCipher;
    private Cipher desCbcCipher;
    private Key tempDesKey2 = null;
    private Key tempDesKey3 = null;
    private OwnerPIN accessPIN;
    
    
    public JavaCardApplet(byte[] buffer, short offset, byte length) {
        accessPIN = new OwnerPIN(SEC_PIN_RETRIES, SEC_PIN_MAX_LENGTH);
        accessPIN.update(buffer, offset, length);
        
        register();
    }

    
        // with the help of https://javacardos.com/wiki/javacard-api-samples/des
    private void setDesKey(APDU apdu)
    {
        byte[] buffer = apdu.getBuffer();
        short bytesLength = apdu.setIncomingAndReceive();
        
        if (bytesLength == 16 || bytesLength == 24) {
            this.desKeyLen = (byte) bytesLength;
            desKey = new byte[bytesLength];
        } else {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, desKey, (short)0, bytesLength);
        
    }
    
    private Key getDesKey()
    {
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
    
    private void setDesICV(APDU apdu)
    {
        byte[] buffer = apdu.getBuffer();
        short bytesLength = apdu.setIncomingAndReceive();
        if (bytesLength != 8)
        {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        //Copy the incoming ICV value to the global variable 'desICV'
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, desICV, (short)0, (short)8);
    }
    
    private void decryptDes(APDU apdu) 
    {
        byte[] buffer = apdu.getBuffer();
        short bytesLength = apdu.setIncomingAndReceive();
        Key key = getDesKey();
        
        byte mode = Cipher.MODE_DECRYPT;
        Cipher cipher = this.desCbcCipher;
        
        cipher.init(key, mode, desICV, (short) 0, (short) 8);
        cipher.doFinal(buffer, ISO7816.OFFSET_CDATA, bytesLength, buffer, (short) 0);
        
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
                case INS_SET_DES_KEY:
                    //SET_DES_KEY
                    setDesKey(apdu);
                    break;
                case INS_SET_DES_ICV:
                    //SET_DES_ICV
                    setDesICV(apdu);
                    break;
                case INS_DO_DES_CIPHER:
                    //DO_DES_CIPHER
                    decryptDes(apdu);
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
    
    
    private void verifyPIN(APDU apdu) 
    {
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
        
        KeyPair keyPair = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_192);
        keyPair.genKeyPair();
        
        KeyAgreement dh = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH, false);
        dh.init(keyPair.getPrivate());
        
        byte[] secret = new byte[20];
        dh.generateSecret(terminalShare, (short) 0, (short) terminalShare.length, secret, (byte) 0);
        
        byte[] cardShare = new byte[49];
        short len = ((ECPublicKey) keyPair.getPublic()).getW(cardShare, (short) 0);
        
        Util.arrayCopy(cardShare, (short) 0, buffer, ISO7816.OFFSET_CDATA, (short) 49);
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) len);
    }
    
    
    private void sendTerminationInfo(APDU apdu)
    {
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
    
}
