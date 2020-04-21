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
    
    
    private OwnerPIN accessPIN;
    
    
    public JavaCardApplet(byte[] buffer, short offset, byte length) {
        accessPIN = new OwnerPIN(SEC_PIN_RETRIES, SEC_PIN_MAX_LENGTH);
        accessPIN.update(buffer, offset, length);
        
        register();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new JavaCardApplet(bArray, bOffset, bLength);
    }

    public void process(APDU apdu) {

        
        byte[] apduBuffer = apdu.getBuffer();
        byte instruction = apduBuffer[ISO7816.OFFSET_INS];
        try {
            switch (instruction) {
            case I_PIN_VERIFY:
                verifyPIN(apdu);
                break;
            case I_ECDH_INIT:
                initECDH(apdu);
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
        // TODO clear or overwrite session data in RAM with bogus data
        throw new UnsupportedOperationException("Not supported yet.");
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
        Util.arrayCompare(buffer, ISO7816.OFFSET_CDATA, terminalShare, (short) 0, bytesLength);
        
        KeyPair keyPair = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
        keyPair.genKeyPair();
        
        KeyAgreement dh = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH, false);
        dh.init(keyPair.getPrivate());
        
        byte[] secret = new byte[20];
        dh.generateSecret(terminalShare, (short) 0, (short) terminalShare.length, secret, (byte) 0);
        
        byte[] cardShare = new byte[57];
        short len = ((ECPublicKey) keyPair.getPublic()).getW(cardShare, (short) 0);
        
        Util.arrayCopy(cardShare, (short) 0, buffer, ISO7816.OFFSET_CDATA, (short) 57);
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) len);
    }
}
