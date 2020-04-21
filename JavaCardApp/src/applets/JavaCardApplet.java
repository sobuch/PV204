package applets;



import javacard.framework.*;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;

public class JavaCardApplet extends javacard.framework.Applet implements MultiSelectable{

    
    
    // usual card values
    private static final byte SEC_PIN_MAX_LENGTH = (byte) 0x04;
    private static final byte SEC_PIN_RETRIES = (byte) 0x03;
    final static short SEC_PIN_VERIFY_FAILED = (short)0x9704;
    
    // instructions
    private static final byte I_PIN_VERIFY = (byte)0x20;
    private static final byte DF_INIT_A = (byte)0xEA;
    private static final byte DF_INIT_B = (byte)0xEB;

    
    
    // ECDH
    
    KeyPair cardKeyPair;
    KeyPair terminalKeyPair;
    KeyAgreement dh;

    KeyAgreement cardKA, terminalKA;
    
    ECPublicKey cardPublicKey;
    ECPrivateKey cardPrivateKey;
    
    ECPublicKey termianlPublicKey;
    
    private byte secret[] = null;
    
    
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
        
        switch (instruction) {
            case I_PIN_VERIFY:
                verifyPIN(apdu);
                break;
            case DF_INIT_A:

                ecdh_init(apdu);
                break;
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
    
    private void ecdh_init(APDU apdu)
    {
 
        // generate keypair
        cardKeyPair = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_192);
        cardKeyPair.genKeyPair();
        
        // get public and private key, based on size 192
        cardPublicKey = (ECPublicKey) cardKeyPair.getPublic();
        cardPrivateKey = (ECPrivateKey) cardKeyPair.getPrivate();
        
        
        
        
        
        // extract received key
        byte[] buffer = apdu.getBuffer();
        byte dataLength = (byte)apdu.setIncomingAndReceive();

        byte[] pk = new byte[dataLength];

        //for (int i = 5; i < dataLength+5; i++) {
        //    terminalPublicKey[i-5] = buffer[i];
        //}
        
        //why no work???
        //termianlPublicKey.setW(buffer, (short)0x05, (short)0x33);
        
        Util.arrayCopy(buffer, (short)0x05, pk, (short) 0, dataLength);
        //this has to go manually
        terminalKeyPair = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_192);
        terminalKeyPair.genKeyPair();
    
        dh = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH, false);
        dh.init(cardPrivateKey);
            
        this.secret = new byte[21];
        dh.generateSecret(pk, (short) 0, (short) pk.length, this.secret, (short) 0);
        
        
        
        
        short ln = cardPublicKey.getW(buffer, (short) 0x0000);
        apdu.setOutgoingAndSend((short) 0x0000, ln);

        
        
    }
    
    
    private void verifyPIN(APDU apdu) 
    {
        byte[] buffer = apdu.getBuffer();
        byte bytesRead = (byte)apdu.setIncomingAndReceive();
        
        if (accessPIN.check(buffer, ISO7816.OFFSET_CDATA, bytesRead) == false) {
            ISOException.throwIt(SEC_PIN_VERIFY_FAILED);
        } 
    }
}
