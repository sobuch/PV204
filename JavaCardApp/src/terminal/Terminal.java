package terminal;

import applets.JavaCardApplet;
import cardTools.CardManager;
import cardTools.RunConfig;
import cardTools.Util;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import javax.crypto.KeyAgreement;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.xml.bind.DatatypeConverter;

/**
 * Terminal class.
 */
public class Terminal {
    private static String APPLET_AID = "482871d58ab7465e5e05";
    private static byte APPLET_AID_BYTE[] = Util.hexStringToByteArray(APPLET_AID);

    private static final String STR_APDU_GETRANDOM = "B054100000";
    private final CardManager cardManager;
    private final RunConfig runConfig;
    
    public Terminal() {
        this.cardManager = new CardManager(true, APPLET_AID_BYTE);
        this.runConfig = RunConfig.getDefaultConfig();
    }

    public static void main(String[] args) {
        try {
            Terminal terminal = new Terminal();
            
            terminal.connectToCard();
            terminal.initEcdhSession();
            
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
       
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec paramSpec = new ECGenParameterSpec("secp256r1");
        generator.initialize(paramSpec);
        KeyPair keyPair = generator.generateKeyPair();
        
        KeyAgreement dh = KeyAgreement.getInstance("ECDH");
        dh.init(keyPair.getPrivate());
        byte[] terminalShare = encodePublicKey((ECPublicKey) keyPair.getPublic());
                
        final ResponseAPDU response = cardManager.transmit(new CommandAPDU(0x00, 0x21, 0x00, 0x00, terminalShare));
        final byte[] cardShare = response.getData();
        System.out.println("Card shared ECDH.");
              
        // extracting from card share
        byte[] x = new byte[24];
        byte[] y = new byte[24];
        System.arraycopy(response.getData(), 1, x, 0, x.length);
        System.arraycopy(response.getData(), 1 + x.length, y, 0, y.length);
        BigInteger b_x = new BigInteger(x);
        BigInteger b_y = new BigInteger(y);
        
         ECPoint points = new ECPoint (b_x,b_y);
        
        ECParameterSpec specs = ((ECPublicKey) keyPair.getPublic()).getParams();
        ECPublicKeySpec keySpecs = new ECPublicKeySpec (points, specs);

        // card public key
        ECPublicKey cardPublicKey = (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(keySpecs);
        dh.doPhase(cardPublicKey, true);
        byte[] secret = dh.generateSecret();

        System.out.println(this.change(secret));
    }
    
    private String change(byte[] key){
        if (key == null){
            return null;
        }
        return DatatypeConverter.printHexBinary(key);
    }
    
    private KeyPair createRandomKeyPairEC() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec paramSpec = new ECGenParameterSpec("prime256v1");
        generator.initialize(paramSpec);
        return generator.generateKeyPair();
    }

    /*
    https://www.codota.com/code/java/methods/java.security.spec.ECPoint/getAffineX
    */
    private byte[] encodePublicKey(ECPublicKey publicKey) {
        ECPoint w = publicKey.getW();
        
        BigInteger x = w.getAffineX();
        BigInteger y = w.getAffineY();
        
        byte[] XBytes = x.toByteArray();
        byte[] YBytes = y.toByteArray();
        
        int elementSize = 29;
        byte[] encodedBytes = new byte[elementSize * 2 + 1];
        
        // Uncompressed format
        encodedBytes[0] = 0x04;
        
        System.arraycopy(XBytes, 0, encodedBytes, 1 + elementSize - XBytes.length, XBytes.length);
        System.arraycopy(YBytes, 0, encodedBytes, 1 + 2 * elementSize - YBytes.length, YBytes.length);
        
        return encodedBytes;
    }
    
    public KeyPair getRandomEcKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(256);
        return keyGen.generateKeyPair();
    }
}
