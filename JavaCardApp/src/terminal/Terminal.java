package terminal;

import applets.JavaCardApplet;
import cardTools.CardManager;
import cardTools.RunConfig;
import cardTools.Util;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import javax.crypto.KeyAgreement;
import javax.smartcardio.CardException;

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
    private  short keySize = 49+1;
    
    public Terminal() {
        this.cardManager = new CardManager(true, APPLET_AID_BYTE);
        this.runConfig = RunConfig.getDefaultConfig();
    }

    public static void main(String[] args) {
        try {
            Terminal terminal = new Terminal();
            
            terminal.connectToCard();
            terminal.sendRandomAPDU();
            
        } catch (Exception ex) {
            System.out.println("Exception : " + ex);
        }
    }
    
    
    private String change(byte[] key){
        if(key==null){
        return null;
        }
    return DatatypeConverter.printHexBinary(key);
    }
    
    private void ecdhGenerate() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(192);
            KeyPair pair = generator.generateKeyPair();
            byte[] myPk = pair.getPublic().getEncoded();
            byte[] mySk = pair.getPublic().getEncoded();
            String publicK = change(myPk);
            String privateK = change(mySk);
            System.out.println("Public: " + publicK);
            System.out.println("Private: " + privateK);       
        } catch (Exception ex) {
             System.out.println("Exception : " + ex);
        }
        
    }
    
    private byte[] createWFromPublicKey(ECPublicKey key)
    {
        ECPoint toCard = key.getW();
        
        // TODO endianess? 
        byte[] x = toCard.getAffineX().toByteArray();
        byte[] y = toCard.getAffineY().toByteArray();
        
        
        byte[] terminalPublicKey = new byte[this.keySize];
        terminalPublicKey[0] = (byte) 0x04;
        System.arraycopy(x, 0, terminalPublicKey, 1 , x.length);
        System.arraycopy(y, 0, terminalPublicKey, x.length, y.length);

        
        return terminalPublicKey;
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
        
        
        // key agreement - generate terminal keypair
        KeyAgreement dh = KeyAgreement.getInstance("ECDH");
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("EC");
        keyGenerator.initialize(new ECGenParameterSpec ("secp192r1"));
        
        KeyPair terminalKeyPair = keyGenerator.generateKeyPair();
        dh.init(terminalKeyPair.getPrivate());
        
        ECPublicKey terminalPublicKey = (ECPublicKey) terminalKeyPair.getPublic();
        byte[] publicWTerminalKey = createWFromPublicKey(terminalPublicKey);
        
        
        
        
        final ResponseAPDU initECDH = cardManager.transmit(new CommandAPDU(0x00, 0xEA, 0x00, 0x00, publicWTerminalKey));
        

        
        
        
       
        
        
        
        // extract key from card

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(new ECGenParameterSpec ("secp192r1"));
        KeyPair keyPair = keyGen.genKeyPair();
       
        byte[] x = new byte[24];
        byte[] y = new byte[24];
        System.arraycopy(initECDH.getData(), 1, x, 0, x.length);
        System.arraycopy(initECDH.getData(), 1 + x.length, y, 0, y.length);
        BigInteger b_x = new BigInteger(x);
        BigInteger b_y = new BigInteger(y);
        
         ECPoint points = new ECPoint (b_x,b_y);
        
        ECParameterSpec specs = ((ECPublicKey) keyPair.getPublic()).getParams();
        ECPublicKeySpec keySpecs = new ECPublicKeySpec (points, specs);

        ECPublicKey cardPublicKey = (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(keySpecs);
        


   
        
        //final ResponseAPDU testWrongPIN = cardManager.transmit(new CommandAPDU(0x00, 0x20, 0x00, 0x00, wrongCardPIN));
        //final ResponseAPDU testOKPIN = cardManager.transmit(new CommandAPDU(0x00, 0x20, 0x00, 0x00, cardPIN));


        
    }
    
    private void sendRandomAPDU() throws CardException {
        // Transmit single APDU
       /* final ResponseAPDU response = cardManager.transmit(new CommandAPDU(Util.hexStringToByteArray(STR_APDU_GETRANDOM)));
        byte[] data = response.getData();
        
        final ResponseAPDU response2 = cardManager.transmit(new CommandAPDU(0xB0, 0x54, 0x00, 0x00, data)); // Use other constructor for CommandAPDU
        
        System.out.println(response);*/
    }
}
