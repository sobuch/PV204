package terminal;

import applets.JavaCardApplet;
import cardTools.CardManager;
import cardTools.RunConfig;
import cardTools.Util;
import javax.smartcardio.CardException;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

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
            terminal.sendRandomAPDU();
            
        } catch (Exception ex) {
            System.out.println("Exception : " + ex);
        }
    }

    private void connectToCard() throws Exception {

        runConfig.setAppletToSimulate(JavaCardApplet.class);

        // Connect to card
        System.out.print("Connecting to card...");
        if (!cardManager.Connect(runConfig)) {
            System.out.println(" Failed.");
        }
        System.out.println(" Done.");

        
    }
    
    private void sendRandomAPDU() throws CardException {
        // Transmit single APDU
        final ResponseAPDU response = cardManager.transmit(new CommandAPDU(Util.hexStringToByteArray(STR_APDU_GETRANDOM)));
        byte[] data = response.getData();
        
        final ResponseAPDU response2 = cardManager.transmit(new CommandAPDU(0xB0, 0x54, 0x00, 0x00, data)); // Use other constructor for CommandAPDU
        
        System.out.println(response);
    }
}
