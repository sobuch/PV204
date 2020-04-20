package cardTools;

import com.licel.jcardsim.io.CAD;
import com.licel.jcardsim.io.JavaxSmartCardInterface;
import javacard.framework.AID;

import javax.smartcardio.*;

public class CardManager {
    protected boolean bDebug = false;
    protected byte[] appletId = null;
    protected Long lastTransmitTime = (long) 0;
    protected CommandAPDU lastCommand = null;
    protected CardChannel channel = null;
    
    public CardManager(boolean bDebug, byte[] appletAID) {
        this.bDebug = bDebug;
        this.appletId = appletAID;
    }

    /**
     * Card connect
     * @param runConfig run configuration
     * @return true if connected
     * @throws Exception exceptions from underlying connects
     */
    public boolean Connect(RunConfig runConfig) throws Exception {
        boolean bConnected = false;
        channel = ConnectJCardSimLocalSimulator(runConfig.appletToSimulate, runConfig.installData);
        if (channel != null) {
            bConnected = true;
        }
        return bConnected;
    }
    
    public void Disconnect(boolean bReset) throws CardException {
        channel.getCard().disconnect(bReset); // Disconnect from the card
    }

    private CardChannel ConnectJCardSimLocalSimulator(Class appletClass, byte[] installData) throws Exception {
        System.setProperty("com.licel.jcardsim.terminal.type", "2");
        CAD cad = new CAD(System.getProperties());
        JavaxSmartCardInterface simulator = (JavaxSmartCardInterface) cad.getCardInterface();
        if (installData == null) {
            installData = new byte[0];
        }
        AID appletAID = new AID(appletId, (short) 0, (byte) appletId.length);

        AID appletAIDRes = simulator.installApplet(appletAID, appletClass, installData, (short) 0, (byte) installData.length);
        simulator.selectApplet(appletAID);

        return new CardChannelLocal(simulator);
    }
    
    public ResponseAPDU transmit(CommandAPDU cmd)
            throws CardException {

        lastCommand = cmd;
        if (bDebug == true) {
            log(cmd);
        }

        long elapsed = -System.currentTimeMillis();
        ResponseAPDU response = channel.transmit(cmd);
        elapsed += System.currentTimeMillis();
        lastTransmitTime = elapsed;

        if (bDebug == true) {
            log(response, lastTransmitTime);
        }

        return response;
    }

    private void log(CommandAPDU cmd) {
        System.out.printf("--> %s\n", Util.toHex(cmd.getBytes()),
                cmd.getBytes().length);
    }

    private void log(ResponseAPDU response, long time) {
        String swStr = String.format("%02X", response.getSW());
        byte[] data = response.getData();
        if (data.length > 0) {
            System.out.printf("<-- %s %s (%d) [%d ms]\n", Util.toHex(data), swStr,
                    data.length, time);
        } else {
            System.out.printf("<-- %s [%d ms]\n", swStr, time);
        }
    }

    private void log(ResponseAPDU response) {
        log(response, 0);
    }
}
