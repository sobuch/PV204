package applets;



import javacard.framework.*;

public class JavaCardApplet extends javacard.framework.Applet implements MultiSelectable{

    public JavaCardApplet(byte[] buffer, short offset, byte length) {
        register();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new JavaCardApplet(bArray, bOffset, bLength);
    }

    public void process(APDU apdu) {
        byte[] reply = new byte[]{1, 9, 8, 7, 1};
        Util.arrayCopyNonAtomic(
            reply, (short) 0,
            apdu.getBuffer(), (short) 0,
            (short) reply.length);
        apdu.setOutgoingAndSend((short) 0, (short) reply.length);
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
}
