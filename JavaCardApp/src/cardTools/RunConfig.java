package cardTools;

/**
 * Applet run configuration.
 */
public class RunConfig {
    public int numRepeats = 1;
    public Class appletToSimulate;
    private boolean bReuploadApplet = false;
    byte[] installData = null;
    
    public static RunConfig getDefaultConfig() {
        RunConfig runCfg = new RunConfig();
        runCfg.appletToSimulate = null;
        runCfg.installData = new byte[15]; // bogus install data
        return runCfg;
    }

    public RunConfig setAppletToSimulate(Class appletToSimulate) {
        this.appletToSimulate = appletToSimulate;
        return this;
    }
}
