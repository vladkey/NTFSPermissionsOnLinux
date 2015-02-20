package wwk;

/**
 * Provides native extended attribute access for Java
 */
public class Xattrj {

    private boolean libLoaded = false;

    public Xattrj() {
        if(!libLoaded){
            System.loadLibrary("wwkxattr");
        }
    }

    public native byte[] readAttribute(String file, String attrKey);

    public native String[] listAttributes(String file);

    public native boolean writeAttribute(String file, String attrKey, byte[] attrValue);

}