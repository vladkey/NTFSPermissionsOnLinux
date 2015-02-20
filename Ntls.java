

import java.io.*;
import java.util.*;

import wwk.*;

public class Ntls {

public static void main(String[] args) throws Exception {
 String fn = args.length > 0 ? args[0] : "/mnt/d/Work";
 System.out.println("FN: " + fn);


 Xattrj dev = new Xattrj();
 String[] a = dev.listAttributes(fn);
 if (a != null) {
     System.out.println("Total attrs: " + a.length);
    for (String an : a)
       System.out.println(an);
 } else System.out.println("listAttributes is null, IMPLEMENT");

 byte[] aclBytes = dev.readAttribute(fn, "system.ntfs_acl");
 NtfsAcl acl = new NtfsAcl(aclBytes);
 acl.print();
}

public static class NtfsAcl {
    public int revision;
    public int flags;
    public int offUSID;
    public int offGSID;
    public int offSACL;
    public int offDACL;
    public String ownerSID;
    public String groupSID;
    public AceList dacl;

 public void print() {
     System.out.println("ACL revision: \t" + revision);
     System.out.println("ACL flags: \t" + hex(flags));
     System.out.println("\t Off USID: " + hex(offUSID));
     System.out.println("\t Off GSID: " + hex(offGSID));
     System.out.println("\t Off SACL: " + hex(offSACL));
     System.out.println("\t Off DACL: " + hex(offDACL));
     System.out.println("Owner SID: " + ownerSID);
     System.out.println("Owner GID: " + groupSID);
     dacl.print();
 }

 public NtfsAcl(byte[] acl) throws IOException {
     MyDataInputStream is = new MyDataInputStream(new ByteArrayInputStream(acl));
     revision = is.readUnsignedShortBE();
     flags = is.readUnsignedShortBE();
     offUSID = is.readIntBE();
     offGSID = is.readIntBE();
     offSACL = is.readIntBE();
     offDACL = is.readIntBE();

     is.seek(offUSID);
     ownerSID = readSID(is);
     is.seek(offGSID);
     groupSID = readSID(is);

     System.out.println("DACL");
     is.seek(offDACL);
     dacl = new AceList(is);
 }

 public static class AceList {
     int revision;
     int daclSize;
     int daclEntryCount;
     List<Ace> aceList = new ArrayList<>();

     public AceList(MyDataInputStream is) throws IOException {
         revision = is.readUnsignedByte();
         is.readUnsignedByte(); // alignment1
         daclSize = is.readUnsignedShortBE();
         daclEntryCount = is.readUnsignedShortBE();
         is.readUnsignedShort(); // alignment2
         for (int i = 0; i < daclEntryCount; i++) {
             Ace ace = new Ace(is);
             aceList.add(ace);
         }
     }
     public void print() {
         System.out.println("\t revision: \t" + revision);
         System.out.println("\t ACL size: " + daclSize);
         System.out.println("\t ACE cnt: " + daclEntryCount);
         for (int i = 0; i < daclEntryCount; i++) {
             System.out.println("\t ACE  " + (i+1));
             Ace ace = aceList.get(i);
             ace.print();
         }
     }
 }

 public static class Ace {
     public int aceType;
     public int aceFlags;
     public int aceSize;
     public int aceRights;
     public String sid;

     public Ace(MyDataInputStream is) throws IOException {
         aceType = is.readUnsignedByte();
         aceFlags = is.readUnsignedByte();
         aceSize = is.readUnsignedShortBE();
         aceRights = is.readIntBE();
         sid = readSID(is);
     }
     public void print() {
         System.out.println("\t\t type: " + aceType);
         System.out.println("\t\t flags: " + hex(aceFlags));
         System.out.println("\t\t size: " + hex(aceSize));
         System.out.println("\t\t Access rights: " + hex(aceRights));
         System.out.println("\t\t SID: " + sid);
     }
 }

 private static String readSID(MyDataInputStream is) throws IOException {
     int revision = is.readUnsignedByte();
     String result = "S-" + revision;
     int sub_authority_count = is.readUnsignedByte();
     int auth_high = is.readUnsignedShort();
     int auth_low = is.readInt();
     long authority = auth_low << 32 | auth_high;
     result += "-" + authority;
     for (int i = 0; i < sub_authority_count; i++) {
         int subAuthPart = is.readIntBE();
         result += "-" + subAuthPart; // Integer.toHexString(subAuthPart);
     }
     return result;
}

 static String hex(int v) {
     return "0x" + Integer.toHexString(v);
 }
}

}

class MyDataInputStream extends DataInputStream {

    public MyDataInputStream(InputStream in) {
        super(in);
        mark(0);
    }

    public void seek(int offset) throws IOException {
        reset();
        skip(offset);
    }

    public int readUnsignedShortBE() throws IOException {
        int u16 = super.readUnsignedShort();
        int b0 = u16 & 0xFF, b1 = (u16 & 0xFF00) >> 8;
        int result = (b0 << 8) | b1;
        return result;
    }

    public int readIntBE() throws IOException {
        int u32 = super.readInt();
        int b0 = u32 & 0xFF, b1 = (u32 & 0xFF00) >> 8, b2 = (u32 & 0xFF0000) >> 16, b3 = (u32 & 0xFF000000) >>> 24;
        int result = b0 << 24 | b1 << 16 | b2 << 8 | b3;
        return result;
    }
}
enum SECURITY_DESCRIPTOR_CONTROL {
    SE_OWNER_DEFAULTED(0x0001, "Owner field was provided by a defaulting mechanism"),
    SE_GROUP_DEFAULTED(0x0002, "Group field was provided by a defaulting mechanism"),
    SE_DACL_PRESENT(0x0004, "DACL is present"),
    SE_DACL_DEFAULTED(0x0008, "DACL field was provided by a defaulting mechanism"),
    SE_SACL_PRESENT(0x0010, "SACL is present"),
    SE_SACL_DEFAULTED(0x0020, "SACL field was provided by a defaulting mechanism"),
    SE_DACL_AUTO_INHERIT_REQ(0x0100, "Required DACL is set up for propagation of inheritable ACEs to existing child objects"),
    SE_SACL_AUTO_INHERIT_REQ(0x0200, "Required SACL is set up for propagation of inheritable ACEs to existing child objects"),
    SE_DACL_AUTO_INHERITED(0x0400, "DACL is set up for propagation of inheritable ACEs to existing child objects"),
    SE_SACL_AUTO_INHERITED(0x0800, "SACL is set up for propagation of inheritable ACEs to existing child objects"),
    SE_DACL_PROTECTED(0x1000, "Prevents ACEs of the parent container DACL from being applied to the object DACL."),
    SE_SACL_PROTECTED(0x2000, "Prevents ACEs of the parent container SACL from being applied to the object DACL."),
    SE_RM_CONTROL_VALID(0x4000, "resource manager control is valid"),
    SE_SELF_RELATIVE(0x8000, "self-relative form");

    int mask;
    String meaning;
    SECURITY_DESCRIPTOR_CONTROL(int mask, String meaning) {
        this.mask = mask;
        this.meaning = meaning;
    }
    List<SECURITY_DESCRIPTOR_CONTROL> decode(int flags) {
        List<SECURITY_DESCRIPTOR_CONTROL> result = new ArrayList<>();
        for (SECURITY_DESCRIPTOR_CONTROL s : values()) {
            if ((flags & s.mask) != 0)
                result.add(s);
        }
        return result;
    }
};