

import java.io.*;
import java.util.*;

import wwk.*;

public class Ntls {

public static int DEBUG = 0;

public static void main(String[] args) throws Exception {
 String fn = args.length > 0 ? args[0] : "/mnt/d/Work";

 DEBUG = args.length > 1 && "-vvv".equalsIgnoreCase(args[1]) ? 3 : 0;

 File f = new File(fn);
 boolean isDir = f.isDirectory();
 System.out.println((isDir ? "Directory name" : "File name") + ": " + fn);


 Xattrj dev = new Xattrj();
 String[] a = dev.listAttributes(fn);
 if (a != null) {
     System.out.println("Total attrs: " + a.length);
    for (String an : a)
       System.out.println(an);
 } else System.out.println("listAttributes is null, IMPLEMENT");

 byte[] aclBytes = dev.readAttribute(fn, "system.ntfs_acl");
 NtfsAclAttribute acl = new NtfsAclAttribute(aclBytes, isDir);
 try {
     readUserMappingFile();
 } catch (IOException e) {
     System.out.println("WARNING: UserMapping file not read: " + e.getMessage());
 }
 acl.print();
 boolean success = dev.writeAttribute(fn, "wwkxattr", "success".getBytes());
 System.out.println("writeAttrib: " + success);
}

public static class NtfsAclAttribute {
    public int revision;
    public int flags;
    public int offUSID;
    public int offGSID;
    public int offSACL;
    public int offDACL;
    public String ownerSID;
    public String groupSID;
    public AceList dacl;
    public AceList sacl;

 public void print() {
     if (DEBUG > 2) System.out.println("ACL revision: \t" + revision);
     System.out.println("ACL flags: \t" + hex(flags) + ": " + SECURITY_DESCRIPTOR_CONTROL.decode(flags));
     if (DEBUG > 2) {
         System.out.println("\t Off USID: " + hex(offUSID));
         System.out.println("\t Off GSID: " + hex(offGSID));
         System.out.println("\t Off SACL: " + hex(offSACL));
         System.out.println("\t Off DACL: " + hex(offDACL));
     }
     System.out.println("Owner SID: " + decode(ownerSID));
     System.out.println("Owner GID: " + decode(groupSID));
     if (dacl != null) {
         if (DEBUG > 2) System.out.println("DACL");
         dacl.print();
     }
     if (sacl != null) {
         if (DEBUG > 2) System.out.println("SACL");
         sacl.print();
     }
 }

 public NtfsAclAttribute(byte[] acl, boolean isDir) throws IOException {
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

     if (offDACL > 0) {
         is.seek(offDACL);
         dacl = new AceList(is, isDir);
     }
     if (offSACL > 0) {
         is.seek(offSACL);
         sacl = new AceList(is, isDir);
     }
 }

 public static class AceList {
     int revision;
     int aclSize;
     int aclEntryCount;
     List<Ace> aceList = new ArrayList<>();

     public AceList(MyDataInputStream is, boolean isDir) throws IOException {
         revision = is.readUnsignedByte();
         is.readUnsignedByte(); // alignment1
         aclSize = is.readUnsignedShortBE();
         aclEntryCount = is.readUnsignedShortBE();
         is.readUnsignedShort(); // alignment2
         for (int i = 0; i < aclEntryCount; i++) {
             Ace ace = new Ace(is, isDir);
             aceList.add(ace);
         }
     }

     public void print() {
         if (DEBUG > 2) {
             System.out.println("\t revision: \t" + revision);
             System.out.println("\t ACL size: " + aclSize);
             System.out.println("\t ACE cnt: " + aclEntryCount);
         }
         for (int i = 0; i < aclEntryCount; i++) {
             if (DEBUG > 2) System.out.println("\t ACE  " + (i+1));
             Ace ace = aceList.get(i);
             ace.print();
         }
     }
 } // class AceList

 public static class Ace {
     int aceType;
     int aceFlags;
     int aceSize;
     int aceRights;
     String sid;
     int objectType;

     public Ace(MyDataInputStream is, boolean isDir) throws IOException {
         this.objectType = isDir ? ACCESS_MASK_DEST.DIR : ACCESS_MASK_DEST.FILE;
         aceType = is.readUnsignedByte();
         aceFlags = is.readUnsignedByte();
         aceSize = is.readUnsignedShortBE();
         aceRights = is.readIntBE();
         sid = readSID(is);
     }

     public void print() {
         if (DEBUG > 2) {
             printDebug();
         } else {
             printNormal();
         }
     }

     public void printDebug() {
        System.out.println("\t\t type: " + decodeType(aceType));
        System.out.println("\t\t flags: " + hex(aceFlags) + ": "  + ACE_FLAGS.decode(aceFlags));
        System.out.println("\t\t size: " + hex(aceSize));
        System.out.println("\t\t Access rights: " + hex(aceRights) + ": " + ACCESS_MASK.decode(aceRights, objectType));
        System.out.println("\t\t SID: " + decode(sid));
     }

     public void printNormal() {
         System.out.println(" " + decode(sid) + ": " + decodeType(aceType) + " " +
             ACCESS_MASK.decode(aceRights, objectType) + " * " + ACE_FLAGS.decode(aceFlags));
      }

     public static String decodeType(int aceType) {
        return aceType == 0 ? "Allow" : aceType == 1 ? "Deny" : "??? " + aceType;
     }
 }  // class Ace

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
} // NtfsAclAttribute


 public static String decode(String sid) {
    String result = WELL_KNOWN_SIDs.get(sid);
    if(result == null)
        result = UserMapping.get(sid);
    if(result == null)
        result = sid;
    return result;
 }

 static void readUserMappingFile() throws IOException {
     try (LineNumberReader r = new LineNumberReader(new InputStreamReader(new FileInputStream("UserMapping")))) {
         while (true) {
             String l = r.readLine();
             if (l == null)
                 break;
             if (l.trim().startsWith("#"))
                 continue;
             String parts[] = l.trim().split(":");
             String username = parts[0], groupname = parts[1], sid = parts[2];
             if (username.isEmpty()) {
                 UserMapping.put(sid, "Group " + groupname);
             } else if (groupname.isEmpty()) {
                 UserMapping.put(sid, "User " + username);
             } else {
                 UserMapping.put(sid, "User " + username + " (group " + groupname + ")");
             }
         }
     }
 }
 static final Map<String, String> UserMapping = new HashMap<>();

 static final Map<String, String> WELL_KNOWN_SIDs = new HashMap<>();
 static {
    /* Users. */
    WELL_KNOWN_SIDs.put("S-1-5-21-*-*-*-500", "Built-In Administrators"); // "DOMAIN_USER_RID_ADMIN", "0x1f4");
    WELL_KNOWN_SIDs.put("S-1-5-21-*-*-*-501", "Built-In Guests"); // "DOMAIN_USER_RID_GUEST", "0x1f5");
    WELL_KNOWN_SIDs.put("S-1-5-21-*-*-*-502", "Built-In KRBTGT"); // "DOMAIN_USER_RID_KRBTGT", "0x1f6");

    /* Groups. */
    WELL_KNOWN_SIDs.put("S-1-5-32-512", "Domain Administrators"); // "DOMAIN_GROUP_RID_ADMINS", "0x200");
    WELL_KNOWN_SIDs.put("S-1-5-32-513", "Domain Users"); // "DOMAIN_GROUP_RID_USERS", "0x201");
    WELL_KNOWN_SIDs.put("S-1-5-32-514", "Domain Guests"); // "DOMAIN_GROUP_RID_GUESTS", "0x202");
    WELL_KNOWN_SIDs.put("S-1-5-32-515", "Domain Computers"); // "DOMAIN_GROUP_RID_COMPUTERS", "0x203");
    WELL_KNOWN_SIDs.put("S-1-5-32-516", "Domain Controllers"); // "DOMAIN_GROUP_RID_CONTROLLERS", "0x204");

    WELL_KNOWN_SIDs.put("S-1-5-32-517", "Domain Cert Admins"); // "DOMAIN_GROUP_RID_CERT_ADMINS", "0x205");
    WELL_KNOWN_SIDs.put("S-1-5-32-518", "Domain Schema Admins"); // "DOMAIN_GROUP_RID_SCHEMA_ADMINS", "0x206");
    WELL_KNOWN_SIDs.put("S-1-5-32-519", "Enterprise Admins"); // "DOMAIN_GROUP_RID_ENTERPRISE_ADMINS", "0x207");
    WELL_KNOWN_SIDs.put("S-1-5-32-520", "Policy Admins"); // "DOMAIN_GROUP_RID_POLICY_ADMINS", "0x208");

    /* Aliases. */
    WELL_KNOWN_SIDs.put("S-1-5-32-544", "Local Administrators"); // "DOMAIN_ALIAS_RID_ADMINS", "0x220");
    WELL_KNOWN_SIDs.put("S-1-5-32-545", "Local Users"); // "DOMAIN_ALIAS_RID_USERS", "0x221");
    WELL_KNOWN_SIDs.put("S-1-5-32-546", "Local Guests"); // "DOMAIN_ALIAS_RID_GUESTS", "0x222");
    WELL_KNOWN_SIDs.put("S-1-5-32-547", "Local Power Users"); // "DOMAIN_ALIAS_RID_POWER_USERS", "0x223");

    WELL_KNOWN_SIDs.put("S-1-5-32-548", "Account  Operators"); // "DOMAIN_ALIAS_RID_ACCOUNT_OPS", "0x224");
    WELL_KNOWN_SIDs.put("S-1-5-32-549", "System Operators"); // "DOMAIN_ALIAS_RID_SYSTEM_OPS", "0x225");
    WELL_KNOWN_SIDs.put("S-1-5-32-550", "Print Operators"); // "DOMAIN_ALIAS_RID_PRINT_OPS", "0x226");
    WELL_KNOWN_SIDs.put("S-1-5-32-551", "Backup Operators"); // "DOMAIN_ALIAS_RID_BACKUP_OPS", "0x227");

    WELL_KNOWN_SIDs.put("S-1-5-32-546", "Replicators"); // "DOMAIN_ALIAS_RID_REPLICATOR", "0x228");
    WELL_KNOWN_SIDs.put("S-1-5-32-546", "RAS Servers"); // "DOMAIN_ALIAS_RID_RAS_SERVERS", "0x229");

    WELL_KNOWN_SIDs.put("S-1-1-0", "WORLD_SID");
    WELL_KNOWN_SIDs.put("S-1-2-0", "LOCAL_SID");
    WELL_KNOWN_SIDs.put("S-1-3-0", "CREATOR_OWNER_SID");
    WELL_KNOWN_SIDs.put("S-1-3-1", "CREATOR_GROUP_SID");
    WELL_KNOWN_SIDs.put("S-1-3-2", "CREATOR_OWNER_SERVER_SID");
    WELL_KNOWN_SIDs.put("S-1-3-3", "CREATOR_GROUP_SERVER_SID");

    WELL_KNOWN_SIDs.put("S-1-5-2", "NETWORK_SID");
    WELL_KNOWN_SIDs.put("S-1-5-3", "BATCH_SID");
    WELL_KNOWN_SIDs.put("S-1-5-4", "INTERACTIVE_SID");
    WELL_KNOWN_SIDs.put("S-1-5-6", "SERVICE_SID");
    WELL_KNOWN_SIDs.put("S-1-5-7", "ANONYMOUS_LOGON_SID");// (aka null logon session)
    WELL_KNOWN_SIDs.put("S-1-5-8", "PROXY_SID");
    WELL_KNOWN_SIDs.put("S-1-5-9", "SERVER_LOGON_SID");//     (aka domain controller account)
    WELL_KNOWN_SIDs.put("S-1-5-10", "SELF_SID");//    (self RID)
    WELL_KNOWN_SIDs.put("S-1-5-11", "AUTHENTICATED_USER_SID");
    WELL_KNOWN_SIDs.put("S-1-5-12", "RESTRICTED_CODE_SID");//    (running restricted code)
    WELL_KNOWN_SIDs.put("S-1-5-13", "TERMINAL_SERVER_SID");//    (running on terminal server)

    /*
    *  (Logon IDs)     S-1-5-5-X-Y
    *
    *  (NT non-unique IDs) S-1-5-0x15-...
    *
    *  (Built-in domain)   S-1-5-0x20
    */

    WELL_KNOWN_SIDs.put("S-1-5-18", "NT System");
 } // static

} // class Ntls

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
} // class MyDataInputStream

enum ACE_FLAGS {
    OBJECT_INHERIT_ACE(0x01),
    CONTAINER_INHERIT_ACE(0x02),
    NO_PROPAGATE_INHERIT_ACE(0x04),
    INHERIT_ONLY_ACE(0x08),
    INHERITED_ACE(0x10), /* Win2k only. */

    /* The audit flags. */
    SUCCESSFUL_ACCESS_ACE_FLAG(0x40),
    FAILED_ACCESS_ACE_FLAG(0x80);

    int mask;
    private ACE_FLAGS(int mask) {
        this.mask = mask;
    }
    static List<ACE_FLAGS> decode(int flags) {
        List<ACE_FLAGS> result = new ArrayList<>();
        for (ACE_FLAGS s : values()) {
            if ((flags & s.mask) != 0)
                result.add(s);
        }
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
    static List<SECURITY_DESCRIPTOR_CONTROL> decode(int flags) {
        List<SECURITY_DESCRIPTOR_CONTROL> result = new ArrayList<>();
        for (SECURITY_DESCRIPTOR_CONTROL s : values()) {
            if ((flags & s.mask) != 0)
                result.add(s);
        }
        return result;
    }
    @Override
    public String toString() {
        return meaning;
    }
}

interface ACCESS_MASK_DEST {
    static final int FILE = 1;
    static final int DIR = 2;
    static final int BOTH = 3;
}

enum ACCESS_MASK implements ACCESS_MASK_DEST {
    /*
     * The specific rights (bits 0 to 15). Depend on the type of the
     * object being secured by the ACE.
     */

    /* Specific rights for files and directories are as follows: */

    /* Right to read data from the file. (FILE) */
    FILE_READ_DATA(0x00000001, "Read data", FILE),
    /* Right to list contents of a directory. (DIRECTORY) */
    FILE_LIST_DIRECTORY(0x00000001, "List directory", DIR),

    /* Right to write data to the file. (FILE) */
    FILE_WRITE_DATA(0x00000002, "Write data", FILE),
    /* Right to create a file in the directory. (DIRECTORY) */
    FILE_ADD_FILE(0x00000002, "Add files", DIR),

    /* Right to append data to the file. (FILE) */
    FILE_APPEND_DATA(0x00000004, "Append data", FILE),
    /* Right to create a subdirectory. (DIRECTORY) */
    FILE_ADD_SUBDIRECTORY(0x00000004, "Add subdirectory", DIR),

    /* Right to read extended attributes. (FILE/DIRECTORY) */
    FILE_READ_EA(0x00000008, "Read ext.attributes"),

    /* Right to write extended attributes. (FILE/DIRECTORY) */
    FILE_WRITE_EA(0x00000010, "Write ext.attributes"),

    /* Right to execute a file. (FILE) */
    FILE_EXECUTE(0x00000020, "Execute", FILE),
    /* Right to traverse the directory. (DIRECTORY) */
    FILE_TRAVERSE(0x00000020, "Traverse", DIR),

    /*
     * Right to delete a directory and all the files it contains (its
     * children), even if the files are read-only. (DIRECTORY)
     */
    FILE_DELETE_CHILD(0x00000040, "Delete child", DIR),

    /* Right to read file attributes. (FILE/DIRECTORY) */
    FILE_READ_ATTRIBUTES(0x00000080, "Read attributes"),

    /* Right to change file attributes. (FILE/DIRECTORY) */
    FILE_WRITE_ATTRIBUTES(0x00000100, "Change attributes"),

    /* The standard rights (bits 16 to 23). Are independent of the type of object being secured. */

    /* Right to delete the object. */
    DELETE(0x00010000, "DELETE OBJECT"),

    /* Right to read read the security descriptor and owner. */
    READ_CONTROL(0x00020000, "READ CONTROL"),

    /* Right to modify the DACL in the object's security descriptor. */
    WRITE_DAC(0x00040000, "WRITE DAC"),

    /* Right to change the owner in the object's security descriptor. */
    WRITE_OWNER(0x00080000, "WRITE OWNER"),

    /* Right to use the object for synchronization. */
    SYNCHRONIZE(0x00100000, "SYNC"),

    /*
     * The following STANDARD_RIGHTS_* are combinations of the above for
     * convenience and are defined by the Win32 API.
     */

    /*
     * The generic rights (bits 28 to 31). These map onto the standard and
     * specific rights.
     */

    /* Read, write, and execute access. */
    GENERIC_ALL(0x10000000, "GENERIC_ALL"),

    /* Execute access. */
    GENERIC_EXECUTE(0x20000000, "GENERIC_EXECUTE"),

    /*
     * Write access. For files, this maps onto:
     * FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_DATA | FILE_WRITE_EA | STANDARD_RIGHTS_WRITE | SYNCHRONIZE
     * For directories, the mapping has the same numerical value.
     */
    GENERIC_WRITE(0x40000000, "GENERIC_WRITE"),

    /*
     * Read access. For files, this maps onto:
     * FILE_READ_ATTRIBUTES | FILE_READ_DATA | FILE_READ_EA | STANDARD_RIGHTS_READ | SYNCHRONIZE
     * For directories, the mapping has the same numerical value.
     */
    GENERIC_READ(0x80000000, "GENERIC_READ"),
    // Access rights: 0x1f01ff: All specific + All standard
    All_specific(0x0001ff, "All specific", 0),
    All_standard(0x1f0000, "All standard", 0);

    int mask;
    String desc;
    int destMask;

    private ACCESS_MASK(int i, String desc) {
        this.mask = i;
        this.desc = desc;
        destMask = BOTH;
    }
    private ACCESS_MASK(int i, String desc, int destMask) {
        this.mask = i;
        this.desc = desc;
        this.destMask = destMask;
    }

    static List<ACCESS_MASK> decode(int flags, int objectType) {
        if (0x1f01ff == flags) {
            return Arrays.asList(All_specific, All_standard);
        }
        List<ACCESS_MASK> result = new ArrayList<>();
        for (ACCESS_MASK s : values()) {
            if ((flags & s.mask) != 0 && (objectType & s.destMask) != 0)
                result.add(s);
        }
        return result;
    }
    @Override
    public String toString() {
        return desc;
    }
} // enum ACCESS_MASK
