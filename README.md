# NTFSPermissionsOnLinux
Allows users to view and change NTFS permissions from command-line and GUI

[NTFS-3G] software allows Linux users to access and modify NTFS drives created by MS Windows.
However adjusting NT directories and files permissions, often carefully crafted, into Unix [file mode] is not quote
 straight-forward task. Users have only 2 options: either disregard them (mount options made all NTFS files/directores
 to have same access mask) or to rely on default behavior of NTFS-3G code hoping it will work. 
 For those users who are fine with the first option (or maybe even don't have NTFS drives at all) this software is not
 useful. So I assume the users have mounted NTFS drive(s) using option 'permissions' and defined proper UserMapping file.

From what I see in AskUbuntu.com such setup sometimes causes a lot of surprises from user, they ask "why I have such
 strange permissions and cannot change them?". Especially because there is no easy way to see and change NTFS
 attributes. The only way provided OOTB  to see them is ntfs-3s.secaudit. In my experience it (a) dumps core
 (b) is a command-line tool with too technical debug output (c) does not provide easy way to *change* them.
 That's why I decided to write my own.

I am expressing sincere thanks to the author of https://github.com/IsNull/xattrj java library for Max OS X that
 provides JNI access to xattr filesystem interface. Basically I have adapted this for Linux (Ubuntu 14.01 amd64)
 and ported from C++ to C.
