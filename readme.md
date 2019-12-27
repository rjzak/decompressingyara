__Decompressing Yara:__ For when your malware samples are stored compressed, but you still want to run rules against them.

Currently supports:
* GZip
* BZip2
* LZMA ([XZ](https://tukaani.org/xz/))

Modules used:
* Go-Yara: https://github.com/hillu/go-yara
* XZ: https://github.com/ulikunitz/xz

Motivation: I've had to test Yara rules with malware which was compressed, but also on different systems, which may or may not have Yara installed. Maybe it was an older version of Yara. I've compiled the project statically against [libyara](https://github.com/VirusTotal/yara), making my sysadmin life easier. Since it was useful to me, maybe someone else would benefit. Currently it only runs a rule file against a directory of files.

Future thoughts:
* Files in archives, such as Zip and Tar.
* Support for password-protected Zip and 7z files, and testing the usual passwords against them.