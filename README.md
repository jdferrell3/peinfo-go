# peinfo-go

This is a PE (Portable Executable) parser written in GoLang. I wanted to learn more about the PE format, specifically how the certificates were stored. What better way is there than to write some code?

_This is a work in progress and will continue to change._

This leverages the `debug/pe` package for parsing of the common headers/sections.

Current state:
- Displays some PE details
- Validates certificate, verifies certificate chain, checks against CRL
- Parses Version Info struct
- Displays imports

TODO:
- ~~Actually Parse Version Info struct (currently displayed as raw binary)~~
- Re-write function for finding Version Info (currently written so I could better understand the structure)
- ~~Custom certificate stores~~

## Example
```
[user:~/peinfo-go\ > go run cmd/main.go -certdir ~/RootCerts -versioninfo ~/Downloads/PsExec.exe
type: pe32
TimeDateStamp: 2016-06-28 18:43:09 +0000 UTC
Characteristics: [Executable 32bit]
Subsystem: IMAGE_SUBSYSTEM_WINDOWS_CUI

Cert:
  subject: CN=Microsoft Corporation,OU=MOPR,O=Microsoft Corporation,L=Redmond,ST=Washington,C=US
  issuer: CN=Microsoft Code Signing PCA,O=Microsoft Corporation,L=Redmond,ST=Washington,C=US
  not before: 2015-06-04 17:42:45 +0000 UTC
  not after: 2016-09-04 17:42:45 +0000 UTC
  CRL: [http://crl.microsoft.com/pki/crl/products/MicCodSigPCA_08-31-2010.crl]
  verified: true (chain expired: true)

Version Info:
 BuildDate            :
 BuildVersion         :
 Comments             :
 CompanyName          : Sysinternals - www.sysinternals.com
 Copyright            :
 FileDescription      : Execute processes remotely
 FileVersion          : 2.2
 InternalName         : PsExec
 LegalCopyright       : Copyright (C) 2001-2016 Mark Russinovich
 LegalTrademarks      :
 OriginalFilename     : psexec.c
 PrivateBuild         :
 ProductName          : Sysinternals PsExec
 ProductVersion       : 2.2
 SpecialBuild         :
 langCharSet          : 040904b0h$
 ```

## References
- https://golang.org/pkg/debug/pe/
- http://www.pelib.com/resources/luevel.txt
- https://github.com/exiftool/exiftool/blob/master/lib/Image/ExifTool/EXE.pm
- https://github.com/deptofdefense/SalSA/blob/master/pe.py
- https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#resource-directory-entries
- https://github.com/quarkslab/dreamboot/blob/31e155b06802dce94367c38ea93316f7cb86cb15/QuarksUBootkit/PeCoffLib.c
- https://docs.microsoft.com/en-us/windows/desktop/Debug/pe-format#the-attribute-certificate-table-image-only
