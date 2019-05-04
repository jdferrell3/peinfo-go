# peinfo-go

This is a PE (Portable Executable) parser written in GoLang. I wanted to learn more about the PE format, specifically how the certificates were stored. What better way is there than to write some code.

This is a work in progress and will likely change.

Current state:
- Some PE details
- Examines the certificate
- Finds Version Info struct
- Displays imports

TODO:
- Parse Version Info struct
- Re-write function for finding Version Info (currently written so I could better understand the structure)
- Custom certificate stores

```
[user:~/peinfo-go\ > ./peinfo-go /tmp/Autoruns/autorunsc64.exe
type: pe32+
Characteristics: [Executable]
Subsystem: IMAGE_SUBSYSTEM_WINDOWS_CUI

Cert:
  subject: CN=Microsoft Corporation,O=Microsoft Corporation,L=Redmond,ST=Washington,C=US
  issuer: CN=Microsoft Code Signing PCA,O=Microsoft Corporation,L=Redmond,ST=Washington,C=US
  verified: false
  error: pkcs7: failed to verify certificate chain: x509: certificate signed by unknown authority

Version Info:
?�StringFileInfo�040904b0h$CompanyNameSysinternals - www.sysinternals.comZFileDescriptionAutostart program viewer,FileVersion13.94LInternalNameSysinternals Autorunsv)LegalCopyrightCopyright (C) 2002-2019 MarkOriginalFilenameautoruns.exeLProductNameSysinternals autoruns0ProductVersion13.94DVarFileInfo$Translation	�

Imports:
 - VerQueryValueW:VERSION.dll
 - GetFileVersionInfoW:VERSION.dll
 - GetFileVersionInfoSizeW:VERSION.dll
 - ImageList_ReplaceIcon:COMCTL32.dll
 ...
 ```