package peinfo

import (
	"debug/pe"
	"os"
)

type FileT struct {
	FileName    string
	OSFile      *os.File
	PEFile      *pe.File
	ExtractCert bool
	Verbose     bool
}

type ResourceDirectoryD struct {
	Characteristics      uint32
	TimeDateStamp        uint32
	MajorVersion         uint16
	MinorVersion         uint16
	NumberOfNamedEntries uint16
	NumberOfIdEntries    uint16
}

type CertDetails struct {
	Length          uint32
	Revision        uint16
	CertificateType uint16
	DER             []byte
}

// typedef struct _IMAGE_RESOURCE_DIRECTORY_ENTRY {
//     union {
//         struct {
//             DWORD NameOffset:31;
//             DWORD NameIsString:1;
//         };
//         DWORD   Name;
//         WORD    Id;
//     };
//     union {
//         DWORD   OffsetToData;
//         struct {
//             DWORD   OffsetToDirectory:31;
//             DWORD   DataIsDirectory:1;
//         };
//     };
// } IMAGE_RESOURCE_DIRECTORY_ENTRY, *PIMAGE_RESOURCE_DIRECTORY_ENTRY;

type ResourceDirectoryEntry struct {
	Name         uint32
	OffsetToData uint32
}

type ResourceDirectoryEntryNamed struct {
	Name         uint32
	OffsetToData uint32
}

/* Resource Directory Entry */
// type ResourceDirectoryEntryT struct {
// 	ResourceDirectoryEntry ResourceDirectoryEntry
// 	FileOffset             uint32
// 	Size                   uint32
// 	DataIsDirectory        bool
// }

type _IMAGE_RESOURCE_DATA_ENTRY struct {
	OffsetToData uint32
	Size         uint32
	CodePage     uint32
	Reserved     uint32
}

type VS_FIXEDFILEINFO struct {
	DwSignature        uint32
	DwStrucVersion     uint32
	DwFileVersionMS    uint32
	DwFileVersionLS    uint32
	DwProductVersionMS uint32
	DwProductVersionLS uint32
	DwFileFlagsMask    uint32
	DwFileFlags        uint32
	DwFileOS           uint32
	DwFileType         uint32
	DwFileSubtype      uint32
	DwFileDateMS       uint32
	DwFileDateLS       uint32
}
