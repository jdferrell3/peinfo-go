package peinfo

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
	"os"
	"time"
)

// http://www.pelib.com/resources/luevel.txt
// https://github.com/exiftool/exiftool/blob/master/lib/Image/ExifTool/EXE.pm
// https://github.com/deptofdefense/SalSA/blob/master/pe.py
// https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#resource-directory-entries
// https://github.com/quarkslab/dreamboot/blob/31e155b06802dce94367c38ea93316f7cb86cb15/QuarksUBootkit/PeCoffLib.c
// https://docs.microsoft.com/en-us/windows/desktop/Debug/pe-format#the-attribute-certificate-table-image-only
// https://docs.microsoft.com/en-us/windows/desktop/menurc/vs-versioninfo

var (
	sizeofOptionalHeader32 = uint16(binary.Size(pe.OptionalHeader32{}))
	sizeofOptionalHeader64 = uint16(binary.Size(pe.OptionalHeader64{}))
)

type ImageDirectoryT struct {
	Type           int
	VirtualAddress uint32
	Size           uint32
	ImageBase      uint64
}

func (f *FileT) HeaderMagic() uint16 {
	pe64 := f.PEFile.Machine == pe.IMAGE_FILE_MACHINE_AMD64

	if pe64 {
		return f.PEFile.OptionalHeader.(*pe.OptionalHeader64).Magic
	}

	return f.PEFile.OptionalHeader.(*pe.OptionalHeader32).Magic
}

func (f *FileT) GetPEType() string {
	t := "pe32"
	if f.PEFile.Machine == pe.IMAGE_FILE_MACHINE_AMD64 {
		t = "pe32+"
	}
	return t
}

func (f *FileT) GetImageSubSystem() string {
	pe64 := f.PEFile.Machine == pe.IMAGE_FILE_MACHINE_AMD64

	subsystem := map[uint16]string{
		0:  "IMAGE_SUBSYSTEM_UNKNOWN",
		1:  "IMAGE_SUBSYSTEM_NATIVE",
		2:  "IMAGE_SUBSYSTEM_WINDOWS_GUI",
		3:  "IMAGE_SUBSYSTEM_WINDOWS_CUI",
		4:  "IMAGE_SUBSYSTEM_OS2_CUI",
		5:  "IMAGE_SUBSYSTEM_POSIX_CUI",
		9:  "IMAGE_SUBSYSTEM_WINDOWS_CE_GUI",
		10: "IMAGE_SUBSYSTEM_EFI_APPLICATION",
		11: "IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER",
		12: "IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER",
		13: "IMAGE_SUBSYSTEM_EFI_ROM",
		14: "IMAGE_SUBSYSTEM_XBOX",
		15: "IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION",
	}

	if pe64 {
		return subsystem[f.PEFile.OptionalHeader.(*pe.OptionalHeader64).Subsystem]
	}

	return subsystem[f.PEFile.OptionalHeader.(*pe.OptionalHeader32).Subsystem]
}

func (f *FileT) GetCharacteristics() []string {
	characteristics := []string{}

	if (f.PEFile.FileHeader.Characteristics & 0x0002) > 1 {
		characteristics = append(characteristics, "Executable")
	}

	if (f.PEFile.FileHeader.Characteristics & 0x0100) > 1 {
		characteristics = append(characteristics, "32bit")
	}

	if (f.PEFile.FileHeader.Characteristics & 0x2000) > 1 {
		characteristics = append(characteristics, "DLL")
	}

	return characteristics
}

func (f *FileT) GetTimeDateStamp() string {
	// i, err := strconv.ParseInt(f.PEFile.FileHeader.TimeDateStamp, 10, 64)
	// if err != nil {
	// 	panic(err)
	// }
	tm := time.Unix(int64(f.PEFile.FileHeader.TimeDateStamp), 0)
	return fmt.Sprintf("%s", tm.UTC())
}

func (f *FileT) FindDataDirectory(imageDirectoryEntryType int) (idd ImageDirectoryT) {
	pe64 := f.PEFile.Machine == pe.IMAGE_FILE_MACHINE_AMD64

	var dd pe.DataDirectory
	if pe64 {
		dd = f.PEFile.OptionalHeader.(*pe.OptionalHeader64).DataDirectory[imageDirectoryEntryType]
		idd.ImageBase = f.PEFile.OptionalHeader.(*pe.OptionalHeader64).ImageBase
	} else {
		dd = f.PEFile.OptionalHeader.(*pe.OptionalHeader32).DataDirectory[imageDirectoryEntryType]
		idd.ImageBase = uint64(f.PEFile.OptionalHeader.(*pe.OptionalHeader32).ImageBase)
	}

	idd.VirtualAddress = dd.VirtualAddress
	idd.Size = dd.Size
	idd.Type = imageDirectoryEntryType

	return idd
}

func (f *FileT) Tell() int64 {
	pos, _ := f.OSFile.Seek(0, os.SEEK_CUR)
	return pos
}
