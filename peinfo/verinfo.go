package peinfo

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
)

const (
	RT_VERSION = 16
)

func (cfg *ConfigT) FindVerInfoOffset(fileOffset int64, sectionOffset uint32, sectionVirtualAddress uint32) (verInfoOffset int64, len uint32, err error) {
	pos, _ := cfg.OSFile.Seek(fileOffset, os.SEEK_SET)
	if pos != fileOffset {
		return 0, 0, fmt.Errorf("did not seek to offset")
	}
	type VerInfoDetailsT struct {
		Off uint32
		Len uint32
		D1  uint32
		D2  uint32
	}
	var peoff VerInfoDetailsT
	err = binary.Read(cfg.OSFile, binary.LittleEndian, &peoff)
	if nil != err {
		return verInfoOffset, len, err
	}

	// $filePos = $off + $$section{Base} - $$section{VirtualAddress};
	verInfoOffset = int64(peoff.Off + sectionOffset - sectionVirtualAddress)
	return verInfoOffset, peoff.Len, nil
}

func (cfg *ConfigT) GetVersionInfo() (vi map[string]string, keys []string, err error) {
	vi = map[string]string{
		"BuildDate":        "",
		"BuildVersion":     "",
		"Comments":         "",
		"CompanyName":      "",
		"Copyright":        "",
		"FileDescription":  "",
		"FileVersion":      "",
		"InternalName":     "",
		"LegalCopyright":   "",
		"LegalTrademarks":  "",
		"OriginalFilename": "",
		"PrivateBuild":     "",
		"ProductName":      "",
		"ProductVersion":   "",
		"SpecialBuild":     "",
		"langCharSet":      "",
		// "varFileInfo":      "",
	}
	keys = []string{
		"BuildDate",
		"BuildVersion",
		"Comments",
		"CompanyName",
		"Copyright",
		"FileDescription",
		"FileVersion",
		"InternalName",
		"LegalCopyright",
		"LegalTrademarks",
		"OriginalFilename",
		"PrivateBuild",
		"ProductName",
		"ProductVersion",
		"SpecialBuild",
		"langCharSet",
		// "varFileInfo"
	}

	section := cfg.PEFile.Section(".rsrc")
	if section == nil {
		return vi, keys, fmt.Errorf("resource section not found")
	}
	// fmt.Printf("%+v\n", section)

	// Resource
	_, err = cfg.OSFile.Seek(int64(0), os.SEEK_SET)
	if nil != err {
		return vi, keys, err
	}

	idd := cfg.FindDataDirectory(pe.IMAGE_DIRECTORY_ENTRY_RESOURCE)
	idd.VirtualAddress -= (section.VirtualAddress - section.Offset)
	if cfg.Verbose {
		fmt.Printf("IMAGE_DIRECTORY_ENTRY_RESOURCE virtual address: %d\n", idd.VirtualAddress)
		fmt.Printf("IMAGE_DIRECTORY_ENTRY_RESOURCE size: %d\n", idd.Size)
		fmt.Printf("IMAGE_DIRECTORY_ENTRY_RESOURCE image base: %d\n", idd.ImageBase)
	}

	pos, err := cfg.OSFile.Seek(int64(idd.VirtualAddress), os.SEEK_SET)
	if nil != err {
		return vi, keys, err
	}
	if pos != int64(idd.VirtualAddress) {
		fmt.Errorf("did not seek to VirtualAddress")
	}

	var table ResourceDirectoryD
	err = binary.Read(cfg.OSFile, binary.LittleEndian, &table)
	if nil != err {
		return vi, keys, err
	}
	// fmt.Printf("table %+v\n", table)

	x := 0
	for x < int(table.NumberOfNamedEntries+table.NumberOfIdEntries) {
		var entry ResourceDirectoryEntry
		err = binary.Read(cfg.OSFile, binary.LittleEndian, &entry)
		if nil != err {
			return vi, keys, err
		}

		if entry.Name == RT_VERSION {
			// Directory
			if (entry.OffsetToData&0x80000000)>>31 == 1 {
				new := entry.OffsetToData&0x7fffffff + idd.VirtualAddress
				cfg.OSFile.Seek(int64(new), os.SEEK_SET)

				var innerDir ResourceDirectoryD
				err = binary.Read(cfg.OSFile, binary.LittleEndian, &innerDir)
				if nil != err {
					return vi, keys, err
				}
				// pos := f.Tell()
				// fmt.Printf("level 1 innerDir %+v (file offset=%d)\n", innerDir, pos)

				y := 0
				for y < int(innerDir.NumberOfNamedEntries+innerDir.NumberOfIdEntries) {
					var entry ResourceDirectoryEntry
					err = binary.Read(cfg.OSFile, binary.LittleEndian, &entry)
					if nil != err {
						return vi, keys, err
					}
					// pos := f.Tell()
					// fmt.Printf("item %d - level 2 buff %s (file offset=%d)\n", y, entry, pos)

					if (entry.OffsetToData&0x80000000)>>31 == 1 {
						new := entry.OffsetToData&0x7fffffff + idd.VirtualAddress
						// fmt.Printf("level 2 DirStart 0x%x (%d)\n", new, new)
						cfg.OSFile.Seek(int64(new), os.SEEK_SET)
					}

					var innerDir ResourceDirectoryD
					err = binary.Read(cfg.OSFile, binary.LittleEndian, &innerDir)
					if nil != err {
						return vi, keys, err
					}
					// pos = f.Tell()
					// fmt.Printf("level 3 innerDir %+v (file offset=%d)\n", innerDir, pos)

					z := 0
					for z < int(innerDir.NumberOfNamedEntries+innerDir.NumberOfIdEntries) {
						var entry ResourceDirectoryEntry
						err = binary.Read(cfg.OSFile, binary.LittleEndian, &entry)
						if nil != err {
							return vi, keys, err
						}
						// pos := f.Tell()
						// fmt.Printf("item %d - level 3 buff %s (file offset=%d)\n", y, entry, pos)
						// fmt.Printf("ver: 0x%x\n", entry.OffsetToData+idd.VirtualAddress)

						// find offset of VS_VERSION_INFO
						off := int64(entry.OffsetToData + idd.VirtualAddress)
						viPos, viLen, err := cfg.FindVerInfoOffset(off, section.SectionHeader.Offset, section.SectionHeader.VirtualAddress)
						if nil != err {
							return vi, keys, err
						}
						// fmt.Printf("VerInfo Struct filePos: 0x%x (%d)\n", viPos, viPos)

						cfg.OSFile.Seek(viPos, os.SEEK_SET)
						b := make([]byte, viLen)
						err = binary.Read(cfg.OSFile, binary.LittleEndian, &b)
						if nil != err {
							return vi, keys, err
						}
						// fmt.Printf("%s\n", b)

						if cfg.Verbose {
							fmt.Printf("  %s\n", hex.Dump(b))
						}

						vi, err = parseVersionInfo(b, vi)
						if nil != err {
							return vi, keys, err
						}
						return vi, keys, nil
					}
					y++
				}
			}
		}
		x++
	}

	return vi, keys, fmt.Errorf("no version info found")
}

func parseVersionInfo(vi []byte, versionInfo map[string]string) (map[string]string, error) {
	// Grab everything after "StringFileInfo"
	stringFileInfo := bytes.Split(vi, []byte{0x53, 0x0, 0x74, 0x0, 0x72, 0x0, 0x69, 0x0, 0x6e, 0x0, 0x67, 0x0, 0x46, 0x0, 0x69, 0x0, 0x6c, 0x0, 0x65, 0x0, 0x49, 0x0, 0x6e, 0x0, 0x66, 0x0, 0x6f})[1]

	divide := bytes.Split(stringFileInfo, []byte{0x0, 0x1, 0x0})

	langCharSet := trimSlice(divide[1])
	versionInfo["langCharSet"] = string(langCharSet)

	// check for slice out of bounds
	if len(divide) < 3 {
		err := fmt.Errorf("VersionInfo slice too small")
		return versionInfo, err
	}

	end := len(divide) - 1
	if end < 2 {
		err := fmt.Errorf("slice end less than start")
		return versionInfo, err
	}

	values := divide[2:end]

	// TODO: handle varFileInfo, currently contains binary information which chrome does not display
	// varFileInfo := divide[len(divide)-1]
	// versionInfo["varFileInfo"] = string(trimSlice(varFileInfo))

	for _, element := range values {
		temp := bytes.Split(element, []byte{0x0, 0x0, 0x0})
		valueInfo := temp[:len(temp)-1]

		if len(valueInfo) > 1 {
			name := string(trimSlice(valueInfo[0]))
			value := string(trimSlice(valueInfo[1]))

			versionInfo[name] = value
		}
	}

	return versionInfo, nil
}

func trimSlice(nonTrimmed []byte) (trimmed []byte) {
	for bytes.HasPrefix(nonTrimmed, []byte{0x0}) {
		nonTrimmed = nonTrimmed[1:]
	}

	for i, val := range nonTrimmed {
		if i%2 == 0 && val != 0x0 {
			trimmed = append(trimmed, val)
		}
	}

	return trimmed
}
