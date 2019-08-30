package peinfo

import (
	// "bytes"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"os"
)

const (
	RT_VERSION = 16
)

func (f *FileT) FindVerInfoOffset(fileOffset int64, sectionOffset uint32, sectionVirtualAddress uint32) (verInfoOffset int64, len uint32, err error) {
	pos, _ := f.OSFile.Seek(fileOffset, os.SEEK_SET)
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
	err = binary.Read(f.OSFile, binary.LittleEndian, &peoff)
	if nil != err {
		return verInfoOffset, len, err
	}

	// $filePos = $off + $$section{Base} - $$section{VirtualAddress};
	verInfoOffset = int64(peoff.Off + sectionOffset - sectionVirtualAddress)
	return verInfoOffset, peoff.Len, nil
}

func (f *FileT) GetVersionInfo() (vi []byte, err error) {
	section := f.PEFile.Section(".rsrc")
	// fmt.Printf("%+v\n", section)

	// Resource
	_, err = f.OSFile.Seek(int64(0), os.SEEK_SET)
	if nil != err {
		return vi, err
	}

	idd := f.FindDataDirectory(pe.IMAGE_DIRECTORY_ENTRY_RESOURCE)
	// Why is the -0x6000 needed?
	// VirtualAddress:602112 Offset:577536
	idd.VirtualAddress -= (section.VirtualAddress - section.Offset)
	if f.Verbose {
		fmt.Printf("IMAGE_DIRECTORY_ENTRY_RESOURCE virtual address: %d\n", idd.VirtualAddress)
		fmt.Printf("IMAGE_DIRECTORY_ENTRY_RESOURCE size: %d\n", idd.Size)
		fmt.Printf("IMAGE_DIRECTORY_ENTRY_RESOURCE image base: %d\n", idd.ImageBase)
	}

	pos, err := f.OSFile.Seek(int64(idd.VirtualAddress), os.SEEK_SET)
	if nil != err {
		return vi, err
	}
	if pos != int64(idd.VirtualAddress) {
		fmt.Errorf("did not seek to VirtualAddress")
	}

	var table ResourceDirectoryD
	err = binary.Read(f.OSFile, binary.LittleEndian, &table)
	if nil != err {
		return vi, err
	}
	// fmt.Printf("table %+v\n", table)

	x := 0
	for x < int(table.NumberOfNamedEntries+table.NumberOfIdEntries) {
		var entry ResourceDirectoryEntry
		err = binary.Read(f.OSFile, binary.LittleEndian, &entry)
		if nil != err {
			return vi, err
		}

		if entry.Name == RT_VERSION {
			// Directory
			if (entry.OffsetToData&0x80000000)>>31 == 1 {
				new := entry.OffsetToData&0x7fffffff + idd.VirtualAddress
				f.OSFile.Seek(int64(new), os.SEEK_SET)

				var innerDir ResourceDirectoryD
				err = binary.Read(f.OSFile, binary.LittleEndian, &innerDir)
				if nil != err {
					return vi, err
				}
				// pos := f.Tell()
				// fmt.Printf("level 1 innerDir %+v (file offset=%d)\n", innerDir, pos)

				y := 0
				for y < int(innerDir.NumberOfNamedEntries+innerDir.NumberOfIdEntries) {
					var entry ResourceDirectoryEntry
					err = binary.Read(f.OSFile, binary.LittleEndian, &entry)
					if nil != err {
						return vi, err
					}
					// pos := f.Tell()
					// fmt.Printf("item %d - level 2 buff %s (file offset=%d)\n", y, entry, pos)

					if (entry.OffsetToData&0x80000000)>>31 == 1 {
						new := entry.OffsetToData&0x7fffffff + idd.VirtualAddress
						// fmt.Printf("level 2 DirStart 0x%x (%d)\n", new, new)
						f.OSFile.Seek(int64(new), os.SEEK_SET)
					}

					var innerDir ResourceDirectoryD
					err = binary.Read(f.OSFile, binary.LittleEndian, &innerDir)
					if nil != err {
						return vi, err
					}
					// pos = f.Tell()
					// fmt.Printf("level 3 innerDir %+v (file offset=%d)\n", innerDir, pos)

					z := 0
					for z < int(innerDir.NumberOfNamedEntries+innerDir.NumberOfIdEntries) {
						var entry ResourceDirectoryEntry
						err = binary.Read(f.OSFile, binary.LittleEndian, &entry)
						if nil != err {
							return vi, err
						}
						// pos := f.Tell()
						// fmt.Printf("item %d - level 3 buff %s (file offset=%d)\n", y, entry, pos)
						// fmt.Printf("ver: 0x%x\n", entry.OffsetToData+idd.VirtualAddress)

						// find offset of VS_VERSION_INFO
						off := int64(entry.OffsetToData + idd.VirtualAddress)
						viPos, viLen, err := f.FindVerInfoOffset(off, section.SectionHeader.Offset, section.SectionHeader.VirtualAddress)
						if nil != err {
							return vi, err
						}
						// fmt.Printf("VerInfo Struct filePos: 0x%x (%d)\n", viPos, viPos)

						f.OSFile.Seek(viPos, os.SEEK_SET)
						b := make([]byte, viLen)
						err = binary.Read(f.OSFile, binary.LittleEndian, &b)
						if nil != err {
							return vi, err
						}
						// fmt.Printf("%s\n", b)
						return b, nil
						z += 1
					}
					y += 1
				}
			}
		}
		x += 1
	}
	return vi, nil
}
