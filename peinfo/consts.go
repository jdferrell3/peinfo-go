package peinfo

var FileOS = map[uint32]string{
	0x00001: "Win16",
	0x00002: "PM-16",
	0x00003: "PM-32",
	0x00004: "Win32",
	0x10000: "DOS",
	0x20000: "OS/2 16-bit",
	0x30000: "OS/2 32-bit",
	0x40000: "Windows NT",
	0x10001: "Windows 16-bit",
	0x10004: "Windows 32-bit",
	0x20002: "OS/2 16-bit PM-16",
	0x30003: "OS/2 32-bit PM-32",
	0x40004: "Windows NT 32-bit",
}
