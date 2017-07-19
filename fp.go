// Device fingerprinting for Windows hosts. This ensures that software cannot
// run unless its on the same machine where the license was generated for it.
package fp

import (
	"crypto/sha1"
	"fmt"
	"net"
	"strings"

	"github.com/StackExchange/wmi" // https://godoc.org/github.com/StackExchange/wmi
)

const checkSocket = "8.8.8.8:80"

// https://msdn.microsoft.com/en-us/library/aa394105(v=vs.85).aspx
type Win32_ComputerSystemProduct struct {
	UUID string
}
type Win32_Processor struct {
	ProcessorId string
}
type Win32_BIOS struct {
	SerialNumber string
}
type Win32_DiskDrive struct {
	Signature uint32
}
type Win32_BaseBoard struct {
	SerialNumber string
}

func osUUID() string {
	// win32_computersystemproduct: name, uuid, vendor, version
	var uuid []Win32_ComputerSystemProduct
	q := wmi.CreateQuery(&uuid, "")
	err := wmi.Query(q, &uuid)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%s", uuid[0].UUID)
}

func procID() string {
	// win32_processor: uniqueid, processorid, name, manufacturer, maxclockspeed
	var procid []Win32_Processor
	q := wmi.CreateQuery(&procid, "")
	err := wmi.Query(q, &procid)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%s", procid[0].ProcessorId)
}

func biosSerial() string {
	// win32_bios: manufacturer, smbiosbiosversion, identificationcode, serialnumber, releasedate, version
	var biosSN []Win32_BIOS
	q := wmi.CreateQuery(&biosSN, "")
	err := wmi.Query(q, &biosSN)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%s", biosSN[0].SerialNumber)
}

func diskSign() string {
	// win32_diskdrive: model, manufacturer, signature, totalheads
	var hddSign []Win32_DiskDrive
	q := wmi.CreateQuery(&hddSign, "")
	err := wmi.Query(q, &hddSign)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%d", hddSign[0].Signature)
}

func baseBoard() string {
	// win32_baseboard: model, manufacturer, name, serialnumber
	var baseBrd []Win32_BaseBoard
	q := wmi.CreateQuery(&baseBrd, "")
	err := wmi.Query(q, &baseBrd)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%s", baseBrd[0].SerialNumber)
}

func getOutboundAddr() string {
	// Get preferred outbound ip of this machine
	conn, err := net.Dial("udp", checkSocket)
	if err != nil {
		return ""
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().String()
	idx := strings.LastIndex(localAddr, ":")

	interfaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	var hwAddr string
	for _, inter := range interfaces {
		if addrs, _ := inter.Addrs(); err == nil {
			for _, addr := range addrs {
				if strings.HasPrefix(addr.String(), localAddr[0:idx]) {
					hwAddr = inter.HardwareAddr.String()
				}
			}
		}
	}

	return fmt.Sprintf("%s%s", localAddr[0:idx], hwAddr)
}

// Hash all gathered unique data.
func HashFingerprint() string {
	s := osUUID() + procID() + biosSerial() +
		diskSign() + baseBoard() + getOutboundAddr()
	//fmt.Println(s) // comment this line so you don't get busted

	h := sha1.New()
	h.Write([]byte(s))
	bs := h.Sum(nil) // finalized hash result as a byte slice
	//fmt.Printf("%x\n", bs)

	return fmt.Sprintf("%x", bs)
}
