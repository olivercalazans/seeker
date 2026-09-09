/*
 * Copyright (C) 2025 Oliver R. Calazans Jeronimo
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org>.
 */

package pixiedust

import (
	"fmt"
	"net"
	"offscan/internal/conv"
	"offscan/internal/dot11dissec"
	"offscan/internal/models"
	"offscan/internal/sniffer"
	"offscan/internal/sysconf"
	"sync"
	"time"
)



func RunWPS(args []string) {
	w := wps{ iface : conv.MustStrToIface("wlp2s0")}
	w.execute()
}



type wps struct {
	iface       net.Interface
	wInfo       map[wifiData]struct{}
	dissector  *dot11dissec.Dot11Dissector
	sniffer    *sniffer.Sniffer
	wg          sync.WaitGroup

}


type wifiData struct {
	ssid   models.SSID
	bssid  models.BSSID
	chnl   uint8
}



func (w *wps) execute() {
	w.memAlloc()
	w.getBeacons()
	w.display()
}



func (w *wps) memAlloc() {
	w.wInfo = make(map[wifiData]struct{}, 75)
}



func (w *wps) getBeacons() {
	w.startBeaconProcessor()
	w.sniff2GChannels()
	w.sniff5GChannels()
	w.stopBeaconProcessor()
}



func (w *wps) startBeaconProcessor() {
	w.dissector = dot11dissec.NewDot11Dissector()
	w.sniffer   = sniffer.NewSniffer(w.iface, getBPFFilter(), false, w.Handler)
	w.sniffer.Start()

	fmt.Printf("[+] Sniffing beacons\n")
}



func getBPFFilter() string {
	return "wlan type mgt subtype beacon"
}



func (w *wps) Handler(beacon []byte) {
	w.dissector.UpdatePkt(beacon)
	w.updateInfo()
}



func (w *wps) updateInfo() {
	info := wifiData{
		ssid  : w.dissector.GetSSID(),
		bssid : w.dissector.GetBSSID(),
		chnl  : w.dissector.GetChannel(),
	}

	w.wInfo[info] = struct{}{}
}



func (w *wps) sniff2GChannels() {
	channels := sysconf.Channels2()
	w.sniffChannels(channels, "2.4")
}



func (w *wps) sniff5GChannels() {
	channels := sysconf.Channels5()
	w.sniffChannels(channels, "5")
}



func (w *wps) sniffChannels(channels []int, freq string) {
	var errChannels []int

	for _, chnl := range channels {
		ok := sysconf.TrySetChannel(w.iface, chnl)

		if ok != nil {
			errChannels = append(errChannels, chnl)
			continue
		}

		time.Sleep(350 * time.Millisecond)
	}

	if len(errChannels) > 0 {
		fmt.Printf("[!] Unable to sniff these channels (%sG):\n%v\n", freq, errChannels)
	}
}



func (w *wps) stopBeaconProcessor() {
	w.sniffer.Stop()
	fmt.Println("[-] Sniffer stopped")
	w.wg.Wait()
}



func (w *wps) display() {
	for i := range w.wInfo {
		fmt.Printf("BSSID: %s  CH: %-3d  SSID: %s\n", i.bssid.String(), i.chnl, i.ssid.String())
	}
}