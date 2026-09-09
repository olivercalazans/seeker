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

package dot11build

import (
	"encoding/binary"
	"offscan/internal/models"
)


type ProbeReq struct {
	buffer [256]byte
	offset int
}



func NewProbeReq() ProbeReq {
	p := ProbeReq{}
	p.buildFixed()
	return p
}



func (pr *ProbeReq) buildFixed() {
	minimalRariotapHeader(pr.buffer[:12])
	pr.setFrameCtrl()
	pr.setDuration()
}



func (pr *ProbeReq) setFrameCtrl() {
	pr.buffer[12] = 0x40
	pr.buffer[13] = 0x00
}



func (pr *ProbeReq) setDuration() {
	pr.buffer[14] = 0x00
	pr.buffer[15] = 0x00
}



func (pr *ProbeReq) SetDstAddr(addr models.MAC) {
	copy(pr.buffer[16:22], addr[:])
}



func (pr *ProbeReq) SetSrcAddr(addr models.MAC) {
	copy(pr.buffer[22:28], addr[:])
}



func (pr *ProbeReq) SetBSSID(bssid models.BSSID) {
	copy(pr.buffer[28:34], bssid[:])
}



func (pr *ProbeReq) SetSeqCtrl(seq uint16) {
	seqCtrl := (seq & 0x0FFF) << 4
	binary.LittleEndian.PutUint16(pr.buffer[34:36], seqCtrl)
}



func (pr *ProbeReq) SetSSID(ssid string) {
	pr.offset  = 36 // 802.11 (24 bytes) + Radiotap (12)
	ssidLen  := len(ssid)

	pr.buffer[pr.offset] = 0x00 // Tag: SSID
	pr.offset++

	pr.buffer[pr.offset] = byte(ssidLen)
	pr.offset++

	copy(pr.buffer[pr.offset : pr.offset + ssidLen], ssid)
	pr.offset += ssidLen
}



func (pr *ProbeReq) SetRates() {
	pr.buffer[pr.offset] = 0x01 // Tag: Supported Rates
	pr.offset++
	
	pr.buffer[pr.offset] = 0x08
	pr.offset++

	rates := [8]byte{
		0x82, 0x84, 0x8B, 0x96, // 1, 2, 5.5, 11 Mbps
		0x0C, 0x12, 0x18, 0x24, // 6, 9, 12, 24 Mbps
	}

	copy(pr.buffer[pr.offset:pr.offset+8], rates[:])
	pr.offset += 8
}



func (pr *ProbeReq) SetExtendedRates() {
	pr.buffer[pr.offset] = 0x32 // Tag: Extended Supported Rates
	pr.offset++
	
	pr.buffer[pr.offset] = 0x04
	pr.offset++

	extRates := [4]byte{0x30, 0x48, 0x60, 0x6C}
	copy(pr.buffer[pr.offset:pr.offset+4], extRates[:])
	pr.offset += 4
}



func (pr *ProbeReq) SetWPSInfo() {
	startIE := pr.offset

	pr.buffer[pr.offset] = 0xDD    // Tag: Vendor Specific
	pr.offset++
	
	lenPos := pr.offset
	pr.offset++

	// OUI: 00:50:F2 (Microsoft/WPS)
	pr.buffer[pr.offset] = 0x00
	pr.offset++
	pr.buffer[pr.offset] = 0x50
	pr.offset++
	pr.buffer[pr.offset] = 0xF2
	pr.offset++

	// OUI Type: 0x04 (WPS)
	pr.buffer[pr.offset] = 0x04
	pr.offset++

	// TLVs
	pr.writeTLV(0x104A, []byte{0x00, 0x10}) // Version 1.0
	pr.writeTLV(0x0006, []byte{0x00, 0x01}) // Request Type = Enrollee
	pr.writeTLV(0x1008, []byte{0x00, 0x80}) // Configuration Methods = PIN

	ieLen := pr.offset - (startIE + 2)
	pr.buffer[lenPos] = byte(ieLen)
}



func (pr *ProbeReq) writeTLV(id uint16, value []byte) {
	binary.BigEndian.PutUint16(pr.buffer[pr.offset:], id)
	pr.offset += 2

	pr.buffer[pr.offset] = byte(len(value))
	pr.offset++

	copy(pr.buffer[pr.offset:], value)
	pr.offset += len(value)
}



func (pr *ProbeReq) Frame() []byte {
	return pr.buffer[:pr.offset]
}