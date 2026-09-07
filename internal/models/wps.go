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

package models

import (
	"fmt"
	"strings"
)


const (
	wpsVersionMask = 0x03
	wpsConfigMask  = 1 << (iota + 2)  // 1 << (0 + 2) = 0x04
	wpsAPSetupLocked                  // 1 << (1 + 2) = 0x08
	wpsStatePresent                   // 1 << (2 + 2) = 0x10
	wpsSelectedRegistrar              // 1 << (3 + 2) = 0x20
)



type WPSInfo struct {
	bitmap uint8
}



func (wi *WPSInfo) SetVersion(v uint8) {
	wi.bitmap &^= wpsVersionMask
	wi.bitmap  |= (v >> 4) & wpsVersionMask
}



func (wi WPSInfo) Version() uint8 {
	return (wi.bitmap & wpsVersionMask)
}



func (wi *WPSInfo) SetConfig(configured bool) {
	if configured { wi.bitmap |= wpsConfigMask }
}



func (wi WPSInfo) isConfigured() bool {
	return (wi.bitmap & wpsConfigMask) == wpsConfigMask
}



func (wi *WPSInfo) SetAPSetupLock(locked bool) {
	if locked { wi.bitmap |= wpsAPSetupLocked }
}



func (wi WPSInfo) isLocked() bool {
	return (wi.bitmap & wpsAPSetupLocked) == wpsAPSetupLocked
}



func (wi *WPSInfo) SetStatePresence() {
	wi.bitmap |= wpsStatePresent
}



func (wi WPSInfo) isStatePresent() bool {
	return (wi.bitmap & wpsStatePresent) == wpsStatePresent
}



func (wi *WPSInfo) SetRegistrar(selected bool) {
	if selected { wi.bitmap |= wpsSelectedRegistrar }
}



func (wi WPSInfo) selectedRegistrar() bool {
	return (wi.bitmap & wpsSelectedRegistrar) == wpsSelectedRegistrar
}



func (wi WPSInfo) String() string {
    if wi.Version() == 0 && !wi.isStatePresent() && !wi.isLocked() {
        return "0.0"
    }

    if wi.isLocked() {
        return "Locked"
    }

    var b strings.Builder

    b.WriteString(wi.formatVersion())

	if wi.selectedRegistrar() {
		b.WriteString(" RGT")
	}

    if wi.isStatePresent() {
        if wi.isConfigured() {
            b.WriteString(" CONF")
        } else {
            b.WriteString(" UNCONF")
        }
    }

    return b.String()
}



func (wi WPSInfo) formatVersion() string {
	return fmt.Sprintf("%d.0", wi.Version())
}



func (wi WPSInfo) Len() int {
	if wi.isLocked() {
        return 7
    }
   
	total := 3  // 0.0 or 1.0 or 2.0

	if wi.selectedRegistrar() {
		total += 4  // ' ' + RGT
	}

	if wi.isStatePresent() {
    	if wi.isConfigured() {
    	    total += 5  // ' ' + conf
    	} else {
    	    total += 7  // ' ' + unconf
    	}
	}

    return total
}