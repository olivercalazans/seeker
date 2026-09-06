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
    methodUSB = 1 << iota // 1 << 0 = 1   (0x0001)
    methodETHER           // 1 << 1 = 2   (0x0002)
    methodLAB             // 1 << 2 = 4   (0x0004)
    methodDISP            // 1 << 3 = 8   (0x0008)
    methodEXTNFC          // 1 << 4 = 16  (0x0010)
    methodINTNFC          // 1 << 5 = 32  (0x0020)
    methodNFCINTF         // 1 << 6 = 64  (0x0040)
    methodPBC             // 1 << 7 = 128 (0x0080)
    methodKPAD            // 1 << 8 = 256 (0x0100)
)



type WPSInfo struct {
	Version        uint8
	IsConfigured   bool
	ConfigMethods  uint16
	APSetupLocked  bool
	StatePresent   bool
}



func (wi WPSInfo) String() string {
    if wi.Version == 0 && !wi.StatePresent && wi.ConfigMethods == 0 && !wi.APSetupLocked {
        return "0.0"
    }

    if wi.APSetupLocked {
        return "Locked"
    }

    var b strings.Builder

    b.WriteString(formatVersion(wi.Version))

    if wi.StatePresent && wi.ConfigMethods == 0 {
        if wi.IsConfigured {
            b.WriteString(" CONF")
        } else {
            b.WriteString(" UNCONF")
        }
    }

    methods := wi.methodsString()
    if methods != "" {
        if b.Len() > 0 { b.WriteByte(' ') }
        b.WriteString(methods)
    }

    return b.String()
}



func formatVersion(v uint8) string {
	major := v >> 4
	minor := v & 0x0F

	return fmt.Sprintf("%d.%d", major, minor)
}



func (wi WPSInfo) methodsString() string {
	var b strings.Builder
	first := true

	appendMethod := func(name string) {
		if !first { b.WriteByte(' ') }
		b.WriteString(name)
		first = false
	}

	if wi.hasUSB()     { appendMethod("USB")     }
	if wi.hasETHER()   { appendMethod("ETHER")   }
	if wi.hasLAB()     { appendMethod("LAB")     }
	if wi.hasDISP()    { appendMethod("DISP")    }
	if wi.hasEXTNFC()  { appendMethod("EXTNFC")  }
	if wi.hasINTNFC()  { appendMethod("INTNFC")  }
	if wi.hasNFCINTF() { appendMethod("NFCINTF") }
	if wi.hasPBC()     { appendMethod("PBC")     }
	if wi.hasKPAD()    { appendMethod("KPAD")    }

	return b.String()
}



func (wi WPSInfo) hasUSB()     bool { return wi.ConfigMethods&methodUSB != 0     }
func (wi WPSInfo) hasETHER()   bool { return wi.ConfigMethods&methodETHER != 0   }
func (wi WPSInfo) hasLAB()     bool { return wi.ConfigMethods&methodLAB != 0     }
func (wi WPSInfo) hasDISP()    bool { return wi.ConfigMethods&methodDISP != 0    }
func (wi WPSInfo) hasEXTNFC()  bool { return wi.ConfigMethods&methodEXTNFC != 0  }
func (wi WPSInfo) hasINTNFC()  bool { return wi.ConfigMethods&methodINTNFC != 0  }
func (wi WPSInfo) hasNFCINTF() bool { return wi.ConfigMethods&methodNFCINTF != 0 }
func (wi WPSInfo) hasPBC()     bool { return wi.ConfigMethods&methodPBC != 0     }
func (wi WPSInfo) hasKPAD()    bool { return wi.ConfigMethods&methodKPAD != 0    }



func (wi WPSInfo) Len() int {
	if wi.APSetupLocked {
        return 7
    }

    total := 0

    if wi.Version > 0 {
		total += 3  // 1.0 or 2.0
    }

    if wi.IsConfigured && wi.ConfigMethods == 0 {
        total += 5  // ' ' + conf
    } else {
        total += 7  // ' ' + unconf
    }

	if wi.ConfigMethods != 0 || wi.APSetupLocked {
        total++ 
    }

    if wi.ConfigMethods != 0 {
        total += wi.lenMethods()
    }

    return total
}



func (wi WPSInfo) lenMethods() int {
	var lenMethods int

	if wi.hasUSB()     { lenMethods += 4 } // ' ' + USB    
	if wi.hasETHER()   { lenMethods += 6 } // ' ' + ETHER  
	if wi.hasLAB()     { lenMethods += 4 } // ' ' + LAB    
	if wi.hasDISP()    { lenMethods += 5 } // ' ' + DISP   
	if wi.hasEXTNFC()  { lenMethods += 7 } // ' ' + EXTNFC 
	if wi.hasINTNFC()  { lenMethods += 7 } // ' ' + INTNFC 
	if wi.hasNFCINTF() { lenMethods += 8 } // ' ' + NFCINTF
	if wi.hasPBC()     { lenMethods += 4 } // ' ' + PBC    
	if wi.hasKPAD()    { lenMethods += 5 } // ' ' + KPAD   

	return lenMethods
}