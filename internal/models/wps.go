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



type WPSInfo struct {
	Version           uint8
	IsConfigured      bool
	APSetupLocked     bool
	StatePresent      bool
	SelectedRegistrar bool
}



func (wi WPSInfo) String() string {
    if wi.Version == 0 && !wi.StatePresent && !wi.APSetupLocked {
        return "0.0"
    }

    if wi.APSetupLocked {
        return "Locked"
    }

    var b strings.Builder

    b.WriteString(formatVersion(wi.Version))

	if wi.SelectedRegistrar {
		b.WriteString(" RGT")
	}

    if wi.StatePresent {
        if wi.IsConfigured {
            b.WriteString(" CONF")
        } else {
            b.WriteString(" UNCONF")
        }
    }

    return b.String()
}



func formatVersion(v uint8) string {
	major := v >> 4
	minor := v & 0x0F

	return fmt.Sprintf("%d.%d", major, minor)
}



func (wi WPSInfo) Len() int {
	if wi.APSetupLocked {
        return 7
    }
   
	total := 3  // 0.0 or 1.0 or 2.0

	if wi.SelectedRegistrar {
		total += 4  // ' ' + RGT
	}

	if wi.StatePresent {
    	if wi.IsConfigured {
    	    total += 5  // ' ' + conf
    	} else {
    	    total += 7  // ' ' + unconf
    	}
	}

    return total
}