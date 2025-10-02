/*
Maddy Mail Server - Composable all-in-one email server.
Copyright © 2019-2020 Max Mazurov <fox.cpp@disroot.org>, Maddy Mail Server contributors

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

package requiretls

import (
	modconfig "github.com/sadraiiali/maddy_chatmail/framework/config/module"
	"github.com/sadraiiali/maddy_chatmail/framework/exterrors"
	"github.com/sadraiiali/maddy_chatmail/framework/module"
	"github.com/sadraiiali/maddy_chatmail/internal/check"
)

func requireTLS(ctx check.StatelessCheckContext) module.CheckResult {
	if ctx.MsgMeta.Conn != nil && ctx.MsgMeta.Conn.TLS.HandshakeComplete {
		return module.CheckResult{}
	}

	return module.CheckResult{
		Reason: &exterrors.SMTPError{
			Code:         550,
			EnhancedCode: exterrors.EnhancedCode{5, 7, 1},
			Message:      "TLS conversation required",
			CheckName:    "require_tls",
		},
	}
}

func init() {
	check.RegisterStatelessCheck("require_tls", modconfig.FailAction{Reject: true}, requireTLS, nil, nil, nil)
}
