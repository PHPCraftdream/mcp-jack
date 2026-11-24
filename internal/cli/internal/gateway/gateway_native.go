package gateway

import (
	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/server"
)

type gatewayNative struct {
	native       *server.Native
	serverKID    string
	serverKIDs   map[string]bool
	serverKeys   server.NativeTools
	webhookKeys  server.NativeTools
	adminEnabled bool
}

func (n gatewayNative) Call(c *server.NativeCall) (server.NativeResult, *jack.Error) {
	deny := func() (server.NativeResult, *jack.Error) {
		return server.NativeResult{}, &jack.Error{HTTPStatus: 403, Code: jack.CodeOperationDenied, Message: "operation is not enabled"}
	}
	if c == nil || n.native == nil || c.Kid == n.serverKID || n.serverKIDs[c.Kid] {
		return deny()
	}
	if c.Tool == server.ToolServerKey && n.serverKeys != nil {
		return n.serverKeys.Call(c)
	}
	if c.Tool == server.ToolWebhookKey && n.webhookKeys != nil {
		return n.webhookKeys.Call(c)
	}
	if c.Tool == server.ToolEnroll {
		return n.native.Call(c)
	}
	if n.adminEnabled {
		switch c.Tool {
		case server.ToolAdminUserList, server.ToolAdminUserGet, server.ToolAdminUserCreate,
			server.ToolAdminUserSetAdmin, server.ToolAdminUserRevoke,
			server.ToolAdminInviteCreate, server.ToolAdminInviteList, server.ToolAdminInviteRevoke:
			return n.native.Call(c)
		}
	}
	return deny()
}
