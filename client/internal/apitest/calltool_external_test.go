package client_test

import (
	"context"

	"github.com/PHPCraftdream/mcp-jack/client"
)

// Compile-level proof that CallTool is exported with the documented signature.
var _ = (*client.Client).CallTool

var _ func(*client.Client, context.Context, string, any, any) error = (*client.Client).CallTool
