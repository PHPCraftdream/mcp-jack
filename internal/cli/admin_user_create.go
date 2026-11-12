package cli

import (
	"context"
	"encoding/json"
	"flag"
	"io"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/client"
	"github.com/PHPCraftdream/mcp-jack/userkey"
)

func userCreate(ctx context.Context, args []string, out io.Writer) error {
	f := flag.NewFlagSet("user-create", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	config := f.String("config", "", "")
	publicPath := f.String("public", "", "")
	name := f.String("name", "", "")
	admin := f.String("admin", "", "")
	before := f.Int64("not-before", 0, "")
	after := f.Int64("not-after", 0, "")
	if f.Parse(args) != nil || f.NArg() != 0 || *config == "" || *publicPath == "" || !jack.ValidName(*name) || (*admin != "true" && *admin != "false") || out == nil {
		return errConfig
	}
	beforeSet, afterSet := false, false
	f.Visit(func(option *flag.Flag) {
		switch option.Name {
		case "not-before":
			beforeSet = true
		case "not-after":
			afterSet = true
		}
	})
	if *before < 0 || *before > 999999999999 || *after < 0 || *after > 999999999999 || (beforeSet && afterSet && *before >= *after) {
		return errConfig
	}
	data, err := readPrivate(*publicPath, 4096)
	if err != nil {
		return err
	}
	defer clear(data)
	public, err := userkey.ImportServerPublicEnvelope(data)
	if err != nil {
		return errConfig
	}
	conn, err := loadConnection(*config)
	if err != nil {
		return err
	}
	isAdmin := *admin == "true"
	arguments := client.UserCreateParams{Name: *name, PublicKey: jack.EncodeBase64URL(public.PublicKey()), Admin: &isAdmin}
	if beforeSet {
		arguments.NotBefore = before
	}
	if afterSet {
		arguments.NotAfter = after
	}
	payload, err := conn.nativeResult(ctx, client.ToolAdminUserCreate, arguments)
	if err != nil {
		return err
	}
	var ack client.KidResult
	if json.Unmarshal(payload, &ack) != nil || ack.KID != public.KID() {
		return errRemote
	}
	return json.NewEncoder(out).Encode(ack)
}
