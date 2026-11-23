package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/PHPCraftdream/mcp-jack/client/modern"
)

// The protocol versions and client identity of contract 4.1 and 4.3.
const (
	modernVersion    = "2026-07-28"
	legacyVersion    = "2025-11-25"
	legacyVersionOld = "2025-06-18"
	clientName       = "mcp-jack-interop-modern-client"
	clientVersion    = "1.0.0"
	regionEchoTool   = "region.echo"
	// unsupportedVersionCode is the client code of the C9 no-era row
	// (contract 4.2).
	unsupportedVersionCode = "unsupported_version"
	// unsupportedVersionNoOverlap is the client code of a -32022 that cannot
	// be retried: a rejection, not a client error (contract 4.3).
	unsupportedVersionNoOverlap = "unsupported_version_no_overlap"
	// defaultJSONID is the --json-id default of contract 4.1. client.CallTool
	// mints its own ids from 1, so only this value lets the native row use it.
	defaultJSONID = "1"
)

// implementedVersions is the version list the C9 retry rule of contract 4.3
// filters the server's supported list against, in fallback order.
var implementedVersions = []string{modernVersion, legacyVersion, legacyVersionOld}

// clientInfo is the optional client implementation info of the C1 _meta.
var clientInfo = map[string]any{"name": clientName, "version": clientVersion}

// regionEchoSchema is the inputSchema of contract 3.4 (d): the annotated tool
// the matrix serves. Scenarios that do not fetch tools/list project the
// arguments with this fixed schema.
const regionEchoSchema = `{"type":"object","properties":{"region":{"type":"string","x-mcp-header":"Region"}},"required":["region"]}`

// modernMetaAndMirrors builds params._meta (C1) and the C2 mirror headers
// through the SDK; params must carry the S6 source field for a method that has
// one (tools/call: map[string]any{"name": tool}).
func modernMetaAndMirrors(version, method string, params map[string]any) (map[string]any, [][2]string, error) {
	mirrors, err := modern.BuildRequestMirrors(version, method, params, clientInfo)
	if err != nil {
		return nil, nil, err
	}
	headers := make([][2]string, 0, len(mirrors.Headers))
	for _, header := range mirrors.Headers {
		headers = append(headers, [2]string{header.Name, header.Value})
	}
	return mirrors.Meta, headers, nil
}

// projectedHeaders is the C5/C6 projection through the SDK: an invalid schema
// yields no headers, and a value that does not match its annotation type
// yields modern.ErrHeaderProjectionInvalidValue.
func projectedHeaders(schema []byte, arguments map[string]any) ([][2]string, error) {
	argumentsJSON, err := json.Marshal(arguments)
	if err != nil {
		return nil, err
	}
	if !modern.ValidateAnnotations(schema).Valid {
		return nil, nil
	}
	headers, err := modern.ProjectArguments(schema, argumentsJSON)
	if err != nil {
		return nil, err
	}
	out := make([][2]string, 0, len(headers))
	for _, header := range headers {
		out = append(out, [2]string{header.Name, header.Value})
	}
	return out, nil
}

// requestBody renders a JSON-RPC request with the id text VERBATIM, so
// --json-id and the four id forms of refusal-id-forms reach the wire unchanged
// (contract 4.1). A method with no parameters still carries "params".
func requestBody(idText, method string, params map[string]any) ([]byte, error) {
	quotedMethod, err := json.Marshal(method)
	if err != nil {
		return nil, err
	}
	paramsJSON, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	return []byte(`{"jsonrpc":"2.0","id":` + idText + `,"method":` + string(quotedMethod) +
		`,"params":` + string(paramsJSON) + `}`), nil
}

// notificationBody renders a JSON-RPC notification: the same body without an
// id member (contract 4.3, notifications/initialized).
func notificationBody(method string, params map[string]any) ([]byte, error) {
	quotedMethod, err := json.Marshal(method)
	if err != nil {
		return nil, err
	}
	paramsJSON, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	return []byte(`{"jsonrpc":"2.0","method":` + string(quotedMethod) + `,"params":` + string(paramsJSON) + `}`), nil
}

// success reports a 2xx answer (contract 4.2 outcome rules).
func success(status int) bool { return status >= 200 && status <= 299 }

// regionEchoArguments is the one argument set contract 4.4 uses.
func regionEchoArguments() map[string]any { return map[string]any{"region": "us-west1"} }

// dropMirror removes one mirror entry, keeping the C2 order of the rest.
func dropMirror(mirrors [][2]string, name string) [][2]string {
	out := make([][2]string, 0, len(mirrors))
	for _, mirror := range mirrors {
		if !strings.EqualFold(mirror[0], name) {
			out = append(out, mirror)
		}
	}
	return out
}

// post writes one JSON POST body and sends it as the given step.
func (c *clientState) post(stepName, idText, method string, params map[string]any, mirrors [][2]string, era string) (*answer, error) {
	body, err := requestBody(idText, method, params)
	if err != nil {
		return nil, err
	}
	return c.perform(request{
		name:        stepName,
		method:      http.MethodPost,
		body:        body,
		contentType: true,
		mirrors:     mirrors,
		era:         era,
	})
}

// discover is the modern server/discover request of contract section 5: it has
// no S6 source field, so it carries no Mcp-Name.
func (c *clientState) discover(stepName, version string) (*answer, error) {
	meta, mirrors, err := modernMetaAndMirrors(version, "server/discover", nil)
	if err != nil {
		return nil, err
	}
	return c.post(stepName, c.jsonID, "server/discover", map[string]any{"_meta": meta}, mirrors, eraModern)
}

// toolsList is the modern tools/list request (contract 3.4 (d)).
func (c *clientState) toolsList(stepName, version string) (*answer, error) {
	meta, mirrors, err := modernMetaAndMirrors(version, "tools/list", nil)
	if err != nil {
		return nil, err
	}
	return c.post(stepName, c.jsonID, "tools/list", map[string]any{"_meta": meta}, mirrors, eraModern)
}

// modernCall is the modern tools/call request of contract 4.4 and section 5.
// withName false drops Mcp-Name, which is the S6 refusal shape of
// refusal-id-forms; a non-nil schema appends the C5/C6 projection after the C2
// mirrors.
func (c *clientState) modernCall(stepName, tool string, arguments map[string]any, version, idText string, schema []byte, withName bool) (*answer, error) {
	meta, mirrors, err := modernMetaAndMirrors(version, "tools/call", map[string]any{"name": tool})
	if err != nil {
		return nil, err
	}
	if !withName {
		mirrors = dropMirror(mirrors, "Mcp-Name")
	}
	if schema != nil {
		projected, err := projectedHeaders(schema, arguments)
		if err != nil {
			// C6: a present argument of the wrong type is the client error
			// header_projection_invalid_value.
			c.stop("header_projection_invalid_value", "client_error")
			return nil, errStopScenario
		}
		mirrors = append(mirrors, projected...)
	}
	params := map[string]any{"name": tool, "arguments": arguments, "_meta": meta}
	return c.post(stepName, idText, "tools/call", params, mirrors, eraModern)
}

// legacyCall is the 0.1.x tools/call of contract section 5: no _meta, no
// mirror headers, and only the session headers a handshake produced.
func (c *clientState) legacyCall(stepName, tool string, arguments map[string]any, sessionHeaders [][2]string) (*answer, error) {
	params := map[string]any{"name": tool, "arguments": arguments}
	return c.post(stepName, c.jsonID, "tools/call", params, sessionHeaders, eraLegacy)
}

// legacyHandshake is the contract 4.3 legacy fallback: initialize with no
// mirror header at all, then notifications/initialized carrying the negotiated
// version and the assigned session. It returns the session headers for the
// operation that follows.
func (c *clientState) legacyHandshake(version string) ([][2]string, error) {
	params := map[string]any{
		"protocolVersion": version,
		"capabilities":    map[string]any{},
		"clientInfo":      clientInfo,
	}
	initialize, err := c.post("initialize", c.jsonID, "initialize", params, nil, eraLegacy)
	if err != nil {
		return nil, err
	}
	if !success(initialize.status) {
		return nil, c.stopSequence()
	}
	// The negotiated version is the response's result.protocolVersion when it
	// is a string, else the requested version.
	negotiated := version
	var parsed struct {
		Result struct {
			ProtocolVersion *string `json:"protocolVersion"`
		} `json:"result"`
	}
	if json.Unmarshal(initialize.body, &parsed) == nil && parsed.Result.ProtocolVersion != nil {
		negotiated = *parsed.Result.ProtocolVersion
	}
	sessionHeaders := [][2]string{{"MCP-Protocol-Version", negotiated}}
	if initialize.step.ResponseSessionID != nil {
		sessionHeaders = append(sessionHeaders, [2]string{"Mcp-Session-Id", *initialize.step.ResponseSessionID})
	}

	readyBody, err := notificationBody("notifications/initialized", map[string]any{})
	if err != nil {
		return nil, err
	}
	ready, err := c.perform(request{
		name:        "initialized",
		method:      http.MethodPost,
		body:        readyBody,
		contentType: true,
		mirrors:     sessionHeaders,
		era:         eraLegacy,
	})
	if err != nil {
		return nil, err
	}
	if !success(ready.status) {
		return nil, c.stopSequence()
	}
	return sessionHeaders, nil
}

// probeAndRun runs one C9 probe and lets settle apply the decision table.
func (c *clientState) probeAndRun(stepName string) error {
	probe, err := c.discover(stepName, c.probeVersion)
	if err != nil {
		return err
	}
	return c.settle(probe, c.probeVersion, true)
}

// settle applies the C9 decision table of contract 4.3 to one VERIFIED probe
// answer. allowRetry is false for the single retried probe: contract 4.3
// never allows a second retry. Only a verified -32022 that cannot be retried
// reports unsupported_version_no_overlap; every other no-era answer (an
// unverified body, or a status outside the table such as a 500) is a client
// error, because the driver accepts that code only where the last response
// carries -32022.
func (c *clientState) settle(probe *answer, attempted string, allowRetry bool) error {
	decision := modern.DetectEraAttempt(probe.status, probe.verified, probe.body, implementedVersions, attempted)
	switch decision.Action {
	case modern.ActionStayModern:
		return c.runModernOperation(modernVersion)
	case modern.ActionFallbackInitialize:
		return c.runLegacyOperation(legacyVersion)
	case modern.ActionRetryWithSupported:
		if !allowRetry || len(decision.Supported) == 0 {
			c.stop(unsupportedVersionNoOverlap, "rejected")
			return errStopScenario
		}
		picked := decision.Supported[0]
		if modern.CompareVersion(picked, modern.ModernMin) < 0 {
			// A legacy pick runs the handshake at that version, then the
			// operation (contract 4.3).
			return c.runLegacyOperation(picked)
		}
		retry, err := c.discover("probe-retry", picked)
		if err != nil {
			return err
		}
		return c.settle(retry, picked, false)
	}
	if decision.Reason == unsupportedVersionNoOverlap {
		c.stop(unsupportedVersionNoOverlap, "rejected")
	} else {
		c.stop(unsupportedVersionCode, "client_error")
	}
	return errStopScenario
}

// runModernOperation runs the settled modern operation of contract 4.3.
func (c *clientState) runModernOperation(version string) error {
	_, err := c.modernCall("call", regionEchoTool, regionEchoArguments(), version, c.jsonID, []byte(regionEchoSchema), true)
	return err
}

// runLegacyOperation runs the settled legacy operation: the handshake at
// version, then the legacy tools/call (contract 4.3).
func (c *clientState) runLegacyOperation(version string) error {
	sessionHeaders, err := c.legacyHandshake(version)
	if err != nil {
		return err
	}
	_, err = c.legacyCall("call", regionEchoTool, regionEchoArguments(), sessionHeaders)
	return err
}

// performEmptyMethod sends the GET or HEAD refusal probe of contract 4.4: no
// body, no Content-Type, no JSON-RPC method, only the protocol-version mirror.
func (c *clientState) performEmptyMethod(method, stepName string) error {
	mirrors := [][2]string{{"MCP-Protocol-Version", modernVersion}}
	_, err := c.perform(request{name: stepName, method: method, mirrors: mirrors, era: eraModern})
	return err
}

// runScenario sends exactly the request sequence of one contract 4.4 row, in
// order, and nothing more.
func (c *clientState) runScenario() error {
	switch c.scenario {
	case "modern-discover":
		_, err := c.discover("discover", modernVersion)
		return err

	case "modern-call-projection":
		list, err := c.toolsList("list", modernVersion)
		if err != nil {
			return err
		}
		if !success(list.status) {
			return c.stopSequence()
		}
		schema := listRegionEchoSchema(list.body)
		_, err = c.modernCall("call", regionEchoTool, regionEchoArguments(), modernVersion, c.jsonID, schema, true)
		return err

	case "modern-mismatch-name":
		first, err := c.modernCall("call", regionEchoTool, regionEchoArguments(), modernVersion, c.jsonID, []byte(regionEchoSchema), true)
		if err != nil {
			return err
		}
		// Contract section 2: the replay is not a new request, so it resends the
		// stored bytes, signature and nonce instead of signing again.
		_, err = c.replay("replay", first.sent)
		return err

	case "modern-repeated-version", "modern-session-stripped":
		_, err := c.modernCall("call", regionEchoTool, regionEchoArguments(), modernVersion, c.jsonID, []byte(regionEchoSchema), true)
		return err

	case "modern-get-405":
		return c.performEmptyMethod(http.MethodGet, "get")

	case "modern-head-405":
		return c.performEmptyMethod(http.MethodHead, "head")

	case "era-auto-modern", "era-auto-legacy", "era-retry-version":
		return c.probeAndRun("probe")

	case "legacy-both-parity":
		_, err := c.legacyCall("call", regionEchoTool, regionEchoArguments(), nil)
		return err

	case "native-era-shape":
		// Contract 4.4: one native jack.whoami call in the era the driver
		// passes. The high-level client mints its own ids from 1, so any other
		// --json-id keeps the low-level signing transport.
		if c.jsonID != defaultJSONID {
			if c.era == eraLegacy {
				_, err := c.legacyCall("whoami", "jack.whoami", map[string]any{}, nil)
				return err
			}
			_, err := c.modernCall("whoami", "jack.whoami", map[string]any{}, modernVersion, c.jsonID, nil, true)
			return err
		}
		return c.nativeEraShape()

	case "refusal-id-forms":
		forms := [][2]string{
			{"id-string", `"abc"`},
			{"id-integer", "7"},
			{"id-null", "null"},
			{"id-fractional", "1.5"},
		}
		for _, form := range forms {
			// Every one of these is refused S6 name_header_missing; a verified
			// refusal does not stop the scenario.
			if _, err := c.modernCall(form[0], regionEchoTool, regionEchoArguments(), modernVersion, form[1], nil, false); err != nil {
				return err
			}
		}
		return nil
	}
	return fmt.Errorf("unsupported scenario %q", c.scenario)
}
