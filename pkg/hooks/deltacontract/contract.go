/*
 * This file is part of the KubeVirt project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright The KubeVirt Authors.
 *
 */

// Package deltacontract implements the optional HookDeltaContract enforcement
// for the OnDefineDomain sidecar callback chain.
//
// The contract is the single authority describing, per explicit sidecar
// identity, which finite domain XML paths a sidecar is allowed to touch and
// which operations it may perform. Every callback result is verified against
// the real structural difference between its input and output bytes before the
// output is accepted. An unauthorized, ambiguous or otherwise non-compliant
// result terminates the chain and is never forwarded to another callback or to
// libvirt.
package deltacontract

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"strings"
)

// ContractAPIVersion is the only supported HookDeltaContract schema version.
const ContractAPIVersion = "v1"

// SupportedCallbackVersions lists the hook RPC versions the contract can bind.
var SupportedCallbackVersions = map[string]struct{}{
	"v1alpha1": {},
	"v1alpha2": {},
	"v1alpha3": {},
}

// Operation is one of the four distinguishable change categories.
type Operation string

const (
	// OpAdd allows creating a new element (together with every explicitly
	// enumerated descendant path of the new subtree).
	OpAdd Operation = "add"
	// OpDelete allows removing an existing element (together with every
	// explicitly enumerated descendant path of the removed subtree).
	OpDelete Operation = "delete"
	// OpAttrUpdate allows adding, removing or changing an element attribute.
	OpAttrUpdate Operation = "attr-update"
	// OpTextUpdate allows changing the meaningful character data of an element.
	OpTextUpdate Operation = "text-update"
)

var knownOperations = map[Operation]struct{}{
	OpAdd:        {},
	OpDelete:     {},
	OpAttrUpdate: {},
	OpTextUpdate: {},
}

// HookDeltaContract is the optional enforcement contract for an
// OnDefineDomain callback chain. It is bound to a single VMI generation and to
// the exact set of sidecar socket identities collected for that VMI pod.
type HookDeltaContract struct {
	// APIVersion must equal ContractAPIVersion.
	APIVersion string `json:"apiVersion"`
	// VMIUID binds the contract to one concrete VirtualMachineInstance.
	VMIUID string `json:"vmiUID"`
	// VMIGeneration binds the contract to one concrete VMI generation.
	VMIGeneration int64 `json:"vmiGeneration"`
	// Sidecars is the exhaustive list of sidecar identities permitted in the
	// chain together with their allowed edits. The list is authoritative:
	// permissions declared by the sidecars themselves are never consulted.
	Sidecars []SidecarRule `json:"sidecars"`
	// Limits optionally overrides the hardening limits of the XML parser.
	Limits *Limits `json:"limits,omitempty"`
}

// SidecarRule describes one explicit sidecar identity and its allowed edits.
type SidecarRule struct {
	// Name is the identity name reported through the Info RPC.
	Name string `json:"name"`
	// SocketPath is the exact unix socket path collected for the sidecar.
	SocketPath string `json:"socketPath"`
	// Versions is the exhaustive set of negotiated callback RPC versions
	// accepted for this identity.
	Versions []string `json:"versions"`
	// AllowedEdits enumerates every finite path/operation pair the sidecar
	// may use. There are no wildcards and subtree edits require every affected
	// descendant path to be listed.
	AllowedEdits []AllowedEdit `json:"allowedEdits"`
}

// AllowedEdit binds one finite path grammar expression to an operation set.
type AllowedEdit struct {
	// Path uses the limited path grammar, e.g.
	//   /domain/devices/disk[alias=ua-myvolume]/driver/@cache
	//   /domain/{http://libvirt.org/schemas/domain/qemu/1.0}commandline
	Path string `json:"path"`
	// Operations is the non-empty set of operations allowed on Path.
	Operations []Operation `json:"operations"`
}

// SidecarIdentity is the collected identity of one hook sidecar connection.
type SidecarIdentity struct {
	Name       string
	SocketPath string
}

// segmentKind distinguishes element and attribute path segments.
type segmentKind int

const (
	segmentElement segmentKind = iota
	segmentAttribute
)

// segment is one parsed path segment. Names always carry the expanded
// namespace URI so that prefix renames cannot change path identity.
type segment struct {
	kind  segmentKind
	name  xml.Name
	alias string
}

// parsedPath is the validated, finite path grammar expression.
type parsedPath struct {
	raw  string
	segs []segment
}

type compiledEdit struct {
	path parsedPath
	ops  map[Operation]struct{}
}

type compiledSidecar struct {
	rule  SidecarRule
	edits []compiledEdit
}

// LoadDeltaContract reads and validates a contract from a JSON file.
func LoadDeltaContract(filePath string) (*HookDeltaContract, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read hook delta contract: %w", err)
	}
	contract := &HookDeltaContract{}
	if err := json.Unmarshal(data, contract); err != nil {
		return nil, fmt.Errorf("failed to decode hook delta contract: %w", err)
	}
	if err := contract.Validate(); err != nil {
		return nil, err
	}
	return contract, nil
}

// Validate performs all document-independent contract checks.
func (c *HookDeltaContract) Validate() error {
	if c.APIVersion != ContractAPIVersion {
		return &Error{Code: ErrCodeUnsupportedContractVersion, Details: []string{c.APIVersion}}
	}
	if strings.TrimSpace(c.VMIUID) == "" {
		return &Error{Code: ErrCodeInvalidContract, Details: []string{"vmiUID must not be empty"}}
	}
	if len(c.Sidecars) == 0 {
		return &Error{Code: ErrCodeInvalidContract, Details: []string{"at least one sidecar rule is required"}}
	}

	seenIdentities := make(map[string]struct{})
	for _, sidecar := range c.Sidecars {
		if strings.TrimSpace(sidecar.Name) == "" || strings.TrimSpace(sidecar.SocketPath) == "" {
			return &Error{Code: ErrCodeInvalidContract, Details: []string{"sidecar name and socketPath must not be empty"}}
		}
		key := identityKey(SidecarIdentity{Name: sidecar.Name, SocketPath: sidecar.SocketPath})
		if _, exists := seenIdentities[key]; exists {
			return &Error{Code: ErrCodeInvalidContract, Details: []string{bounded(sidecar.SocketPath), "duplicate sidecar identity"}}
		}
		seenIdentities[key] = struct{}{}

		if len(sidecar.Versions) == 0 {
			return &Error{Code: ErrCodeInvalidContract, Details: []string{bounded(sidecar.Name), "versions must not be empty"}}
		}
		for _, version := range sidecar.Versions {
			if _, supported := SupportedCallbackVersions[version]; !supported {
				return &Error{Code: ErrCodeUnsupportedVersion, Details: []string{bounded(sidecar.Name), version}}
			}
		}
		// An empty AllowedEdits list is valid: the identity is bound and may
		// connect, but every structural change it produces fails closed.

		seenPaths := make(map[string]struct{})
		for _, edit := range sidecar.AllowedEdits {
			if _, duplicated := seenPaths[edit.Path]; duplicated {
				return &Error{Code: ErrCodeInvalidContract, Details: []string{bounded(edit.Path), "duplicate path rule"}}
			}
			seenPaths[edit.Path] = struct{}{}
			if _, err := parsePath(edit.Path); err != nil {
				return err
			}
			if len(edit.Operations) == 0 {
				return &Error{Code: ErrCodeInvalidContract, Details: []string{bounded(edit.Path), "operations must not be empty"}}
			}
			for _, op := range edit.Operations {
				if _, known := knownOperations[op]; !known {
					return &Error{Code: ErrCodeInvalidContract, Details: []string{bounded(edit.Path), string(op)}}
				}
			}
		}
	}

	if c.Limits != nil {
		if err := c.Limits.validate(); err != nil {
			return err
		}
	}
	return nil
}

func compile(contract *HookDeltaContract) (map[string]*compiledSidecar, Limits, error) {
	limits := DefaultLimits
	if contract.Limits != nil {
		limits = *contract.Limits
	}
	compiled := make(map[string]*compiledSidecar, len(contract.Sidecars))
	for _, sidecar := range contract.Sidecars {
		entry := &compiledSidecar{rule: sidecar}
		for _, edit := range sidecar.AllowedEdits {
			path, err := parsePath(edit.Path)
			if err != nil {
				return nil, limits, err
			}
			ops := make(map[Operation]struct{}, len(edit.Operations))
			for _, op := range edit.Operations {
				ops[op] = struct{}{}
			}
			entry.edits = append(entry.edits, compiledEdit{path: path, ops: ops})
		}
		compiled[identityKey(SidecarIdentity{Name: sidecar.Name, SocketPath: sidecar.SocketPath})] = entry
	}
	return compiled, limits, nil
}

func identityKey(id SidecarIdentity) string {
	return id.SocketPath + "\x00" + id.Name
}

// parsePath parses the limited path grammar:
//
//	path    := "/" segment ("/" segment)*
//	segment := element | attribute
//	element := qname ("[" "alias=" name "]")?
//	attribute := "@" qname
//	qname   := "{" uri "}" local | local
//
// Positional predicates, wildcards, descendant axes and relative segments are
// intentionally rejected so that rules can only name finite, namespace
// expanded locations, optionally pinned by a stable device alias.
// splitSegments splits on "/" only outside of expanded-name braces and alias
// predicates, so that URIs containing slashes (e.g. http://...) stay intact.
func splitSegments(raw string) ([]string, error) {
	var segments []string
	start := 1
	inBrace, inBracket := false, false
	for i := 1; i < len(raw); i++ {
		switch raw[i] {
		case '{':
			if inBrace || inBracket {
				return nil, &Error{Code: ErrCodeInvalidPath, Details: []string{bounded(raw), "unexpected {"}}
			}
			inBrace = true
		case '}':
			if !inBrace {
				return nil, &Error{Code: ErrCodeInvalidPath, Details: []string{bounded(raw), "unexpected }"}}
			}
			inBrace = false
		case '[':
			if inBrace || inBracket {
				return nil, &Error{Code: ErrCodeInvalidPath, Details: []string{bounded(raw), "unexpected ["}}
			}
			inBracket = true
		case ']':
			if !inBracket {
				return nil, &Error{Code: ErrCodeInvalidPath, Details: []string{bounded(raw), "unexpected ]"}}
			}
			inBracket = false
		case '/':
			if !inBrace && !inBracket {
				segments = append(segments, raw[start:i])
				start = i + 1
			}
		}
	}
	if inBrace || inBracket {
		return nil, &Error{Code: ErrCodeInvalidPath, Details: []string{bounded(raw), "unbalanced braces or predicates"}}
	}
	return append(segments, raw[start:]), nil
}

func parsePath(raw string) (parsedPath, error) {
	if raw == "" || raw[0] != '/' {
		return parsedPath{}, &Error{Code: ErrCodeInvalidPath, Details: []string{bounded(raw), "path must start with /"}}
	}
	parts, err := splitSegments(raw)
	if err != nil {
		return parsedPath{}, err
	}
	segs := make([]segment, 0, len(parts))
	for i, part := range parts {
		isLast := i == len(parts)-1
		if part == "" {
			return parsedPath{}, &Error{Code: ErrCodeInvalidPath, Details: []string{bounded(raw), "descendant axes and empty segments are not allowed"}}
		}
		if strings.HasPrefix(part, "@") {
			if !isLast {
				return parsedPath{}, &Error{Code: ErrCodeInvalidPath, Details: []string{bounded(raw), "attribute segments are only allowed at the end of a path"}}
			}
			name, err := parseQName(part[1:], raw)
			if err != nil {
				return parsedPath{}, err
			}
			segs = append(segs, segment{kind: segmentAttribute, name: name})
			continue
		}

		elementPart := part
		var alias string
		if bracket := strings.IndexByte(part, '['); bracket >= 0 {
			if !strings.HasSuffix(part, "]") {
				return parsedPath{}, &Error{Code: ErrCodeInvalidPath, Details: []string{bounded(raw), "predicate must be terminated with ]"}}
			}
			elementPart = part[:bracket]
			predicate := part[bracket+1 : len(part)-1]
			const aliasPrefix = "alias="
			if !strings.HasPrefix(predicate, aliasPrefix) || predicate == aliasPrefix {
				return parsedPath{}, &Error{Code: ErrCodeInvalidPath, Details: []string{bounded(raw), "only alias=<name> predicates are allowed"}}
			}
			alias = predicate[len(aliasPrefix):]
			if strings.ContainsAny(alias, "[]/@{}") {
				return parsedPath{}, &Error{Code: ErrCodeInvalidPath, Details: []string{bounded(raw), "alias names must not contain grammar separators"}}
			}
		}
		name, err := parseQName(elementPart, raw)
		if err != nil {
			return parsedPath{}, err
		}
		if i == 0 && alias != "" {
			return parsedPath{}, &Error{Code: ErrCodeInvalidPath, Details: []string{bounded(raw), "the document root must not carry an alias predicate"}}
		}
		segs = append(segs, segment{kind: segmentElement, name: name, alias: alias})
	}
	return parsedPath{raw: raw, segs: segs}, nil
}

func parseQName(token, rawPath string) (xml.Name, error) {
	if token == "" {
		return xml.Name{}, &Error{Code: ErrCodeInvalidPath, Details: []string{bounded(rawPath), "empty qualified name"}}
	}
	if strings.HasPrefix(token, "{") {
		closing := strings.IndexByte(token, '}')
		if closing < 0 || closing == 1 || closing == len(token)-1 || strings.Count(token, "{") != 1 || strings.Count(token, "}") != 1 {
			return xml.Name{}, &Error{Code: ErrCodeInvalidPath, Details: []string{bounded(rawPath), "malformed expanded name, want {uri}local"}}
		}
		uri, local := token[1:closing], token[closing+1:]
		if strings.ContainsAny(uri, "{}[]") || strings.ContainsAny(local, "{}[]/*@ ") {
			return xml.Name{}, &Error{Code: ErrCodeInvalidPath, Details: []string{bounded(rawPath), "malformed expanded name, want {uri}local"}}
		}
		return xml.Name{Space: uri, Local: local}, nil
	}
	if token == "." || token == ".." || strings.ContainsAny(token, "{}[]/*@ ") {
		return xml.Name{}, &Error{Code: ErrCodeInvalidPath, Details: []string{bounded(rawPath), "wildcards, relative segments and separators are not allowed"}}
	}
	return xml.Name{Local: token}, nil
}

// renderQName renders the expanded name using the same Clark notation the path
// grammar accepts, so rendered change paths are directly comparable to rules.
func renderQName(name xml.Name) string {
	if name.Space == "" {
		return name.Local
	}
	return "{" + name.Space + "}" + name.Local
}
