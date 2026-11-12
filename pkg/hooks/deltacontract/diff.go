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

package deltacontract

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"sort"
	"strings"
)

// Stable error codes reported to callers. Error messages built from them only
// contain bounded paths and change categories, never XML content that might
// carry secrets.
const (
	ErrCodeInvalidContract            = "invalid-contract"
	ErrCodeUnsupportedContractVersion = "unsupported-contract-version"
	ErrCodeUnsupportedVersion         = "unsupported-callback-version"
	ErrCodeInvalidPath                = "invalid-path"
	ErrCodeMalformed                  = "malformed-xml"
	ErrCodeDTDRejected                = "dtd-rejected"
	ErrCodeLimitExceeded              = "limit-exceeded"
	ErrCodeBindingMismatch            = "contract-binding-mismatch"
	ErrCodeIdentityMismatch           = "sidecar-identity-mismatch"
	ErrCodeMissingContract            = "missing-sidecar-contract"
	ErrCodeUnauthorizedChange         = "unauthorized-change"
	ErrCodeAliasNotFound              = "alias-not-found"
	ErrCodeAliasAmbiguous             = "alias-ambiguous"
	ErrCodeMixedContentUnsupported    = "mixed-content-unsupported"
)

// Error is the only error type returned by enforcement entry points. Its
// details are bounded strings (paths, categories, counters) and must never be
// populated with raw XML.
type Error struct {
	Code    string
	Details []string
}

func (e *Error) Error() string {
	if len(e.Details) == 0 {
		return e.Code
	}
	return e.Code + ": " + strings.Join(e.Details, "; ")
}

func bounded(value string) string {
	capacity := DefaultLimits.MaxPathString
	if len(value) > capacity {
		return value[:capacity] + "...(truncated)"
	}
	return value
}

// ChangeKind is one of the four supported change categories.
type ChangeKind string

const (
	KindAdd        ChangeKind = "add"
	KindDelete     ChangeKind = "delete"
	KindAttrUpdate ChangeKind = "attribute-update"
	KindTextUpdate ChangeKind = "text-update"
)

// Change describes one structural difference using a canonical bounded path.
type Change struct {
	Kind ChangeKind
	Path string
}

type diffResult struct {
	changes   []Change
	truncated bool
}

// Enforcer verifies sidecar callback results against compiled contract rules.
type Enforcer struct {
	contract *HookDeltaContract
	limits   Limits
	sidecars map[string]*compiledSidecar
}

// NewEnforcer validates and compiles a contract for enforcement.
func NewEnforcer(contract *HookDeltaContract) (*Enforcer, error) {
	if contract == nil {
		return nil, &Error{Code: ErrCodeInvalidContract, Details: []string{"contract must not be nil"}}
	}
	if err := contract.Validate(); err != nil {
		return nil, err
	}
	compiled, limits, err := compile(contract)
	if err != nil {
		return nil, err
	}
	return &Enforcer{contract: contract, limits: limits, sidecars: compiled}, nil
}

// Limits exposes the effective hardening limits.
func (e *Enforcer) Limits() Limits { return e.limits }

// ValidateBinding ensures the contract was issued for this VMI UID/generation
// and that the collected socket identity set matches the contracted set
// exactly. Extra, missing or renamed identities fail closed.
func (e *Enforcer) ValidateBinding(vmiUID string, generation int64, identities []SidecarIdentity) error {
	if vmiUID != e.contract.VMIUID {
		return &Error{Code: ErrCodeBindingMismatch, Details: []string{"vmi UID does not match contract"}}
	}
	if generation != e.contract.VMIGeneration {
		return &Error{
			Code:    ErrCodeBindingMismatch,
			Details: []string{fmt.Sprintf("vmi generation %d does not match contract generation %d", generation, e.contract.VMIGeneration)},
		}
	}

	collected := make(map[string]SidecarIdentity, len(identities))
	for _, id := range identities {
		key := identityKey(id)
		if _, duplicated := collected[key]; duplicated {
			return &Error{Code: ErrCodeIdentityMismatch, Details: []string{bounded(id.SocketPath), "duplicate collected identity"}}
		}
		collected[key] = id
	}

	contracted := make(map[string]struct{}, len(e.contract.Sidecars))
	for _, sidecar := range e.contract.Sidecars {
		contracted[identityKey(SidecarIdentity{Name: sidecar.Name, SocketPath: sidecar.SocketPath})] = struct{}{}
	}

	var unexpected, missing []string
	for key := range collected {
		if _, ok := contracted[key]; !ok {
			unexpected = append(unexpected, key)
		}
	}
	for key := range contracted {
		if _, ok := collected[key]; !ok {
			missing = append(missing, key)
		}
	}
	if len(unexpected) != 0 || len(missing) != 0 {
		sort.Strings(unexpected)
		sort.Strings(missing)
		details := []string{}
		if len(unexpected) > 0 {
			details = append(details, "unexpected sidecar identities: "+bounded(strings.Join(unexpected, ",")))
		}
		if len(missing) > 0 {
			details = append(details, "missing sidecar identities: "+bounded(strings.Join(missing, ",")))
		}
		return &Error{Code: ErrCodeIdentityMismatch, Details: details}
	}
	return nil
}

// Check validates one callback result. The raw output bytes are only read for
// verification and are never re-marshaled; callers keep forwarding the exact
// bytes returned by the sidecar.
func (e *Enforcer) Check(id SidecarIdentity, version string, oldXML, newXML []byte) error {
	entry, found := e.sidecars[identityKey(id)]
	if !found {
		return &Error{Code: ErrCodeMissingContract, Details: []string{bounded(id.Name)}}
	}

	versionAllowed := false
	for _, allowed := range entry.rule.Versions {
		if allowed == version {
			versionAllowed = true
			break
		}
	}
	if !versionAllowed {
		return &Error{Code: ErrCodeUnsupportedVersion, Details: []string{bounded(id.Name), version}}
	}

	// Byte-identical output is trivially compliant and needs no parsing.
	if bytes.Equal(oldXML, newXML) {
		return nil
	}

	oldRoot, err := Parse(oldXML, e.limits)
	if err != nil {
		return err
	}
	newRoot, err := Parse(newXML, e.limits)
	if err != nil {
		return err
	}

	result := diffTrees(oldRoot, newRoot, e.limits)
	if result.truncated {
		return &Error{
			Code:    ErrCodeLimitExceeded,
			Details: []string{fmt.Sprintf("change report exceeds limit of %d; refusing partial verification", e.limits.MaxReportChanges)},
		}
	}
	if len(result.changes) == 0 {
		return nil
	}

	allowed, err := e.buildAllowSet(entry, oldRoot, newRoot)
	if err != nil {
		return err
	}

	var violations []string
	for _, change := range result.changes {
		kinds, pathKnown := allowed[change.Path]
		if !pathKnown {
			violations = append(violations, string(change.Kind)+" "+bounded(change.Path))
			continue
		}
		if _, opAllowed := kinds[change.Kind]; !opAllowed {
			violations = append(violations, string(change.Kind)+" "+bounded(change.Path))
		}
	}
	if len(violations) != 0 {
		return &Error{Code: ErrCodeUnauthorizedChange, Details: violations}
	}
	return nil
}

// buildAllowSet resolves every contracted rule against the tree relevant for
// its operation and renders the canonical paths the rule authorizes.
func (e *Enforcer) buildAllowSet(entry *compiledSidecar, oldRoot, newRoot *Node) (map[string]map[ChangeKind]struct{}, error) {
	allowed := make(map[string]map[ChangeKind]struct{})
	add := func(path string, kind ChangeKind) {
		if _, ok := allowed[path]; !ok {
			allowed[path] = make(map[ChangeKind]struct{})
		}
		allowed[path][kind] = struct{}{}
	}

	for _, edit := range entry.edits {
		finalSegment := edit.path.segs[len(edit.path.segs)-1]
		for op := range edit.ops {
			switch op {
			case OpAttrUpdate:
				if finalSegment.kind != segmentAttribute {
					return nil, &Error{Code: ErrCodeInvalidPath, Details: []string{bounded(edit.path.raw), "attr-update requires an attribute path"}}
				}
				// Resolve against both trees so that attributes removed as part
				// of an explicitly covered subtree deletion can be authorized.
				node, attr, err := resolveEither([]*Node{newRoot, oldRoot}, edit.path.segs)
				if err != nil {
					return nil, err
				}
				if node != nil && attr != nil {
					add(attrPath(node, attr.Name), KindAttrUpdate)
				}
			case OpTextUpdate:
				if finalSegment.kind != segmentElement {
					return nil, &Error{Code: ErrCodeInvalidPath, Details: []string{bounded(edit.path.raw), "text-update requires an element path"}}
				}
				// Same dual-tree rationale as attribute updates.
				node, _, err := resolveEither([]*Node{newRoot, oldRoot}, edit.path.segs)
				if err != nil {
					return nil, err
				}
				if node == nil {
					continue
				}
				if node.Mixed {
					return nil, &Error{Code: ErrCodeMixedContentUnsupported, Details: []string{bounded(edit.path.raw)}}
				}
				add(renderNodePath(node), KindTextUpdate)
			case OpAdd, OpDelete:
				if finalSegment.kind != segmentElement {
					return nil, &Error{Code: ErrCodeInvalidPath, Details: []string{bounded(edit.path.raw), string(op) + " requires an element path"}}
				}
				tree := oldRoot
				kind := KindDelete
				if op == OpAdd {
					tree = newRoot
					kind = KindAdd
				}
				node, _, err := resolve(tree, edit.path.segs)
				if err != nil {
					return nil, err
				}
				if node == nil {
					continue
				}
				if node.Mixed {
					return nil, &Error{Code: ErrCodeMixedContentUnsupported, Details: []string{bounded(edit.path.raw)}}
				}
				add(renderNodePath(node), kind)
			default:
				return nil, &Error{Code: ErrCodeInvalidContract, Details: []string{string(op)}}
			}
		}
	}
	return allowed, nil
}

// resolve walks the parsed segments against a concrete tree. Alias predicates
// must match exactly one sibling; a missing or duplicated alias rejects the
// evaluation. Positional slice selection is never used.
func resolve(root *Node, segs []segment) (*Node, *xml.Attr, error) {
	if len(segs) == 0 || segs[0].kind != segmentElement || segs[0].name != root.Name {
		return nil, nil, &Error{Code: ErrCodeInvalidPath, Details: []string{"path root does not match document root"}}
	}
	current := root
	for i := 1; i < len(segs); i++ {
		seg := segs[i]
		if seg.kind == segmentAttribute {
			attr, found := current.Attr(seg.name)
			if !found {
				return current, nil, nil
			}
			return current, &attr, nil
		}

		var matches []*Node
		for _, child := range current.Children {
			if child.Name != seg.name {
				continue
			}
			if seg.alias == "" || child.alias == seg.alias {
				matches = append(matches, child)
			}
		}
		if seg.alias != "" {
			switch {
			case len(matches) == 0:
				return nil, nil, &Error{Code: ErrCodeAliasNotFound, Details: []string{bounded(seg.alias)}}
			case len(matches) > 1:
				return nil, nil, &Error{Code: ErrCodeAliasAmbiguous, Details: []string{bounded(seg.alias), fmt.Sprintf("%d matching siblings", len(matches))}}
			}
		} else if len(matches) > 1 {
			return nil, nil, &Error{
				Code:    ErrCodeAliasAmbiguous,
				Details: []string{renderQName(seg.name), "multiple siblings match and no alias predicate is present"},
			}
		} else if len(matches) == 0 {
			return nil, nil, nil
		}
		current = matches[0]
	}
	return current, nil, nil
}

// resolveEither attempts resolution against several trees. A hard alias error
// is only returned when no tree can resolve the path, which keeps subtree
// deletion rules working while still rejecting genuine ambiguity.
func resolveEither(roots []*Node, segs []segment) (*Node, *xml.Attr, error) {
	var lastErr error
	for _, tree := range roots {
		node, attr, err := resolve(tree, segs)
		if err != nil {
			lastErr = err
			continue
		}
		if node != nil {
			return node, attr, nil
		}
	}
	if lastErr != nil {
		return nil, nil, lastErr
	}
	return nil, nil, nil
}

func renderNodePath(node *Node) string {
	segments := make([]string, 0, 8)
	for current := node; current != nil; current = current.parent {
		segment := renderQName(current.Name)
		if current.alias != "" {
			segment += "[alias=" + current.alias + "]"
		}
		segments = append(segments, segment)
	}
	for i, j := 0, len(segments)-1; i < j; i, j = i+1, j-1 {
		segments[i], segments[j] = segments[j], segments[i]
	}
	return "/" + strings.Join(segments, "/")
}

func attrPath(node *Node, name xml.Name) string {
	return renderNodePath(node) + "/@" + renderQName(name)
}

// diffTrees computes the structural difference. Element identity is based on
// the expanded name plus the stable alias; ordering is preserved through an
// LCS alignment and is never generally ignored.
func diffTrees(oldRoot, newRoot *Node, limits Limits) diffResult {
	result := diffResult{changes: make([]Change, 0)}
	appendChange := func(change Change) {
		if len(result.changes) >= limits.MaxReportChanges {
			result.truncated = true
			return
		}
		result.changes = append(result.changes, change)
	}

	if oldRoot.Name != newRoot.Name {
		enumerateSubtree(oldRoot, KindDelete, appendChange)
		enumerateSubtree(newRoot, KindAdd, appendChange)
		return result
	}
	compareNodes(oldRoot, newRoot, appendChange)
	return result
}

func compareNodes(oldNode, newNode *Node, appendChange func(Change)) {
	compareAttrs(oldNode, newNode, appendChange)
	compareText(oldNode, newNode, appendChange)
	alignAndCompareChildren(oldNode, newNode, appendChange)
}

func compareAttrs(oldNode, newNode *Node, appendChange func(Change)) {
	oldAttrs := make(map[xml.Name]xml.Attr, len(oldNode.Attrs))
	for _, attr := range oldNode.Attrs {
		oldAttrs[attr.Name] = attr
	}
	newAttrs := make(map[xml.Name]xml.Attr, len(newNode.Attrs))
	for _, attr := range newNode.Attrs {
		newAttrs[attr.Name] = attr
	}

	// Iterate deterministically; attribute *order* is irrelevant for equality.
	names := make([]xml.Name, 0, len(oldAttrs)+len(newAttrs))
	seen := make(map[xml.Name]struct{}, len(oldAttrs)+len(newAttrs))
	for name := range oldAttrs {
		names = append(names, name)
		seen[name] = struct{}{}
	}
	for name := range newAttrs {
		if _, ok := seen[name]; !ok {
			names = append(names, name)
		}
	}
	sort.Slice(names, func(i, j int) bool {
		if names[i].Space != names[j].Space {
			return names[i].Space < names[j].Space
		}
		return names[i].Local < names[j].Local
	})

	for _, name := range names {
		oldAttr, oldExists := oldAttrs[name]
		newAttr, newExists := newAttrs[name]
		if oldExists != newExists || (oldExists && newExists && oldAttr.Value != newAttr.Value) {
			appendChange(Change{Kind: KindAttrUpdate, Path: attrPath(newNode, name)})
		}
	}
}

func compareText(oldNode, newNode *Node, appendChange func(Change)) {
	if len(oldNode.Children) == 0 && len(newNode.Children) == 0 {
		if significantText(oldNode.Text) != significantText(newNode.Text) {
			appendChange(Change{Kind: KindTextUpdate, Path: renderNodePath(newNode)})
		}
		return
	}
	if (oldNode.Mixed || newNode.Mixed) && significantText(oldNode.Text) != significantText(newNode.Text) {
		appendChange(Change{Kind: KindTextUpdate, Path: renderNodePath(newNode)})
	}
}

func alignAndCompareChildren(oldNode, newNode *Node, appendChange func(Change)) {
	oldKeys := make([]string, len(oldNode.Children))
	newKeys := make([]string, len(newNode.Children))
	for i, child := range oldNode.Children {
		oldKeys[i] = childKey(child)
	}
	for i, child := range newNode.Children {
		newKeys[i] = childKey(child)
	}

	// Longest common subsequence over stable child keys.
	lcs := make([][]int, len(oldKeys)+1)
	for i := range lcs {
		lcs[i] = make([]int, len(newKeys)+1)
	}
	for i := 1; i <= len(oldKeys); i++ {
		for j := 1; j <= len(newKeys); j++ {
			if oldKeys[i-1] == newKeys[j-1] {
				lcs[i][j] = lcs[i-1][j-1] + 1
			} else if lcs[i-1][j] >= lcs[i][j-1] {
				lcs[i][j] = lcs[i-1][j]
			} else {
				lcs[i][j] = lcs[i][j-1]
			}
		}
	}

	type pair struct{ old, new *Node }
	var pairs []pair
	var removed, added []*Node
	i, j := len(oldKeys), len(newKeys)
	for i > 0 || j > 0 {
		switch {
		case i > 0 && j > 0 && oldKeys[i-1] == newKeys[j-1]:
			pairs = append(pairs, pair{old: oldNode.Children[i-1], new: newNode.Children[j-1]})
			i--
			j--
		case j > 0 && (i == 0 || lcs[i][j-1] >= lcs[i-1][j]):
			added = append(added, newNode.Children[j-1])
			j--
		default:
			removed = append(removed, oldNode.Children[i-1])
			i--
		}
	}

	for k := 0; k < len(removed)/2; k++ {
		removed[k], removed[len(removed)-1-k] = removed[len(removed)-1-k], removed[k]
	}
	for k := 0; k < len(added)/2; k++ {
		added[k], added[len(added)-1-k] = added[len(added)-1-k], added[k]
	}

	for _, node := range removed {
		enumerateSubtree(node, KindDelete, appendChange)
	}
	for _, node := range added {
		enumerateSubtree(node, KindAdd, appendChange)
	}
	for k := len(pairs) - 1; k >= 0; k-- {
		compareNodes(pairs[k].old, pairs[k].new, appendChange)
	}
}

func childKey(node *Node) string {
	return node.Name.Space + "|" + node.Name.Local + "|" + node.alias
}

// enumerateSubtree emits one change per affected node so that a parent
// deletion or replacement can only pass when the contract explicitly covers
// every descendant. Allowing one child path must never authorize the whole
// subtree.
func enumerateSubtree(node *Node, kind ChangeKind, appendChange func(Change)) {
	appendChange(Change{Kind: kind, Path: renderNodePath(node)})
	for _, attr := range node.Attrs {
		appendChange(Change{Kind: KindAttrUpdate, Path: attrPath(node, attr.Name)})
	}
	if significantText(node.Text) != "" {
		appendChange(Change{Kind: KindTextUpdate, Path: renderNodePath(node)})
	}
	for _, child := range node.Children {
		enumerateSubtree(child, kind, appendChange)
	}
}
