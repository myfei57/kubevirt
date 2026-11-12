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
	"io"
	"strings"
)

// Limits hardens XML parsing and change reporting against hostile sidecar
// output. Zero values are replaced by DefaultLimits.
type Limits struct {
	// MaxXMLBytes rejects oversized documents before tokenizing.
	MaxXMLBytes int `json:"maxXMLBytes"`
	// MaxNodes bounds the number of element nodes in a document.
	MaxNodes int `json:"maxNodes"`
	// MaxDepth bounds element nesting depth.
	MaxDepth int `json:"maxDepth"`
	// MaxReportChanges bounds the number of changes reported for one result.
	MaxReportChanges int `json:"maxReportChanges"`
	// MaxPathString bounds the length of any path rendered into an error.
	MaxPathString int `json:"maxPathString"`
}

// DefaultLimits are conservative defaults suitable for libvirt domain XML.
var DefaultLimits = Limits{
	MaxXMLBytes:      4 * 1024 * 1024,
	MaxNodes:         20000,
	MaxDepth:         100,
	MaxReportChanges: 100,
	MaxPathString:    2048,
}

func (l *Limits) validate() error {
	if l.MaxXMLBytes <= 0 || l.MaxNodes <= 0 || l.MaxDepth <= 0 || l.MaxReportChanges <= 0 || l.MaxPathString <= 0 {
		return &Error{Code: ErrCodeInvalidContract, Details: []string{"limits must all be positive"}}
	}
	return nil
}

func (l Limits) orDefault() Limits {
	defaults := DefaultLimits
	if l.MaxXMLBytes > 0 {
		defaults.MaxXMLBytes = l.MaxXMLBytes
	}
	if l.MaxNodes > 0 {
		defaults.MaxNodes = l.MaxNodes
	}
	if l.MaxDepth > 0 {
		defaults.MaxDepth = l.MaxDepth
	}
	if l.MaxReportChanges > 0 {
		defaults.MaxReportChanges = l.MaxReportChanges
	}
	if l.MaxPathString > 0 {
		defaults.MaxPathString = l.MaxPathString
	}
	return defaults
}

// Node is a generic DOM node. It deliberately preserves unknown extension
// elements, namespaced attributes and character data instead of round-tripping
// through a typed DomainSpec, which would silently drop unknown fields.
type Node struct {
	Name     xml.Name
	Attrs    []xml.Attr
	Children []*Node
	// Text holds the concatenated character data of the element.
	Text string
	// Mixed is true when the element carries both child elements and
	// non-whitespace character data.
	Mixed bool

	parent *Node
	alias  string
}

// Parent returns the parent element or nil for the document root.
func (n *Node) Parent() *Node { return n.parent }

// Alias returns the stable device alias declared by a child alias element.
func (n *Node) Alias() string { return n.alias }

// Attr looks up an attribute by its expanded name.
func (n *Node) Attr(name xml.Name) (xml.Attr, bool) {
	for _, attr := range n.Attrs {
		if attr.Name == name {
			return attr, true
		}
	}
	return xml.Attr{}, false
}

// Parse tokenizes untrusted XML into a generic DOM. It rejects DTDs and entity
// directives (which covers external entity declarations), enforces the
// configured byte/node/depth limits and never fetches external resources.
func Parse(data []byte, limits Limits) (*Node, error) {
	limits = limits.orDefault()
	if len(data) == 0 {
		return nil, &Error{Code: ErrCodeMalformed, Details: []string{"empty document"}}
	}
	if len(data) > limits.MaxXMLBytes {
		return nil, &Error{
			Code:    ErrCodeLimitExceeded,
			Details: []string{fmt.Sprintf("xml size %d exceeds limit %d bytes", len(data), limits.MaxXMLBytes)},
		}
	}

	decoder := xml.NewDecoder(bytes.NewReader(data))
	// Strict mode plus a nil entity map means only the five predefined XML
	// entities resolve; every other entity reference fails. encoding/xml never
	// dereferences external resources itself, and directives are rejected
	// below, so XXE payloads cannot be expanded.
	decoder.Strict = true
	decoder.Entity = nil

	var (
		root      *Node
		stack     []*Node
		nodeCount int
		depth     int
	)

	for {
		token, err := decoder.Token()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, &Error{Code: ErrCodeMalformed, Details: []string{bounded(err.Error())}}
		}

		switch t := token.(type) {
		case xml.StartElement:
			depth++
			if depth > limits.MaxDepth {
				return nil, &Error{
					Code:    ErrCodeLimitExceeded,
					Details: []string{fmt.Sprintf("xml depth exceeds limit of %d", limits.MaxDepth)},
				}
			}
			nodeCount++
			if nodeCount > limits.MaxNodes {
				return nil, &Error{
					Code:    ErrCodeLimitExceeded,
					Details: []string{fmt.Sprintf("xml node count exceeds limit of %d", limits.MaxNodes)},
				}
			}

			// Namespace declarations only bind prefixes; they are not semantic
			// attributes and prefix renames must compare as equivalent, so they
			// are not part of the DOM.
			attrs := make([]xml.Attr, 0, len(t.Attr))
			for _, attr := range t.Attr {
				if attr.Name.Space == "xmlns" || (attr.Name.Space == "" && attr.Name.Local == "xmlns") {
					continue
				}
				attrs = append(attrs, attr)
			}
			node := &Node{Name: t.Name, Attrs: attrs}
			if len(stack) == 0 {
				if root != nil {
					return nil, &Error{Code: ErrCodeMalformed, Details: []string{"multiple document roots"}}
				}
				root = node
			} else {
				parent := stack[len(stack)-1]
				node.parent = parent
				parent.Children = append(parent.Children, node)
			}
			stack = append(stack, node)

		case xml.EndElement:
			if len(stack) == 0 {
				return nil, &Error{Code: ErrCodeMalformed, Details: []string{"unbalanced end element"}}
			}
			finished := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			finished.finalize()
			depth--

		case xml.CharData:
			if len(stack) > 0 {
				stack[len(stack)-1].Text += string(t)
			}

		case xml.Directive:
			directive := strings.TrimSpace(string(t))
			if strings.HasPrefix(strings.ToUpper(directive), "DOCTYPE") {
				return nil, &Error{Code: ErrCodeDTDRejected, Details: []string{"document type declarations are not allowed"}}
			}
			return nil, &Error{Code: ErrCodeDTDRejected, Details: []string{"xml directives are not allowed"}}

		case xml.ProcInst, xml.Comment:
			// Processing instructions are harmless without a DTD and comments
			// carry no domain semantics; both are ignored.
			continue
		}
	}

	if root == nil {
		return nil, &Error{Code: ErrCodeMalformed, Details: []string{"no root element"}}
	}
	if len(stack) != 0 {
		return nil, &Error{Code: ErrCodeMalformed, Details: []string{"unbalanced elements"}}
	}
	return root, nil
}

func (n *Node) finalize() {
	if aliasNode := n.directChild(xml.Name{Local: "alias"}); aliasNode != nil {
		if attr, found := aliasNode.Attr(xml.Name{Local: "name"}); found {
			n.alias = attr.Value
		}
	}
	if len(n.Children) > 0 && strings.TrimSpace(n.Text) != "" {
		n.Mixed = true
	}
}

func (n *Node) directChild(name xml.Name) *Node {
	for _, child := range n.Children {
		if child.Name == name {
			return child
		}
	}
	return nil
}

// significantText returns the text worth comparing: pure indentation between
// child elements is not meaningful, whereas leaf character data is.
func significantText(text string) string {
	return strings.TrimSpace(text)
}
