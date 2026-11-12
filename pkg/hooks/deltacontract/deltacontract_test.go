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
	"encoding/xml"
	"errors"
	"strings"
	"testing"
)

func TestPathGrammar(t *testing.T) {
	valid := []string{
		"/domain/vcpu",
		"/domain/devices/disk[alias=ua-myvolume]/driver/@cache",
		"/domain/{http://libvirt.org/schemas/domain/qemu/1.0}commandline",
		"/domain/os/type/@arch",
		"/domain/devices/interface[alias=ua-default]/model/@type",
	}
	for _, path := range valid {
		if _, err := parsePath(path); err != nil {
			t.Errorf("expected path %q to be accepted, got %v", path, err)
		}
	}

	invalid := map[string]string{
		"domain/vcpu":              "must start with /",
		"/domain//vcpu":            "descendant",
		"/domain/*":                "wildcard",
		"/domain/devices/disk[0]":  "only alias",
		"/domain/@type/vcpu":       "attribute segments are only allowed at the end",
		"/domain/disk[alias=]":     "alias=",
		"/domain/{}local":          "malformed expanded",
		"/domain/{malformed":       "unbalanced braces",
		"/domain/disk[alias=ua/x]": "grammar separators", // slash inside the predicate is preserved by the splitter
		"/":                        "empty segment",
		"/domain/disk[alias=ua-x]/[alias=ua-y]/x": "empty qualified name",
	}
	for path, wantFragment := range invalid {
		_, err := parsePath(path)
		if err == nil {
			t.Errorf("expected path %q to be rejected", path)
			continue
		}
		var deltaErr *Error
		if !errors.As(err, &deltaErr) || deltaErr.Code != ErrCodeInvalidPath {
			t.Errorf("expected invalid-path error for %q, got %v", path, err)
		}
		if !strings.Contains(err.Error(), wantFragment) {
			t.Errorf("error for %q = %v, want fragment %q", path, err, wantFragment)
		}
	}
}

func TestParseRejectsDTDAndEntities(t *testing.T) {
	documents := map[string]string{
		"doctype":        `<!DOCTYPE domain [<!ENTITY x "y">]><domain>&x;</domain>`,
		"xxe":            `<!DOCTYPE domain [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><domain>&xxe;</domain>`,
		"unknown entity": `<domain>&undefined-entity;</domain>`,
	}
	for name, doc := range documents {
		if _, err := Parse([]byte(doc), DefaultLimits); err == nil {
			t.Errorf("%s: expected rejection", name)
		} else {
			var deltaErr *Error
			if !errors.As(err, &deltaErr) {
				t.Errorf("%s: expected *Error, got %T", name, err)
			}
		}
	}

	doc := `<!DOCTYPE domain><domain/>`
	_, err := Parse([]byte(doc), DefaultLimits)
	var deltaErr *Error
	if !errors.As(err, &deltaErr) || deltaErr.Code != ErrCodeDTDRejected {
		t.Fatalf("expected dtd-rejected, got %v", err)
	}
}

func TestParseEnforcesLimits(t *testing.T) {
	doc := []byte(`<domain><a><b><c>text</c></b></a></domain>`)

	if _, err := Parse(doc, Limits{MaxXMLBytes: 5}); err == nil || !codeIs(err, ErrCodeLimitExceeded) {
		t.Errorf("byte limit: expected limit error, got %v", err)
	}
	if _, err := Parse(doc, Limits{MaxNodes: 2}); err == nil || !codeIs(err, ErrCodeLimitExceeded) {
		t.Errorf("node limit: expected limit error, got %v", err)
	}
	if _, err := Parse(doc, Limits{MaxDepth: 2}); err == nil || !codeIs(err, ErrCodeLimitExceeded) {
		t.Errorf("depth limit: expected limit error, got %v", err)
	}
	if _, err := Parse([]byte(`<domain><unclosed>`), DefaultLimits); err == nil || !codeIs(err, ErrCodeMalformed) {
		t.Errorf("malformed: expected malformed error, got %v", err)
	}
}

func TestParsePreservesUnknownExtensionsAndNamespacedAttributes(t *testing.T) {
	doc := []byte(`<domain xmlns:q="http://libvirt.org/schemas/domain/qemu/1.0" type="qemu">
		<q:commandline q:env="x"><q:arg value="a"/></q:commandline>
		<vcpu>1</vcpu>
	</domain>`)
	root, err := Parse(doc, DefaultLimits)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if root.Name.Local != "domain" {
		t.Fatalf("unexpected root %v", root.Name)
	}
	if attr, found := root.Attr(xmlName("", "type")); !found || attr.Value != "qemu" {
		t.Errorf("plain attribute not preserved: %v", root.Attrs)
	}
	ext := root.directChild(xmlName("http://libvirt.org/schemas/domain/qemu/1.0", "commandline"))
	if ext == nil {
		t.Fatal("unknown namespaced extension element was dropped")
	}
	if attr, found := ext.Attr(xmlName("http://libvirt.org/schemas/domain/qemu/1.0", "env")); !found || attr.Value != "x" {
		t.Errorf("namespaced attribute not preserved: %v", ext.Attrs)
	}
}

func TestNamespacePrefixAndAttributeOrderAreEquivalent(t *testing.T) {
	docA := []byte(`<domain xmlns:q="http://libvirt.org/schemas/domain/qemu/1.0" a="1" b="2">
		<q:commandline><q:arg value="a"/></q:commandline></domain>`)
	docB := []byte(`<domain b="2" a="1" xmlns:z="http://libvirt.org/schemas/domain/qemu/1.0">
		<z:commandline><z:arg value="a"/></z:commandline></domain>`)

	rootA, err := Parse(docA, DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	rootB, err := Parse(docB, DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	result := diffTrees(rootA, rootB, DefaultLimits)
	if result.truncated {
		t.Fatal("diff report unexpectedly truncated")
	}
	if len(result.changes) != 0 {
		t.Errorf("prefix/attr-order changes must be equivalent, got %v", result.changes)
	}
}

func TestDiffDistinguishesChangeCategories(t *testing.T) {
	oldDoc := []byte(`<domain>
		<vcpu>1</vcpu>
		<devices>
			<disk><alias name="ua-a"/><driver name="qemu" cache="none"/></disk>
			<disk><alias name="ua-b"/><driver name="qemu"/></disk>
		</devices>
	</domain>`)
	newDoc := []byte(`<domain>
		<vcpu>2</vcpu>
		<devices>
			<disk><alias name="ua-b"/><driver name="qemu"/></disk>
			<disk><alias name="ua-a"/><driver name="qemu" cache="writeback"/></disk>
			<disk><alias name="ua-c"/><driver name="qemu"/></disk>
		</devices>
	</domain>`)

	rootOld, err := Parse(oldDoc, DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	rootNew, err := Parse(newDoc, DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	result := diffTrees(rootOld, rootNew, DefaultLimits)

	kinds := map[ChangeKind]int{}
	paths := map[string]bool{}
	for _, change := range result.changes {
		kinds[change.Kind]++
		paths[change.Path] = true
	}
	if kinds[KindTextUpdate] == 0 {
		t.Errorf("expected a text-update change, got %v", result.changes)
	}
	if kinds[KindAttrUpdate] == 0 {
		t.Errorf("expected an attribute-update change, got %v", result.changes)
	}
	if kinds[KindAdd] == 0 || kinds[KindDelete] == 0 {
		t.Errorf("reordering must surface add/delete changes, got %v", result.changes)
	}
	if !paths["/domain/vcpu"] {
		t.Errorf("text change path missing: %v", paths)
	}
}

func TestEnforcerAcceptsCompliantEdits(t *testing.T) {
	oldDoc := []byte(`<domain>
		<vcpu>1</vcpu>
		<devices><disk><alias name="ua-a"/><driver name="qemu" cache="none"/></disk></devices>
	</domain>`)
	newDoc := []byte(`<domain>
		<vcpu>2</vcpu>
		<devices><disk><alias name="ua-a"/><driver name="qemu" cache="writeback"/></disk></devices>
	</domain>`)

	enforcer := mustEnforcer(t, &HookDeltaContract{
		APIVersion:    ContractAPIVersion,
		VMIUID:        "uid-1",
		VMIGeneration: 7,
		Sidecars: []SidecarRule{{
			Name:       "hook1",
			SocketPath: "/sockets/hook1.sock",
			Versions:   []string{"v1alpha3"},
			AllowedEdits: []AllowedEdit{
				{Path: "/domain/vcpu", Operations: []Operation{OpTextUpdate}},
				{Path: "/domain/devices/disk[alias=ua-a]/driver/@cache", Operations: []Operation{OpAttrUpdate}},
			},
		}},
	})

	if err := enforcer.ValidateBinding("uid-1", 7, []SidecarIdentity{{Name: "hook1", SocketPath: "/sockets/hook1.sock"}}); err != nil {
		t.Fatalf("binding rejected: %v", err)
	}
	if err := enforcer.Check(SidecarIdentity{Name: "hook1", SocketPath: "/sockets/hook1.sock"}, "v1alpha3", oldDoc, newDoc); err != nil {
		t.Fatalf("compliant edits rejected: %v", err)
	}
	if err := enforcer.Check(SidecarIdentity{Name: "hook1", SocketPath: "/sockets/hook1.sock"}, "v1alpha3", oldDoc, oldDoc); err != nil {
		t.Fatalf("identical bytes rejected: %v", err)
	}
}

func TestEnforcerRejectsUnauthorizedEditAndHidesSecrets(t *testing.T) {
	oldDoc := []byte(`<domain>
		<vcpu>1</vcpu>
		<devices><disk><serial>super-secret-value</serial><alias name="ua-a"/></disk></devices>
	</domain>`)
	newDoc := []byte(`<domain>
		<vcpu>2</vcpu>
		<devices><disk><serial>super-secret-value</serial><alias name="ua-a"/></disk></devices>
	</domain>`)

	enforcer := mustEnforcer(t, contractWithEdits(AllowedEdit{Path: "/domain/name", Operations: []Operation{OpTextUpdate}}))
	err := enforcer.Check(sidecarID(), "v1alpha3", oldDoc, newDoc)
	if err == nil || !codeIs(err, ErrCodeUnauthorizedChange) {
		t.Fatalf("expected unauthorized-change, got %v", err)
	}
	if strings.Contains(err.Error(), "super-secret-value") {
		t.Fatalf("error must not echo XML content: %v", err)
	}
}

func TestParentDeleteRequiresFullDescendantCoverage(t *testing.T) {
	oldDoc := []byte(`<domain><devices>
		<disk><alias name="ua-x"/><driver name="qemu"/></disk>
	</devices></domain>`)
	newDoc := []byte(`<domain><devices></devices></domain>`)

	t.Run("single allowed child path cannot authorize subtree deletion", func(t *testing.T) {
		enforcer := mustEnforcer(t, contractWithEdits(
			AllowedEdit{Path: "/domain/devices/disk[alias=ua-x]/driver/@name", Operations: []Operation{OpAttrUpdate}},
		))
		err := enforcer.Check(sidecarID(), "v1alpha3", oldDoc, newDoc)
		if err == nil || !codeIs(err, ErrCodeUnauthorizedChange) {
			t.Fatalf("expected unauthorized subtree deletion, got %v", err)
		}
	})

	t.Run("exhaustive descendant coverage authorizes the deletion", func(t *testing.T) {
		enforcer := mustEnforcer(t, contractWithEdits(
			AllowedEdit{Path: "/domain/devices/disk[alias=ua-x]", Operations: []Operation{OpDelete}},
			AllowedEdit{Path: "/domain/devices/disk[alias=ua-x]/alias", Operations: []Operation{OpDelete}},
			AllowedEdit{Path: "/domain/devices/disk[alias=ua-x]/alias/@name", Operations: []Operation{OpAttrUpdate}},
			AllowedEdit{Path: "/domain/devices/disk[alias=ua-x]/driver", Operations: []Operation{OpDelete}},
			AllowedEdit{Path: "/domain/devices/disk[alias=ua-x]/driver/@name", Operations: []Operation{OpAttrUpdate}},
		))
		if err := enforcer.Check(sidecarID(), "v1alpha3", oldDoc, newDoc); err != nil {
			t.Fatalf("fully covered deletion rejected: %v", err)
		}
	})
}

func TestAliasAmbiguityAndMissingAlias(t *testing.T) {
	duplicateAlias := []byte(`<domain><devices>
		<disk><alias name="ua-x"/></disk>
		<disk><alias name="ua-x"/></disk>
	</devices></domain>`)

	enforcer := mustEnforcer(t, contractWithEdits(
		AllowedEdit{Path: "/domain/devices/disk[alias=ua-x]/@device", Operations: []Operation{OpAttrUpdate}},
	))
	// A real change is required because identical bytes short-circuit before
	// rule resolution.
	changed := []byte(`<domain attr="x"><devices>
		<disk><alias name="ua-x"/></disk>
		<disk><alias name="ua-x"/></disk>
	</devices></domain>`)
	err := enforcer.Check(sidecarID(), "v1alpha3", duplicateAlias, changed)
	if err == nil || !codeIs(err, ErrCodeAliasAmbiguous) {
		t.Fatalf("expected alias-ambiguous, got %v", err)
	}

	missing := []byte(`<domain><devices><disk><alias name="ua-other"/></disk></devices></domain>`)
	enforcer = mustEnforcer(t, contractWithEdits(
		AllowedEdit{Path: "/domain/devices/disk[alias=ua-missing]/@device", Operations: []Operation{OpAttrUpdate}},
	))
	changedMissing := []byte(`<domain attr="x"><devices><disk><alias name="ua-other"/></disk></devices></domain>`)
	err = enforcer.Check(sidecarID(), "v1alpha3", missing, changedMissing)
	if err == nil || !codeIs(err, ErrCodeAliasNotFound) {
		t.Fatalf("expected alias-not-found, got %v", err)
	}

	multipleWithoutPredicate := []byte(`<domain><devices>
		<disk><alias name="ua-a"/></disk><disk><alias name="ua-b"/></disk>
	</devices></domain>`)
	enforcer = mustEnforcer(t, contractWithEdits(
		AllowedEdit{Path: "/domain/devices/disk/@device", Operations: []Operation{OpAttrUpdate}},
	))
	changedMultiple := []byte(`<domain attr="x"><devices>
		<disk><alias name="ua-a"/></disk><disk><alias name="ua-b"/></disk>
	</devices></domain>`)
	err = enforcer.Check(sidecarID(), "v1alpha3", multipleWithoutPredicate, changedMultiple)
	if err == nil || !codeIs(err, ErrCodeAliasAmbiguous) {
		t.Fatalf("expected positional ambiguity rejection, got %v", err)
	}
}

func TestMixedContentPathsAreRejected(t *testing.T) {
	oldDoc := []byte(`<domain><mixed>hello<child/></mixed></domain>`)
	newDoc := []byte(`<domain><mixed>world<child/></mixed></domain>`)

	enforcer := mustEnforcer(t, contractWithEdits(
		AllowedEdit{Path: "/domain/mixed", Operations: []Operation{OpTextUpdate}},
	))
	err := enforcer.Check(sidecarID(), "v1alpha3", oldDoc, newDoc)
	if err == nil || !codeIs(err, ErrCodeMixedContentUnsupported) {
		t.Fatalf("expected mixed-content rejection, got %v", err)
	}
}

func TestUnknownNamespaceChangesAreVisiblyEnforced(t *testing.T) {
	oldDoc := []byte(`<domain xmlns:q="http://libvirt.org/schemas/domain/qemu/1.0">
		<q:commandline><q:arg value="a"/></q:commandline>
	</domain>`)
	newDoc := []byte(`<domain xmlns:q="http://libvirt.org/schemas/domain/qemu/1.0">
		<q:commandline><q:arg value="b"/></q:commandline>
	</domain>`)

	t.Run("unauthorized namespaced edit is detected", func(t *testing.T) {
		enforcer := mustEnforcer(t, contractWithEdits(
			AllowedEdit{Path: "/domain/vcpu", Operations: []Operation{OpTextUpdate}},
		))
		err := enforcer.Check(sidecarID(), "v1alpha3", oldDoc, newDoc)
		if err == nil || !codeIs(err, ErrCodeUnauthorizedChange) {
			t.Fatalf("expected unauthorized namespaced change, got %v", err)
		}
	})

	t.Run("explicit expanded-name rule authorizes the edit", func(t *testing.T) {
		enforcer := mustEnforcer(t, contractWithEdits(
			AllowedEdit{
				Path:       "/domain/{http://libvirt.org/schemas/domain/qemu/1.0}commandline/{http://libvirt.org/schemas/domain/qemu/1.0}arg/@value",
				Operations: []Operation{OpAttrUpdate},
			},
		))
		if err := enforcer.Check(sidecarID(), "v1alpha3", oldDoc, newDoc); err != nil {
			t.Fatalf("explicit namespaced rule rejected: %v", err)
		}
	})
}

func TestBindingIdentityVersionAndReportLimit(t *testing.T) {
	enforcer := mustEnforcer(t, &HookDeltaContract{
		APIVersion:    ContractAPIVersion,
		VMIUID:        "uid-1",
		VMIGeneration: 7,
		Sidecars: []SidecarRule{{
			Name:       "hook1",
			SocketPath: "/sockets/hook1.sock",
			Versions:   []string{"v1alpha3"},
			AllowedEdits: []AllowedEdit{
				{Path: "/domain/vcpu", Operations: []Operation{OpTextUpdate}},
			},
		}},
	})

	if err := enforcer.ValidateBinding("uid-2", 7, []SidecarIdentity{{Name: "hook1", SocketPath: "/sockets/hook1.sock"}}); !codeIs(err, ErrCodeBindingMismatch) {
		t.Errorf("uid mismatch: got %v", err)
	}
	if err := enforcer.ValidateBinding("uid-1", 8, []SidecarIdentity{{Name: "hook1", SocketPath: "/sockets/hook1.sock"}}); !codeIs(err, ErrCodeBindingMismatch) {
		t.Errorf("generation mismatch: got %v", err)
	}
	identities := []SidecarIdentity{
		{Name: "hook1", SocketPath: "/sockets/hook1.sock"},
		{Name: "hook2", SocketPath: "/sockets/hook2.sock"},
	}
	if err := enforcer.ValidateBinding("uid-1", 7, identities); !codeIs(err, ErrCodeIdentityMismatch) {
		t.Errorf("identity set mismatch: got %v", err)
	}

	oldDoc := []byte(`<domain><vcpu>1</vcpu></domain>`)
	newDoc := []byte(`<domain><vcpu>2</vcpu></domain>`)
	if err := enforcer.Check(SidecarIdentity{Name: "unknown", SocketPath: "/sockets/x.sock"}, "v1alpha3", oldDoc, newDoc); !codeIs(err, ErrCodeMissingContract) {
		t.Errorf("missing contract: got %v", err)
	}
	if err := enforcer.Check(sidecarID(), "v1alpha1", oldDoc, newDoc); !codeIs(err, ErrCodeUnsupportedVersion) {
		t.Errorf("unsupported version: got %v", err)
	}

	enforcer.limits.MaxReportChanges = 1
	manyOld := []byte(`<domain><devices></devices></domain>`)
	manyNew := []byte(`<domain><devices><disk/><disk/><disk/></devices></domain>`)
	if err := enforcer.Check(sidecarID(), "v1alpha3", manyOld, manyNew); !codeIs(err, ErrCodeLimitExceeded) {
		t.Errorf("report limit: got %v", err)
	}
}

func TestContractValidationFailures(t *testing.T) {
	cases := []struct {
		name     string
		contract *HookDeltaContract
		code     string
	}{
		{"bad api version", &HookDeltaContract{APIVersion: "v0"}, ErrCodeUnsupportedContractVersion},
		{"empty uid", &HookDeltaContract{APIVersion: ContractAPIVersion}, ErrCodeInvalidContract},
		{"duplicate identity", &HookDeltaContract{
			APIVersion: ContractAPIVersion, VMIUID: "u",
			Sidecars: []SidecarRule{
				{Name: "h", SocketPath: "/s", Versions: []string{"v1alpha3"}, AllowedEdits: []AllowedEdit{{Path: "/domain", Operations: []Operation{OpAdd}}}},
				{Name: "h", SocketPath: "/s", Versions: []string{"v1alpha3"}, AllowedEdits: []AllowedEdit{{Path: "/domain", Operations: []Operation{OpAdd}}}},
			},
		}, ErrCodeInvalidContract},
		{"unsupported callback version", &HookDeltaContract{
			APIVersion: ContractAPIVersion, VMIUID: "u",
			Sidecars: []SidecarRule{{Name: "h", SocketPath: "/s", Versions: []string{"v9"}, AllowedEdits: []AllowedEdit{{Path: "/domain", Operations: []Operation{OpAdd}}}}},
		}, ErrCodeUnsupportedVersion},
		{"bad path", &HookDeltaContract{
			APIVersion: ContractAPIVersion, VMIUID: "u",
			Sidecars: []SidecarRule{{Name: "h", SocketPath: "/s", Versions: []string{"v1alpha3"}, AllowedEdits: []AllowedEdit{{Path: "domain", Operations: []Operation{OpAdd}}}}},
		}, ErrCodeInvalidPath},
		{"unknown operation", &HookDeltaContract{
			APIVersion: ContractAPIVersion, VMIUID: "u",
			Sidecars: []SidecarRule{{Name: "h", SocketPath: "/s", Versions: []string{"v1alpha3"}, AllowedEdits: []AllowedEdit{{Path: "/domain", Operations: []Operation{"explode"}}}}},
		}, ErrCodeInvalidContract},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.contract.Validate()
			if !codeIs(err, tc.code) {
				t.Fatalf("expected %s, got %v", tc.code, err)
			}
		})
	}
}

func mustEnforcer(t *testing.T, contract *HookDeltaContract) *Enforcer {
	t.Helper()
	enforcer, err := NewEnforcer(contract)
	if err != nil {
		t.Fatalf("failed to build enforcer: %v", err)
	}
	return enforcer
}

func contractWithEdits(edits ...AllowedEdit) *HookDeltaContract {
	return &HookDeltaContract{
		APIVersion:    ContractAPIVersion,
		VMIUID:        "uid-1",
		VMIGeneration: 7,
		Sidecars: []SidecarRule{{
			Name:         "hook1",
			SocketPath:   "/sockets/hook1.sock",
			Versions:     []string{"v1alpha3"},
			AllowedEdits: edits,
		}},
	}
}

func sidecarID() SidecarIdentity {
	return SidecarIdentity{Name: "hook1", SocketPath: "/sockets/hook1.sock"}
}

func codeIs(err error, code string) bool {
	var deltaErr *Error
	return errors.As(err, &deltaErr) && deltaErr.Code == code
}

func xmlName(space, local string) xml.Name {
	return xml.Name{Space: space, Local: local}
}
