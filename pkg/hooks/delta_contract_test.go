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

package hooks

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "kubevirt.io/api/core/v1"

	"kubevirt.io/kubevirt/pkg/hooks/deltacontract"
	hooksInfo "kubevirt.io/kubevirt/pkg/hooks/info"
	hooksV1alpha1 "kubevirt.io/kubevirt/pkg/hooks/v1alpha1"
	hooksV1alpha2 "kubevirt.io/kubevirt/pkg/hooks/v1alpha2"
	hooksV1alpha3 "kubevirt.io/kubevirt/pkg/hooks/v1alpha3"
	virtwrapApi "kubevirt.io/kubevirt/pkg/virt-launcher/virtwrap/api"
)

const (
	contractVMIUID       = "contract-vmi-uid"
	contractVMIGen int64 = 7
)

// deltaInfoServer answers the Info RPC for a fake sidecar.
type deltaInfoServer struct {
	hooksInfo.InfoResult
}

func (s *deltaInfoServer) Info(_ context.Context, _ *hooksInfo.InfoParams) (*hooksInfo.InfoResult, error) {
	return &s.InfoResult, nil
}

// deltaSidecar is a local unix gRPC fake sidecar with a pluggable mutator.
type deltaSidecar struct {
	name     string
	versions []string
	socket   string

	mu           sync.Mutex
	calls        int
	inputs       [][]byte
	serverCtxErr error
	mutator      func([]byte) []byte

	// When non-nil the OnDefineDomain handler blocks until release is closed
	// or the handler context is canceled.
	release chan struct{}

	server *grpc.Server
	cancel context.CancelFunc
	errch  chan error
}

func (s *deltaSidecar) recordCall(input []byte) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	copied := append([]byte(nil), input...)
	s.inputs = append(s.inputs, copied)
	if s.mutator != nil {
		return s.mutator(append([]byte(nil), input...))
	}
	return input
}

func (s *deltaSidecar) wait(ctx context.Context) error {
	if s.release == nil {
		return nil
	}
	select {
	case <-ctx.Done():
		s.mu.Lock()
		s.serverCtxErr = ctx.Err()
		s.mu.Unlock()
		return ctx.Err()
	case <-s.release:
		return nil
	}
}

func (s *deltaSidecar) CallCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func (s *deltaSidecar) LastInput() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.inputs) == 0 {
		return nil
	}
	return append([]byte(nil), s.inputs[len(s.inputs)-1]...)
}

func (s *deltaSidecar) ServerContextError() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.serverCtxErr
}

type deltaSrvV1Alpha1 struct{ sidecar *deltaSidecar }

func (s *deltaSrvV1Alpha1) OnDefineDomain(ctx context.Context, params *hooksV1alpha1.OnDefineDomainParams) (*hooksV1alpha1.OnDefineDomainResult, error) {
	if err := s.sidecar.wait(ctx); err != nil {
		return nil, err
	}
	return &hooksV1alpha1.OnDefineDomainResult{DomainXML: s.sidecar.recordCall(params.GetDomainXML())}, nil
}

type deltaSrvV1Alpha2 struct{ sidecar *deltaSidecar }

func (s *deltaSrvV1Alpha2) OnDefineDomain(ctx context.Context, params *hooksV1alpha2.OnDefineDomainParams) (*hooksV1alpha2.OnDefineDomainResult, error) {
	if err := s.sidecar.wait(ctx); err != nil {
		return nil, err
	}
	return &hooksV1alpha2.OnDefineDomainResult{DomainXML: s.sidecar.recordCall(params.GetDomainXML())}, nil
}

func (s *deltaSrvV1Alpha2) PreCloudInitIso(_ context.Context, params *hooksV1alpha2.PreCloudInitIsoParams) (*hooksV1alpha2.PreCloudInitIsoResult, error) {
	return &hooksV1alpha2.PreCloudInitIsoResult{
		CloudInitData:          params.GetCloudInitData(),
		CloudInitNoCloudSource: params.GetCloudInitNoCloudSource(),
	}, nil
}

type deltaSrvV1Alpha3 struct{ sidecar *deltaSidecar }

func (s *deltaSrvV1Alpha3) OnDefineDomain(ctx context.Context, params *hooksV1alpha3.OnDefineDomainParams) (*hooksV1alpha3.OnDefineDomainResult, error) {
	if err := s.sidecar.wait(ctx); err != nil {
		return nil, err
	}
	return &hooksV1alpha3.OnDefineDomainResult{DomainXML: s.sidecar.recordCall(params.GetDomainXML())}, nil
}

func (s *deltaSrvV1Alpha3) PreCloudInitIso(_ context.Context, params *hooksV1alpha3.PreCloudInitIsoParams) (*hooksV1alpha3.PreCloudInitIsoResult, error) {
	return &hooksV1alpha3.PreCloudInitIsoResult{
		CloudInitData:          params.GetCloudInitData(),
		CloudInitNoCloudSource: params.GetCloudInitNoCloudSource(),
	}, nil
}

func (s *deltaSrvV1Alpha3) Shutdown(_ context.Context, _ *hooksV1alpha3.ShutdownParams) (*hooksV1alpha3.ShutdownResult, error) {
	return &hooksV1alpha3.ShutdownResult{}, nil
}

func startDeltaSidecar(socketDir, name string, priority int32, versions []string, mutator func([]byte) []byte) *deltaSidecar {
	hookPath := filepath.Join(socketDir, "hook-sidecar-"+name)
	Expect(os.MkdirAll(hookPath, os.ModePerm)).ToNot(HaveOccurred())

	_, cancel := context.WithCancel(context.Background())
	sidecar := &deltaSidecar{
		name:     name,
		versions: versions,
		socket:   filepath.Join(hookPath, name+".sock"),
		mutator:  mutator,
		cancel:   cancel,
		errch:    make(chan error, 1),
	}
	server := grpc.NewServer()
	sidecar.server = server

	hooksInfo.RegisterInfoServer(server, &deltaInfoServer{
		InfoResult: hooksInfo.InfoResult{
			Name:     name,
			Versions: versions,
			HookPoints: []*hooksInfo.HookPoint{{
				Name:     hooksInfo.OnDefineDomainHookPointName,
				Priority: priority,
			}},
		},
	})
	for _, version := range versions {
		switch version {
		case hooksV1alpha1.Version:
			hooksV1alpha1.RegisterCallbacksServer(server, &deltaSrvV1Alpha1{sidecar: sidecar})
		case hooksV1alpha2.Version:
			hooksV1alpha2.RegisterCallbacksServer(server, &deltaSrvV1Alpha2{sidecar: sidecar})
		case hooksV1alpha3.Version:
			hooksV1alpha3.RegisterCallbacksServer(server, &deltaSrvV1Alpha3{sidecar: sidecar})
		default:
			panic("unsupported fake sidecar version " + version)
		}
	}

	go func() {
		defer GinkgoRecover()
		socket, err := net.Listen("unix", sidecar.socket)
		Expect(err).ToNot(HaveOccurred())
		defer socket.Close()
		sidecar.errch <- server.Serve(socket)
	}()

	DeferCleanup(func() {
		server.Stop()
		cancel()
		os.Remove(sidecar.socket)
	})
	return sidecar
}

func newEnforcingManager(socketDir string, sidecars []*deltaSidecar, timeout time.Duration) *hookManager {
	manager := newManager(socketDir)
	manager.callbackTimeout = timeout
	Expect(manager.Collect(uint(len(sidecars)), collectTimeout)).To(Succeed())
	return manager
}

// contractFromCollected builds a contract bound to the exact identities the
// manager collected, so tests never rely on sidecar self-declared permissions.
func contractFromCollected(manager *hookManager, edits map[string][]deltacontract.AllowedEdit, limits *deltacontract.Limits) *deltacontract.HookDeltaContract {
	callbacks := manager.CallbacksPerHookPoint[hooksInfo.OnDefineDomainHookPointName]
	rules := make([]deltacontract.SidecarRule, 0, len(callbacks))
	for _, callback := range callbacks {
		rules = append(rules, deltacontract.SidecarRule{
			Name:         callback.Name,
			SocketPath:   callback.SocketPath,
			Versions:     []string{callback.Version},
			AllowedEdits: edits[callback.Name],
		})
	}
	return &deltacontract.HookDeltaContract{
		APIVersion:    deltacontract.ContractAPIVersion,
		VMIUID:        contractVMIUID,
		VMIGeneration: contractVMIGen,
		Sidecars:      rules,
		Limits:        limits,
	}
}

func contractVMI() *v1.VirtualMachineInstance {
	return &v1.VirtualMachineInstance{
		ObjectMeta: metav1.ObjectMeta{UID: contractVMIUID, Generation: contractVMIGen},
		Spec: v1.VirtualMachineInstanceSpec{
			Domain: v1.DomainSpec{Devices: v1.Devices{}},
		},
	}
}

func domainSpecFromTestData() *virtwrapApi.DomainSpec {
	domainSpec := &virtwrapApi.DomainSpec{}
	Expect(xml.Unmarshal(domainXML, domainSpec)).To(Succeed())
	return domainSpec
}

var _ = Describe("HookDeltaContract enforcement", func() {
	var socketDir string

	BeforeEach(func() {
		socketDir = GinkgoT().TempDir()
	})

	editVCPU := func(in []byte) []byte {
		out := strings.Replace(string(in), ">1</vcpu>", ">2</vcpu>", 1)
		Expect(out).ToNot(Equal(string(in)))
		return []byte(out)
	}
	editDiskCache := func(in []byte) []byte {
		out := strings.Replace(string(in), `cache="none"`, `cache="writeback"`, 1)
		Expect(out).ToNot(Equal(string(in)))
		return []byte(out)
	}

	It("accepts two compliant phases and forwards raw bytes between callbacks", func() {
		first := startDeltaSidecar(socketDir, "first", 10, []string{hooksV1alpha3.Version}, editVCPU)
		second := startDeltaSidecar(socketDir, "second", 0, []string{hooksV1alpha3.Version}, editDiskCache)

		manager := newEnforcingManager(socketDir, []*deltaSidecar{first, second}, time.Minute)
		contract := contractFromCollected(manager, map[string][]deltacontract.AllowedEdit{
			"first":  {{Path: "/domain/vcpu", Operations: []deltacontract.Operation{deltacontract.OpTextUpdate}}},
			"second": {{Path: "/domain/devices/disk[alias=ua-ephemeral_pvc]/driver/@cache", Operations: []deltacontract.Operation{deltacontract.OpAttrUpdate}}},
		}, nil)
		Expect(manager.SetDeltaContract(contract)).To(Succeed())

		result, err := manager.OnDefineDomain(domainSpecFromTestData(), contractVMI())
		Expect(err).ToNot(HaveOccurred())
		Expect(first.CallCount()).To(Equal(1))
		Expect(second.CallCount()).To(Equal(1))

		// The second sidecar must receive the exact raw bytes the first one
		// produced; verification must not re-marshal the document.
		Expect(string(second.LastInput())).To(ContainSubstring(">2</vcpu>"))
		Expect(result).To(ContainSubstring(">2</vcpu>"))
		Expect(result).To(ContainSubstring(`cache="writeback"`))
	})

	It("stops the chain on a phase-one unauthorized edit and never returns the rejected bytes", func() {
		first := startDeltaSidecar(socketDir, "first", 10, []string{hooksV1alpha3.Version}, editVCPU)
		second := startDeltaSidecar(socketDir, "second", 0, []string{hooksV1alpha3.Version}, editDiskCache)

		manager := newEnforcingManager(socketDir, []*deltaSidecar{first, second}, time.Minute)
		// Only the second sidecar has any permission; the first sidecar has none.
		contract := contractFromCollected(manager, map[string][]deltacontract.AllowedEdit{
			"second": {{Path: "/domain/devices/disk[alias=ua-ephemeral_pvc]/driver/@cache", Operations: []deltacontract.Operation{deltacontract.OpAttrUpdate}}},
		}, nil)
		Expect(manager.SetDeltaContract(contract)).To(Succeed())

		result, err := manager.OnDefineDomain(domainSpecFromTestData(), contractVMI())
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring(deltacontract.ErrCodeUnauthorizedChange))
		// Rejected output must never reach the domain define entry: the
		// manager returns no XML together with the error.
		Expect(result).To(BeEmpty())
		Expect(first.CallCount()).To(Equal(1))
		Expect(second.CallCount()).To(Equal(0))
		Expect(err.Error()).ToNot(ContainSubstring("2</vcpu>"))
	})

	It("rejects a parent deletion bypass when only a child path is allowed", func() {
		removeDisk := func(in []byte) []byte {
			document := string(in)
			aliasPos := strings.Index(document, `ua-ephemeral_pvc`)
			Expect(aliasPos).To(BeNumerically(">", 0))
			start := strings.LastIndex(document[:aliasPos], "<disk")
			Expect(start).To(BeNumerically(">", 0))
			endRel := strings.Index(document[aliasPos:], "</disk>")
			Expect(endRel).To(BeNumerically(">", 0))
			end := aliasPos + endRel + len("</disk>")
			return []byte(document[:start] + document[end:])
		}
		first := startDeltaSidecar(socketDir, "first", 10, []string{hooksV1alpha3.Version}, removeDisk)

		manager := newEnforcingManager(socketDir, []*deltaSidecar{first}, time.Minute)
		contract := contractFromCollected(manager, map[string][]deltacontract.AllowedEdit{
			"first": {{Path: "/domain/devices/disk[alias=ua-ephemeral_pvc]/driver/@name", Operations: []deltacontract.Operation{deltacontract.OpAttrUpdate}}},
		}, nil)
		Expect(manager.SetDeltaContract(contract)).To(Succeed())

		result, err := manager.OnDefineDomain(domainSpecFromTestData(), contractVMI())
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring(deltacontract.ErrCodeUnauthorizedChange))
		Expect(err.Error()).To(ContainSubstring("disk[alias=ua-ephemeral_pvc]"))
		Expect(result).To(BeEmpty())
	})

	It("rejects duplicate aliases instead of falling back to slice positions", func() {
		duplicateAlias := func(in []byte) []byte {
			extra := `<disk device="disk" type="file"><alias name="ua-ephemeral_pvc"/></disk>`
			out := strings.Replace(string(in), "</devices>", extra+"</devices>", 1)
			Expect(out).ToNot(Equal(string(in)))
			return []byte(out)
		}
		first := startDeltaSidecar(socketDir, "first", 10, []string{hooksV1alpha3.Version}, duplicateAlias)

		manager := newEnforcingManager(socketDir, []*deltaSidecar{first}, time.Minute)
		contract := contractFromCollected(manager, map[string][]deltacontract.AllowedEdit{
			"first": {
				{Path: "/domain/devices/disk[alias=ua-ephemeral_pvc]/@device", Operations: []deltacontract.Operation{deltacontract.OpAttrUpdate}},
				{Path: "/domain/devices", Operations: []deltacontract.Operation{deltacontract.OpAdd}},
			},
		}, nil)
		Expect(manager.SetDeltaContract(contract)).To(Succeed())

		_, err := manager.OnDefineDomain(domainSpecFromTestData(), contractVMI())
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring(deltacontract.ErrCodeAliasAmbiguous))
	})

	It("preserves unknown namespace extensions and enforces edits to them", func() {
		addExtension := func(in []byte) []byte {
			ext := `<x:custom xmlns:x="http://example.com/ext"><x:entry value="a"/></x:custom>`
			return []byte(strings.Replace(string(in), "</domain>", ext+"</domain>", 1))
		}
		first := startDeltaSidecar(socketDir, "first", 10, []string{hooksV1alpha3.Version}, addExtension)
		echo := startDeltaSidecar(socketDir, "second", 0, []string{hooksV1alpha3.Version}, nil)

		manager := newEnforcingManager(socketDir, []*deltaSidecar{first, echo}, time.Minute)

		By("rejecting the unknown extension without an explicit expanded-name rule")
		contract := contractFromCollected(manager, map[string][]deltacontract.AllowedEdit{
			"second": {{Path: "/domain/vcpu", Operations: []deltacontract.Operation{deltacontract.OpTextUpdate}}},
		}, nil)
		Expect(manager.SetDeltaContract(contract)).To(Succeed())
		_, err := manager.OnDefineDomain(domainSpecFromTestData(), contractVMI())
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring(deltacontract.ErrCodeUnauthorizedChange))
		Expect(echo.CallCount()).To(Equal(0))

		By("accepting the extension once every affected path is explicitly covered")
		extURI := "http://example.com/ext"
		Expect(manager.SetDeltaContract(contractFromCollected(manager, map[string][]deltacontract.AllowedEdit{
			"first": {
				{Path: fmt.Sprintf("/domain/{%s}custom", extURI), Operations: []deltacontract.Operation{deltacontract.OpAdd}},
				{Path: fmt.Sprintf("/domain/{%s}custom/{%s}entry", extURI, extURI), Operations: []deltacontract.Operation{deltacontract.OpAdd}},
				{Path: fmt.Sprintf("/domain/{%s}custom/{%s}entry/@value", extURI, extURI), Operations: []deltacontract.Operation{deltacontract.OpAttrUpdate}},
			},
		}, nil))).To(Succeed())

		result, err := manager.OnDefineDomain(domainSpecFromTestData(), contractVMI())
		Expect(err).ToNot(HaveOccurred())
		// Raw bytes, including the unknown prefix, survive the whole chain.
		Expect(result).To(ContainSubstring(`<x:custom xmlns:x="http://example.com/ext">`))
		Expect(string(echo.LastInput())).To(ContainSubstring(`x:entry value="a"`))
	})

	It("rejects output exceeding the contracted XML byte limit", func() {
		appendOversizedComment := func(in []byte) []byte {
			return []byte(string(in) + "<!--" + strings.Repeat("a", 10*1024) + "-->")
		}
		first := startDeltaSidecar(socketDir, "first", 10, []string{hooksV1alpha3.Version}, appendOversizedComment)

		manager := newEnforcingManager(socketDir, []*deltaSidecar{first}, time.Minute)
		contract := contractFromCollected(manager, map[string][]deltacontract.AllowedEdit{
			"first": {{Path: "/domain/vcpu", Operations: []deltacontract.Operation{deltacontract.OpTextUpdate}}},
		}, &deltacontract.Limits{
			MaxXMLBytes:      8192,
			MaxNodes:         deltacontract.DefaultLimits.MaxNodes,
			MaxDepth:         deltacontract.DefaultLimits.MaxDepth,
			MaxReportChanges: deltacontract.DefaultLimits.MaxReportChanges,
			MaxPathString:    deltacontract.DefaultLimits.MaxPathString,
		})
		Expect(manager.SetDeltaContract(contract)).To(Succeed())

		result, err := manager.OnDefineDomain(domainSpecFromTestData(), contractVMI())
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring(deltacontract.ErrCodeLimitExceeded))
		Expect(result).To(BeEmpty())
	})

	It("closes the connection and stops the chain on timeout without claiming rollback", func() {
		never := make(chan struct{})
		first := startDeltaSidecar(socketDir, "first", 10, []string{hooksV1alpha3.Version}, nil)
		first.release = never
		second := startDeltaSidecar(socketDir, "second", 0, []string{hooksV1alpha3.Version}, editVCPU)

		manager := newEnforcingManager(socketDir, []*deltaSidecar{first, second}, 200*time.Millisecond)
		contract := contractFromCollected(manager, map[string][]deltacontract.AllowedEdit{
			"second": {{Path: "/domain/vcpu", Operations: []deltacontract.Operation{deltacontract.OpTextUpdate}}},
		}, nil)
		Expect(manager.SetDeltaContract(contract)).To(Succeed())

		start := time.Now()
		result, err := manager.OnDefineDomain(domainSpecFromTestData(), contractVMI())
		Expect(time.Since(start)).To(BeNumerically("<", 5*time.Second))
		Expect(err).To(HaveOccurred())
		Expect(result).To(BeEmpty())

		var canceled *callbackCanceledError
		Expect(errors.As(err, &canceled)).To(BeTrue(), "expected callbackCanceledError, got %v", err)
		Expect(err.Error()).To(ContainSubstring("chain was stopped"))
		Expect(err.Error()).To(ContainSubstring("not rolled back"))
		Expect(second.CallCount()).To(Equal(0))

		// The server side must observe the canceled handler context, proving
		// the connection was torn down rather than abandoned.
		Eventually(first.ServerContextError, 5*time.Second, 50*time.Millisecond).ShouldNot(BeNil())
	})

	It("keeps the legacy protocol and ordering when no contract is enabled", func() {
		first := startDeltaSidecar(socketDir, "first", 10, []string{hooksV1alpha3.Version}, editVCPU)
		second := startDeltaSidecar(socketDir, "second", 0, []string{hooksV1alpha3.Version}, editDiskCache)

		manager := newEnforcingManager(socketDir, []*deltaSidecar{first, second}, time.Minute)
		Expect(manager.enforcer).To(BeNil())

		result, err := manager.OnDefineDomain(domainSpecFromTestData(), contractVMI())
		Expect(err).ToNot(HaveOccurred())
		Expect(first.CallCount()).To(Equal(1))
		Expect(second.CallCount()).To(Equal(1))
		Expect(string(second.LastInput())).To(ContainSubstring(">2</vcpu>"))
		Expect(result).To(ContainSubstring(">2</vcpu>"))
		Expect(result).To(ContainSubstring(`cache="writeback"`))
	})

	It("enforces contracts through the real v1alpha1, v1alpha2 and v1alpha3 RPC paths", func() {
		for _, version := range []string{hooksV1alpha1.Version, hooksV1alpha2.Version, hooksV1alpha3.Version} {
			By("using callback version " + version)
			dir := GinkgoT().TempDir()
			sidecar := startDeltaSidecar(dir, "hook-"+version, 0, []string{version}, editVCPU)
			manager := newEnforcingManager(dir, []*deltaSidecar{sidecar}, time.Minute)
			contract := contractFromCollected(manager, map[string][]deltacontract.AllowedEdit{
				sidecar.name: {{Path: "/domain/vcpu", Operations: []deltacontract.Operation{deltacontract.OpTextUpdate}}},
			}, nil)
			Expect(manager.SetDeltaContract(contract)).To(Succeed())

			result, err := manager.OnDefineDomain(domainSpecFromTestData(), contractVMI())
			Expect(err).ToNot(HaveOccurred())
			Expect(result).To(ContainSubstring(">2</vcpu>"))
			Expect(sidecar.CallCount()).To(Equal(1))
		}
	})

	It("rejects binding, identity and callback version mismatches", func() {
		first := startDeltaSidecar(socketDir, "first", 10, []string{hooksV1alpha3.Version}, editVCPU)
		manager := newEnforcingManager(socketDir, []*deltaSidecar{first}, time.Minute)
		contract := contractFromCollected(manager, map[string][]deltacontract.AllowedEdit{
			"first": {{Path: "/domain/vcpu", Operations: []deltacontract.Operation{deltacontract.OpTextUpdate}}},
		}, nil)

		By("rejecting a VMI UID mismatch")
		Expect(manager.SetDeltaContract(contract)).To(Succeed())
		wrongUID := contractVMI()
		wrongUID.UID = "other-uid"
		_, err := manager.OnDefineDomain(domainSpecFromTestData(), wrongUID)
		Expect(err.Error()).To(ContainSubstring(deltacontract.ErrCodeBindingMismatch))
		Expect(first.CallCount()).To(Equal(0))

		By("rejecting a VMI generation mismatch")
		wrongGeneration := contractVMI()
		wrongGeneration.Generation = 99
		_, err = manager.OnDefineDomain(domainSpecFromTestData(), wrongGeneration)
		Expect(err.Error()).To(ContainSubstring(deltacontract.ErrCodeBindingMismatch))

		By("rejecting a contracted callback version the sidecar did not negotiate")
		contract.Sidecars[0].Versions = []string{hooksV1alpha2.Version}
		Expect(manager.SetDeltaContract(contract)).To(Succeed())
		_, err = manager.OnDefineDomain(domainSpecFromTestData(), contractVMI())
		Expect(err.Error()).To(ContainSubstring(deltacontract.ErrCodeUnsupportedVersion))
	})

	It("rejects DTD-bearing sidecar output", func() {
		injectDTD := func(in []byte) []byte {
			return []byte(`<!DOCTYPE domain [<!ENTITY x "y">]>` + string(in))
		}
		first := startDeltaSidecar(socketDir, "first", 10, []string{hooksV1alpha3.Version}, injectDTD)
		manager := newEnforcingManager(socketDir, []*deltaSidecar{first}, time.Minute)
		contract := contractFromCollected(manager, map[string][]deltacontract.AllowedEdit{
			"first": {{Path: "/domain/vcpu", Operations: []deltacontract.Operation{deltacontract.OpTextUpdate}}},
		}, nil)
		Expect(manager.SetDeltaContract(contract)).To(Succeed())

		result, err := manager.OnDefineDomain(domainSpecFromTestData(), contractVMI())
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring(deltacontract.ErrCodeDTDRejected))
		Expect(result).To(BeEmpty())
	})
})
