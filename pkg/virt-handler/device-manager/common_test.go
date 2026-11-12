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

package device_manager_test

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	v1 "kubevirt.io/api/core/v1"

	"kubevirt.io/kubevirt/pkg/util"
	devicemanager "kubevirt.io/kubevirt/pkg/virt-handler/device-manager"
	pluginapi "kubevirt.io/kubevirt/pkg/virt-handler/device-manager/deviceplugin/v1beta1"
)

var _ = Describe("PCI device plugin VFIO cdev allocation", func() {
	var tmpDir string
	var vfioDevicesDir string

	BeforeEach(func() {
		tmpDir = GinkgoT().TempDir()
		vfioDevicesDir = filepath.Join(tmpDir, "dev-vfio-devices")
		Expect(os.MkdirAll(vfioDevicesDir, 0755)).To(Succeed())
		DeferCleanup(devicemanager.SetPCIBasePath(tmpDir))
		DeferCleanup(devicemanager.SetVFIODevicesRoot(vfioDevicesDir))
	})

	It("should include VFIO cdev device specs in Allocate response", func() {
		pciAddr := "0000:08:00.0"
		iommuGroup := "42"
		vfioDevDir := filepath.Join(tmpDir, pciAddr, "vfio-dev")
		Expect(os.MkdirAll(vfioDevDir, 0755)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(vfioDevDir, "vfio0"), []byte{}, 0644)).To(Succeed())
		// Create the actual device file in the mocked /dev/vfio/devices directory
		Expect(os.WriteFile(filepath.Join(vfioDevicesDir, "vfio0"), []byte{}, 0644)).To(Succeed())

		dpi := devicemanager.NewPCIDevicePluginForTest(map[string]string{iommuGroup: pciAddr})

		resp, err := dpi.Allocate(context.Background(), &pluginapi.AllocateRequest{
			ContainerRequests: []*pluginapi.ContainerAllocateRequest{
				{DevicesIDs: []string{iommuGroup}},
			},
		})

		Expect(err).ToNot(HaveOccurred())
		Expect(resp.ContainerResponses).To(HaveLen(1))

		expectedPath := filepath.Join(vfioDevicesDir, "vfio0")
		Expect(resp.ContainerResponses[0].Devices).To(ContainElement(
			BeEquivalentTo(&pluginapi.DeviceSpec{
				HostPath:      expectedPath,
				ContainerPath: expectedPath,
				Permissions:   "mrw",
			})))
	})

	It("should not fail when no VFIO cdev devices exist", func() {
		iommuGroup := "42"
		pciAddr := "0000:08:00.0"
		dpi := devicemanager.NewPCIDevicePluginForTest(map[string]string{iommuGroup: pciAddr})

		resp, err := dpi.Allocate(context.Background(), &pluginapi.AllocateRequest{
			ContainerRequests: []*pluginapi.ContainerAllocateRequest{
				{DevicesIDs: []string{iommuGroup}},
			},
		})

		Expect(err).ToNot(HaveOccurred())
		Expect(resp.ContainerResponses).To(HaveLen(1))

		devicePaths := make([]string, 0)
		for _, spec := range resp.ContainerResponses[0].Devices {
			devicePaths = append(devicePaths, spec.ContainerPath)
		}
		Expect(devicePaths).ToNot(ContainElement(ContainSubstring(vfioDevicesDir)))
	})

	It("should skip VFIO cdev device specs when sysfs dir exists but device files don't", func() {
		// This simulates kernels without CONFIG_VFIO_DEVICE_CDEV where the
		// vfio-dev directory exists in sysfs but the actual character devices
		// in /dev/vfio/devices/ don't exist
		pciAddr := "0000:08:00.0"
		iommuGroup := "42"
		vfioDevDir := filepath.Join(tmpDir, pciAddr, "vfio-dev")
		Expect(os.MkdirAll(vfioDevDir, 0755)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(vfioDevDir, "vfio0"), []byte{}, 0644)).To(Succeed())

		// Note: we don't create /dev/vfio/devices/vfio0, simulating the missing device

		dpi := devicemanager.NewPCIDevicePluginForTest(map[string]string{iommuGroup: pciAddr})

		resp, err := dpi.Allocate(context.Background(), &pluginapi.AllocateRequest{
			ContainerRequests: []*pluginapi.ContainerAllocateRequest{
				{DevicesIDs: []string{iommuGroup}},
			},
		})

		Expect(err).ToNot(HaveOccurred())
		Expect(resp.ContainerResponses).To(HaveLen(1))

		// Should only contain legacy VFIO group devices, not cdev devices
		devicePaths := make([]string, 0)
		for _, spec := range resp.ContainerResponses[0].Devices {
			devicePaths = append(devicePaths, spec.ContainerPath)
		}
		Expect(devicePaths).ToNot(ContainElement(ContainSubstring("/dev/vfio/devices/")))
		Expect(devicePaths).To(ContainElement("/dev/vfio/vfio"))
	})
})

var _ = Describe("PCI device plugin Allocate response isolation", func() {
	const (
		group0    = "42"
		group1    = "43"
		pciAddr0  = "0000:08:00.0"
		pciAddr1  = "0000:09:00.0"
		cdevName0 = "vfio0"
		cdevName1 = "vfio1"
	)

	var (
		tmpDir         string
		vfioDevicesDir string
		envVarName     = util.ResourceNameToEnvVar(v1.PCIResourcePrefix, "test-resource")
	)

	legacyGroupPath := func(group string) string {
		return "/dev/vfio/" + group
	}
	cdevPath := func(cdevName string) string {
		return filepath.Join(vfioDevicesDir, cdevName)
	}
	devicePaths := func(response *pluginapi.ContainerAllocateResponse) []string {
		paths := make([]string, 0, len(response.Devices))
		for _, spec := range response.Devices {
			paths = append(paths, spec.ContainerPath)
		}
		return paths
	}
	newPlugin := func() *devicemanager.PCIDevicePlugin {
		return devicemanager.NewPCIDevicePluginForTest(map[string]string{
			group0: pciAddr0,
			group1: pciAddr1,
		})
	}
	twoContainerRequest := func() *pluginapi.AllocateRequest {
		return &pluginapi.AllocateRequest{
			ContainerRequests: []*pluginapi.ContainerAllocateRequest{
				{DevicesIDs: []string{group0}},
				{DevicesIDs: []string{group1}},
			},
		}
	}

	BeforeEach(func() {
		tmpDir = GinkgoT().TempDir()
		vfioDevicesDir = filepath.Join(tmpDir, "dev-vfio-devices")
		Expect(os.MkdirAll(vfioDevicesDir, 0755)).To(Succeed())
		DeferCleanup(devicemanager.SetPCIBasePath(tmpDir))
		DeferCleanup(devicemanager.SetVFIODevicesRoot(vfioDevicesDir))

		createMockVFIOCDevice := func(pciAddr, cdevName string) {
			vfioDevSysfsDir := filepath.Join(tmpDir, pciAddr, "vfio-dev")
			Expect(os.MkdirAll(vfioDevSysfsDir, 0755)).To(Succeed())
			Expect(os.WriteFile(filepath.Join(vfioDevSysfsDir, cdevName), []byte{}, 0644)).To(Succeed())
			Expect(os.WriteFile(cdevPath(cdevName), []byte{}, 0644)).To(Succeed())
		}
		createMockVFIOCDevice(pciAddr0, cdevName0)
		createMockVFIOCDevice(pciAddr1, cdevName1)
	})

	It("should give each container an independent response carrying only its own PCI addresses", func() {
		resp, err := newPlugin().Allocate(context.Background(), twoContainerRequest())
		Expect(err).ToNot(HaveOccurred())
		Expect(resp.ContainerResponses).To(HaveLen(2))

		firstResponse, secondResponse := resp.ContainerResponses[0], resp.ContainerResponses[1]

		// Version isolation probe: the buggy implementation reused a single
		// ContainerAllocateResponse pointer for every container request.
		Expect(firstResponse).ToNot(BeIdenticalTo(secondResponse))
		// Env maps and device slices must be independent allocations too, not
		// shared headers or backing arrays.
		Expect(reflect.ValueOf(firstResponse.Envs).Pointer()).ToNot(
			Equal(reflect.ValueOf(secondResponse.Envs).Pointer()))
		Expect(reflect.ValueOf(firstResponse.Devices).Pointer()).ToNot(
			Equal(reflect.ValueOf(secondResponse.Devices).Pointer()))

		// The first container must only receive the PCI address of its own IOMMU
		// group; the buggy outer-scope accumulation made it receive both addresses.
		Expect(firstResponse.Envs).To(HaveLen(1))
		Expect(firstResponse.Envs).To(HaveKeyWithValue(envVarName, pciAddr0))
		Expect(secondResponse.Envs).To(HaveLen(1))
		Expect(secondResponse.Envs).To(HaveKeyWithValue(envVarName, pciAddr1))

		firstPaths, secondPaths := devicePaths(firstResponse), devicePaths(secondResponse)
		Expect(firstPaths).To(ContainElements(
			"/dev/vfio/vfio", legacyGroupPath(group0), cdevPath(cdevName0)))
		Expect(firstPaths).ToNot(ContainElement(legacyGroupPath(group1)))
		Expect(firstPaths).ToNot(ContainElement(cdevPath(cdevName1)))
		Expect(secondPaths).To(ContainElements(
			"/dev/vfio/vfio", legacyGroupPath(group1), cdevPath(cdevName1)))
		Expect(secondPaths).ToNot(ContainElement(legacyGroupPath(group0)))
		Expect(secondPaths).ToNot(ContainElement(cdevPath(cdevName0)))
	})

	It("should keep container ownership independent after the response is returned", func() {
		resp, err := newPlugin().Allocate(context.Background(), twoContainerRequest())
		Expect(err).ToNot(HaveOccurred())
		firstResponse, secondResponse := resp.ContainerResponses[0], resp.ContainerResponses[1]
		secondEnvSnapshot := secondResponse.Envs[envVarName]
		secondDeviceCount := len(secondResponse.Devices)

		// Mutate the first container through the returned map and slice headers.
		firstResponse.Envs[envVarName] = "mutated-address"
		firstResponse.Envs["EXTRA_ENV"] = "extra"
		firstResponse.Devices = append(firstResponse.Devices, &pluginapi.DeviceSpec{
			HostPath: "mutated-device", ContainerPath: "mutated-device", Permissions: "mrw",
		})

		Expect(secondResponse.Envs).To(HaveLen(1))
		Expect(secondResponse.Envs[envVarName]).To(Equal(secondEnvSnapshot))
		Expect(secondResponse.Devices).To(HaveLen(secondDeviceCount))
		Expect(devicePaths(secondResponse)).ToNot(ContainElement("mutated-device"))

		// The reverse direction must be isolated as well.
		secondResponse.Envs[envVarName] = "second-mutation"
		Expect(firstResponse.Envs[envVarName]).To(Equal("mutated-address"))
		Expect(firstResponse.Envs).To(HaveLen(2))
	})

	It("should allocate multiple devices to the same container in request order", func() {
		resp, err := newPlugin().Allocate(context.Background(), &pluginapi.AllocateRequest{
			ContainerRequests: []*pluginapi.ContainerAllocateRequest{
				{DevicesIDs: []string{group0, group1}},
			},
		})
		Expect(err).ToNot(HaveOccurred())
		Expect(resp.ContainerResponses).To(HaveLen(1))
		response := resp.ContainerResponses[0]

		Expect(response.Envs).To(HaveKeyWithValue(envVarName, pciAddr0+","+pciAddr1))
		Expect(strings.Split(response.Envs[envVarName], ",")).To(
			Equal([]string{pciAddr0, pciAddr1}))

		paths := devicePaths(response)
		Expect(paths).To(ContainElements(
			"/dev/vfio/vfio",
			legacyGroupPath(group0), legacyGroupPath(group1),
			cdevPath(cdevName0), cdevPath(cdevName1),
		))
		// Every allocated device contributes the VFIO control node, its IOMMU
		// group node and its VFIO cdev node.
		Expect(response.Devices).To(HaveLen(6))
		for _, spec := range response.Devices {
			Expect(spec.HostPath).To(Equal(spec.ContainerPath))
			Expect(spec.Permissions).To(Equal("mrw"))
		}

		// Reversing the request order reverses the env address order.
		reversedResp, err := newPlugin().Allocate(context.Background(), &pluginapi.AllocateRequest{
			ContainerRequests: []*pluginapi.ContainerAllocateRequest{
				{DevicesIDs: []string{group1, group0}},
			},
		})
		Expect(err).ToNot(HaveOccurred())
		Expect(reversedResp.ContainerResponses[0].Envs).To(
			HaveKeyWithValue(envVarName, pciAddr1+","+pciAddr0))
	})

	It("should preserve empty container requests and response ordering", func() {
		resp, err := newPlugin().Allocate(context.Background(), &pluginapi.AllocateRequest{
			ContainerRequests: []*pluginapi.ContainerAllocateRequest{
				{},
				{DevicesIDs: []string{group0}},
				{},
				{DevicesIDs: []string{group1}},
			},
		})
		Expect(err).ToNot(HaveOccurred())
		Expect(resp.ContainerResponses).To(HaveLen(4))

		emptyFirst, first, emptySecond, second :=
			resp.ContainerResponses[0], resp.ContainerResponses[1], resp.ContainerResponses[2], resp.ContainerResponses[3]

		for _, emptyResponse := range []*pluginapi.ContainerAllocateResponse{emptyFirst, emptySecond} {
			Expect(emptyResponse.Devices).To(BeEmpty())
			Expect(emptyResponse.Envs).To(HaveLen(1))
			Expect(emptyResponse.Envs).To(HaveKeyWithValue(envVarName, ""))
		}
		Expect(first.Envs).To(HaveKeyWithValue(envVarName, pciAddr0))
		Expect(second.Envs).To(HaveKeyWithValue(envVarName, pciAddr1))

		// Every container request gets its own response object.
		for i := range resp.ContainerResponses {
			for j := i + 1; j < len(resp.ContainerResponses); j++ {
				Expect(resp.ContainerResponses[i]).ToNot(BeIdenticalTo(resp.ContainerResponses[j]))
			}
		}
	})

	It("should skip unknown device IDs without polluting other containers", func() {
		resp, err := newPlugin().Allocate(context.Background(), &pluginapi.AllocateRequest{
			ContainerRequests: []*pluginapi.ContainerAllocateRequest{
				{DevicesIDs: []string{"unknown-999", group0}},
				{DevicesIDs: []string{group1}},
				{DevicesIDs: []string{"unknown-1", "unknown-2"}},
			},
		})
		Expect(err).ToNot(HaveOccurred())
		Expect(resp.ContainerResponses).To(HaveLen(3))

		first, second, onlyUnknown :=
			resp.ContainerResponses[0], resp.ContainerResponses[1], resp.ContainerResponses[2]

		Expect(first.Envs).To(HaveKeyWithValue(envVarName, pciAddr0))
		Expect(devicePaths(first)).To(ContainElement(legacyGroupPath(group0)))
		Expect(devicePaths(first)).ToNot(ContainElement(legacyGroupPath(group1)))

		Expect(second.Envs).To(HaveKeyWithValue(envVarName, pciAddr1))
		Expect(devicePaths(second)).ToNot(ContainElement(legacyGroupPath(group0)))

		// A container that only requested unknown IDs keeps an empty allocation
		// instead of inheriting another container's devices.
		Expect(onlyUnknown.Devices).To(BeEmpty())
		Expect(onlyUnknown.Envs).To(HaveLen(1))
		Expect(onlyUnknown.Envs).To(HaveKeyWithValue(envVarName, ""))
	})

	It("should not reuse allocation state across repeated Allocate calls", func() {
		dpi := newPlugin()

		firstResp, err := dpi.Allocate(context.Background(), twoContainerRequest())
		Expect(err).ToNot(HaveOccurred())

		// Corrupt everything returned by the first call.
		firstResp.ContainerResponses[0].Envs[envVarName] = "stale-address"
		firstResp.ContainerResponses[0].Envs["STALE"] = "stale"
		firstResp.ContainerResponses[0].Devices = append(
			firstResp.ContainerResponses[0].Devices,
			&pluginapi.DeviceSpec{HostPath: "stale-device", ContainerPath: "stale-device"},
		)
		firstResp.ContainerResponses[1].Envs["STALE"] = "stale"

		secondResp, err := dpi.Allocate(context.Background(), twoContainerRequest())
		Expect(err).ToNot(HaveOccurred())
		Expect(secondResp.ContainerResponses).To(HaveLen(2))
		Expect(secondResp.ContainerResponses[0]).ToNot(BeIdenticalTo(firstResp.ContainerResponses[0]))
		Expect(secondResp.ContainerResponses[1]).ToNot(BeIdenticalTo(firstResp.ContainerResponses[1]))
		Expect(reflect.ValueOf(secondResp.ContainerResponses[0].Envs).Pointer()).ToNot(
			Equal(reflect.ValueOf(firstResp.ContainerResponses[0].Envs).Pointer()))

		Expect(secondResp.ContainerResponses[0].Envs).To(HaveLen(1))
		Expect(secondResp.ContainerResponses[0].Envs).To(HaveKeyWithValue(envVarName, pciAddr0))
		Expect(secondResp.ContainerResponses[1].Envs).To(HaveLen(1))
		Expect(secondResp.ContainerResponses[1].Envs).To(HaveKeyWithValue(envVarName, pciAddr1))
		Expect(devicePaths(secondResp.ContainerResponses[0])).ToNot(ContainElement("stale-device"))

		// A later, smaller request must not inherit addresses accumulated earlier.
		thirdResp, err := dpi.Allocate(context.Background(), &pluginapi.AllocateRequest{
			ContainerRequests: []*pluginapi.ContainerAllocateRequest{
				{DevicesIDs: []string{group1}},
			},
		})
		Expect(err).ToNot(HaveOccurred())
		Expect(thirdResp.ContainerResponses).To(HaveLen(1))
		Expect(thirdResp.ContainerResponses[0].Envs).To(HaveKeyWithValue(envVarName, pciAddr1))
		Expect(devicePaths(thirdResp.ContainerResponses[0])).ToNot(
			ContainElement(legacyGroupPath(group0)))
	})
})
