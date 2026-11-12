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

package snapshot

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	vsv1 "github.com/kubernetes-csi/external-snapshotter/client/v4/apis/volumesnapshot/v1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/testing"
	"k8s.io/client-go/tools/record"

	kubevirtv1 "kubevirt.io/api/core/v1"
	instancetypeapi "kubevirt.io/api/instancetype"
	snapshotv1 "kubevirt.io/api/snapshot/v1beta1"
	cdifake "kubevirt.io/client-go/containerizeddataimporter/fake"
	"kubevirt.io/client-go/kubecli"
	kubevirtfake "kubevirt.io/client-go/kubevirt/fake"
	cdiv1 "kubevirt.io/containerized-data-importer-api/pkg/apis/core/v1beta1"

	virtcontroller "kubevirt.io/kubevirt/pkg/controller"
	"kubevirt.io/kubevirt/pkg/instancetype/revision"
	"kubevirt.io/kubevirt/pkg/pointer"
	backendstorage "kubevirt.io/kubevirt/pkg/storage/backend-storage"
	storageutils "kubevirt.io/kubevirt/pkg/storage/utils"
	"kubevirt.io/kubevirt/pkg/testutils"
)

type writeSpy struct {
	counts map[string]int
}

func newWriteSpy() *writeSpy {
	return &writeSpy{counts: map[string]int{}}
}

func (s *writeSpy) record(verb, resource string) {
	s.counts[verb+"|"+resource]++
}

func (s *writeSpy) total() int {
	total := 0
	for _, count := range s.counts {
		total += count
	}
	return total
}

func (s *writeSpy) totalForResource(resource string) int {
	total := 0
	for key, count := range s.counts {
		if strings.HasSuffix(key, "|"+resource) {
			total += count
		}
	}
	return total
}

type recordedAction struct {
	verb        string
	resource    string
	name        string
	subresource string
}

func (a recordedAction) key() string {
	return strings.Join([]string{a.verb, a.resource, a.name, a.subresource}, "|")
}

var _ = Describe("Cold restore preview", func() {
	const (
		previewNamespace = "default"
		previewUID       = "preview-uid"
		previewVMName    = "testvm"
		previewSnapName  = "snapshot"
		previewRestore   = "restore"
	)

	var (
		controller *VMRestoreController
		planner    *ColdRestorePlanner
		recorder   *record.FakeRecorder

		kubevirtClient *kubevirtfake.Clientset
		k8sClient      *k8sfake.Clientset
		cdiClient      *cdifake.Clientset

		spy *writeSpy

		volumeSnapshotProvider *MockVolumeSnapshotProvider
	)

	storageClass := func() *storagev1.StorageClass {
		binding := storagev1.VolumeBindingImmediate
		reclaim := corev1.PersistentVolumeReclaimDelete
		return &storagev1.StorageClass{
			ObjectMeta:        metav1.ObjectMeta{Name: storageClassName},
			VolumeBindingMode: &binding,
			ReclaimPolicy:     &reclaim,
		}
	}

	restore := func() *snapshotv1.VirtualMachineRestore {
		return &snapshotv1.VirtualMachineRestore{
			ObjectMeta: metav1.ObjectMeta{
				Name:              previewRestore,
				Namespace:         previewNamespace,
				UID:               previewUID,
				CreationTimestamp: metav1.Time{Time: time.Now().Truncate(time.Second)},
			},
			Spec: snapshotv1.VirtualMachineRestoreSpec{
				Target: corev1.TypedLocalObjectReference{
					APIGroup: pointer.P("kubevirt.io"),
					Kind:     "VirtualMachine",
					Name:     previewVMName,
				},
				VirtualMachineSnapshotName: previewSnapName,
			},
		}
	}

	snapshotWithContent := func(vm *kubevirtv1.VirtualMachine, pvcs []corev1.PersistentVolumeClaim) (
		*snapshotv1.VirtualMachineSnapshot, *snapshotv1.VirtualMachineSnapshotContent,
	) {
		s := createVirtualMachineSnapshot(previewNamespace, previewSnapName, vm.Name)
		s.Finalizers = []string{"snapshot.kubevirt.io/vmsnapshot-protection"}
		s.Status = &snapshotv1.VirtualMachineSnapshotStatus{
			ReadyToUse:   pointer.P(true),
			CreationTime: pointer.P(metav1.Time{Time: time.Now().Truncate(time.Second)}),
			SourceUID:    &vmUID,
			Phase:        snapshotv1.Succeeded,
		}
		content := createVirtualMachineSnapshotContent(s, vm, pvcs)
		content.Status = &snapshotv1.VirtualMachineSnapshotContentStatus{
			CreationTime: pointer.P(metav1.Time{Time: time.Now().Truncate(time.Second)}),
			ReadyToUse:   pointer.P(true),
		}
		s.Status.VirtualMachineSnapshotContentName = &content.Name
		return s, content
	}

	volumeSnapshotFor := func(name string) *vsv1.VolumeSnapshot {
		size := resource.MustParse("2Gi")
		return &vsv1.VolumeSnapshot{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Status:     &vsv1.VolumeSnapshotStatus{RestoreSize: &size},
		}
	}

	// stockProviderWithContent feeds one VolumeSnapshot per content volume backup, in order.
	stockProviderWithContent := func(content *snapshotv1.VirtualMachineSnapshotContent) {
		for _, vb := range content.Spec.VolumeBackups {
			if vb.VolumeSnapshotName != nil {
				volumeSnapshotProvider.Add(volumeSnapshotFor(*vb.VolumeSnapshotName))
			}
		}
	}

	BeforeEach(func() {
		gomockCtrl := gomock.NewController(GinkgoT())
		virtClient := kubecli.NewMockKubevirtClient(gomockCtrl)

		vmRestoreInformer, _ := testutils.NewFakeInformerWithIndexersFor(&snapshotv1.VirtualMachineRestore{}, virtcontroller.GetVirtualMachineRestoreInformerIndexers())
		vmSnapshotInformer, _ := testutils.NewFakeInformerFor(&snapshotv1.VirtualMachineSnapshot{})
		vmSnapshotContentInformer, _ := testutils.NewFakeInformerFor(&snapshotv1.VirtualMachineSnapshotContent{})
		vmiInformer, _ := testutils.NewFakeInformerFor(&kubevirtv1.VirtualMachineInstance{})
		vmInformer, _ := testutils.NewFakeInformerFor(&kubevirtv1.VirtualMachine{})
		dataVolumeInformer, _ := testutils.NewFakeInformerFor(&cdiv1.DataVolume{})
		pvcInformer, _ := testutils.NewFakeInformerFor(&corev1.PersistentVolumeClaim{})
		scInformer, _ := testutils.NewFakeInformerFor(&storagev1.StorageClass{})
		crInformer, _ := testutils.NewFakeInformerWithIndexersFor(&appsv1.ControllerRevision{}, virtcontroller.GetControllerRevisionInformerIndexers())

		recorder = record.NewFakeRecorder(100)
		recorder.IncludeObject = true
		volumeSnapshotProvider = &MockVolumeSnapshotProvider{volumeSnapshots: []*vsv1.VolumeSnapshot{}}

		controller = &VMRestoreController{
			Client:                    virtClient,
			VMRestoreInformer:         vmRestoreInformer,
			VMSnapshotInformer:        vmSnapshotInformer,
			VMSnapshotContentInformer: vmSnapshotContentInformer,
			VMInformer:                vmInformer,
			VMIInformer:               vmiInformer,
			PVCInformer:               pvcInformer,
			StorageClassInformer:      scInformer,
			DataVolumeInformer:        dataVolumeInformer,
			CRInformer:                crInformer,
			Recorder:                  recorder,
			VolumeSnapshotProvider:    volumeSnapshotProvider,
		}
		controller.Init()
		controller.vmRestoreQueue = testutils.NewMockWorkQueue(controller.vmRestoreQueue)
		planner = NewColdRestorePlanner(controller)

		kubevirtClient = kubevirtfake.NewSimpleClientset()
		virtClient.EXPECT().VirtualMachine(gomock.Any()).Return(kubevirtClient.KubevirtV1().VirtualMachines(previewNamespace)).AnyTimes()
		virtClient.EXPECT().VirtualMachineRestore(gomock.Any()).Return(kubevirtClient.SnapshotV1beta1().VirtualMachineRestores(previewNamespace)).AnyTimes()
		virtClient.EXPECT().VirtualMachineSnapshot(gomock.Any()).Return(kubevirtClient.SnapshotV1beta1().VirtualMachineSnapshots(previewNamespace)).AnyTimes()
		virtClient.EXPECT().VirtualMachineSnapshotContent(gomock.Any()).Return(kubevirtClient.SnapshotV1beta1().VirtualMachineSnapshotContents(previewNamespace)).AnyTimes()

		k8sClient = k8sfake.NewSimpleClientset()
		virtClient.EXPECT().CoreV1().Return(k8sClient.CoreV1()).AnyTimes()

		cdiClient = cdifake.NewSimpleClientset()
		virtClient.EXPECT().CdiClient().Return(cdiClient).AnyTimes()
		virtClient.EXPECT().AppsV1().Return(k8sClient.AppsV1()).AnyTimes()

		spy = newWriteSpy()
		for _, verb := range []string{"create", "update", "delete", "patch"} {
			verbCopy := verb
			k8sClient.Fake.PrependReactor(verbCopy, "*", func(action testing.Action) (bool, runtime.Object, error) {
				spy.record(verbCopy, action.GetResource().Resource)
				return false, nil, nil
			})
			kubevirtClient.Fake.PrependReactor(verbCopy, "*", func(action testing.Action) (bool, runtime.Object, error) {
				spy.record(verbCopy, action.GetResource().Resource)
				return false, nil, nil
			})
			cdiClient.Fake.PrependReactor(verbCopy, "*", func(action testing.Action) (bool, runtime.Object, error) {
				spy.record(verbCopy, action.GetResource().Resource)
				return false, nil, nil
			})
		}
	})

	addRestore := func(r *snapshotv1.VirtualMachineRestore) {
		Expect(controller.VMRestoreInformer.GetStore().Add(r)).To(Succeed())
	}

	seedSnapshot := func(vm *kubevirtv1.VirtualMachine) (*snapshotv1.VirtualMachineSnapshot, *snapshotv1.VirtualMachineSnapshotContent) {
		pvcs := createPVCsForVM(vm)
		s, content := snapshotWithContent(vm, pvcs)
		Expect(controller.VMSnapshotInformer.GetStore().Add(s)).To(Succeed())
		Expect(controller.VMSnapshotContentInformer.GetStore().Add(content)).To(Succeed())
		Expect(controller.StorageClassInformer.GetStore().Add(storageClass())).To(Succeed())
		stockProviderWithContent(content)
		return s, content
	}

	findAction := func(plan *ColdRestorePlan, verb PlannedActionVerb, kind, name string) (PlannedAction, bool) {
		for _, action := range plan.Actions {
			if action.Verb == verb && action.Resource.Kind == kind && action.Resource.Name == name {
				return action, true
			}
		}
		return PlannedAction{}, false
	}

	hasPrecondition := func(preconditions []RestorePlanPrecondition, id string, status PreconditionStatus) bool {
		for _, precondition := range preconditions {
			if precondition.Type == id && precondition.Status == status {
				return true
			}
		}
		return false
	}

	planHasGlobalPrecondition := func(plan *ColdRestorePlan, id string, status PreconditionStatus) bool {
		return hasPrecondition(plan.Preconditions, id, status)
	}

	It("builds a ready plan without any write and with pinned input digests", func() {
		vm := createVirtualMachine(previewNamespace, previewVMName)
		seedSnapshot(vm)
		r := restore()
		addRestore(r)

		plan, err := planner.PreviewColdRestorePlan(context.Background(), r)
		Expect(err).ToNot(HaveOccurred())
		Expect(plan.Phase).To(Equal(ColdRestorePlanReady))
		Expect(spy.total()).To(BeZero(), "preview must not perform any create/update/delete/patch")

		Expect(plan.Inputs.RestoreUID).To(Equal(types.UID(previewUID)))
		Expect(plan.Inputs.SnapshotName).To(Equal(previewSnapName))
		Expect(plan.Inputs.TargetName).To(Equal(previewVMName))
		Expect(plan.Inputs.ContentDigest).ToNot(BeEmpty())
		Expect(plan.Inputs.TargetSpecDigest).ToNot(BeEmpty())
		Expect(plan.CandidateVM).ToNot(BeNil())
		Expect(plan.CandidateVM.SpecDigest).ToNot(BeEmpty())
	})

	It("never stops a running target and marks the plan Unsupported", func() {
		vm := createVirtualMachine(previewNamespace, previewVMName)
		seedSnapshot(vm)
		Expect(controller.VMInformer.GetStore().Add(vm)).To(Succeed())
		Expect(controller.VMIInformer.GetStore().Add(&kubevirtv1.VirtualMachineInstance{
			ObjectMeta: metav1.ObjectMeta{Name: vm.Name, Namespace: vm.Namespace},
		})).To(Succeed())
		r := restore()
		addRestore(r)

		plan, err := planner.PreviewColdRestorePlan(context.Background(), r)
		Expect(err).ToNot(HaveOccurred())
		Expect(plan.Phase).To(Equal(ColdRestorePlanUnsupported))
		Expect(planHasGlobalPrecondition(plan, preconditionTargetPoweredOff, PreconditionUnmet)).To(BeTrue())
		Expect(spy.total()).To(BeZero())
		Expect(spy.totalForResource("virtualmachines")).To(BeZero())
	})

	It("is blocked when the VolumeSnapshot cannot be resolved", func() {
		vm := createVirtualMachine(previewNamespace, previewVMName)
		seedSnapshot(vm)
		// Provider has no matching VolumeSnapshot.
		volumeSnapshotProvider.volumeSnapshots = nil
		r := restore()
		addRestore(r)

		plan, err := planner.PreviewColdRestorePlan(context.Background(), r)
		Expect(err).ToNot(HaveOccurred())
		Expect(plan.Phase).To(Equal(ColdRestorePlanBlocked))
		action, ok := findAction(plan, PlannedActionSkip, "PersistentVolumeClaim", "restore-"+previewUID+"-disk1")
		Expect(ok).To(BeTrue())
		Expect(hasPrecondition(action.Preconditions, preconditionVolumeSnapshotPresent, PreconditionUnmet)).To(BeTrue())
		Expect(spy.total()).To(BeZero())
	})

	It("is blocked when a volume backup carries no VolumeSnapshot name", func() {
		vm := createVirtualMachine(previewNamespace, previewVMName)
		_, content := seedSnapshot(vm)
		content.Spec.VolumeBackups[0].VolumeSnapshotName = nil
		Expect(controller.VMSnapshotContentInformer.GetStore().Update(content)).To(Succeed())
		r := restore()
		addRestore(r)

		plan, err := planner.PreviewColdRestorePlan(context.Background(), r)
		Expect(err).ToNot(HaveOccurred())
		Expect(plan.Phase).To(Equal(ColdRestorePlanBlocked))
		Expect(plan.Actions).To(ContainElement(WithTransform(func(a PlannedAction) string { return a.ID },
			Equal("skip-volume-disk1"))))
	})

	It("is blocked when snapshot and target are different existing VMs", func() {
		vm := createVirtualMachine(previewNamespace, previewVMName)
		seedSnapshot(vm)
		otherVM := createVirtualMachine(previewNamespace, "other-vm")
		otherVM.UID = "other-vm-uid"
		Expect(controller.VMInformer.GetStore().Add(otherVM)).To(Succeed())

		r := restore()
		r.Spec.Target.Name = "other-vm"
		addRestore(r)

		plan, err := planner.PreviewColdRestorePlan(context.Background(), r)
		Expect(err).ToNot(HaveOccurred())
		Expect(plan.Phase).To(Equal(ColdRestorePlanBlocked))
		Expect(planHasGlobalPrecondition(plan, preconditionTargetNotColliding, PreconditionUnmet)).To(BeTrue())
	})

	It("reports Unknown when the StorageClass is missing and Unmet when binding info is absent", func() {
		vm := createVirtualMachine(previewNamespace, previewVMName)
		_, content := seedSnapshot(vm)
		Expect(controller.StorageClassInformer.GetStore().Delete(storageClass())).To(Succeed())
		r := restore()
		addRestore(r)

		plan, err := planner.PreviewColdRestorePlan(context.Background(), r)
		Expect(err).ToNot(HaveOccurred())
		Expect(plan.Phase).To(Equal(ColdRestorePlanBlocked))
		pvcAction, ok := findAction(plan, PlannedActionCreate, "PersistentVolumeClaim", "restore-"+previewUID+"-disk1")
		Expect(ok).To(BeTrue())
		Expect(hasPrecondition(pvcAction.Preconditions, preconditionStorageClassResolvable, PreconditionUnmet)).To(BeTrue())

		// Re-add the StorageClass without a binding mode: unknown capability, not a hard failure.
		sc := storageClass()
		sc.VolumeBindingMode = nil
		Expect(controller.StorageClassInformer.GetStore().Add(sc)).To(Succeed())
		// The first preview consumed the queued VolumeSnapshot, so stock it again.
		stockProviderWithContent(content)
		plan, err = planner.PreviewColdRestorePlan(context.Background(), r)
		Expect(err).ToNot(HaveOccurred())
		Expect(plan.Phase).To(Equal(ColdRestorePlanUnknown))
		pvcAction, ok = findAction(plan, PlannedActionCreate, "PersistentVolumeClaim", "restore-"+previewUID+"-disk1")
		Expect(ok).To(BeTrue())
		Expect(hasPrecondition(pvcAction.Preconditions, preconditionStorageClassBindingKnown, PreconditionUnknown)).To(BeTrue())
	})

	It("adopts an already restored bound PVC and waits on a pending one", func() {
		vm := createVirtualMachine(previewNamespace, previewVMName)
		seedSnapshot(vm)
		restorePVCName := "restore-" + previewUID + "-disk1"
		Expect(controller.PVCInformer.GetStore().Add(&corev1.PersistentVolumeClaim{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: previewNamespace,
				Name:      restorePVCName,
				Annotations: map[string]string{
					lastRestoreAnnotation: getRestoreAnnotationValue(restore()),
				},
			},
			Spec:   corev1.PersistentVolumeClaimSpec{StorageClassName: pointer.P(storageClassName)},
			Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound},
		})).To(Succeed())
		r := restore()
		addRestore(r)

		plan, err := planner.PreviewColdRestorePlan(context.Background(), r)
		Expect(err).ToNot(HaveOccurred())
		_, ok := findAction(plan, PlannedActionAdopt, "PersistentVolumeClaim", restorePVCName)
		Expect(ok).To(BeTrue())
		Expect(spy.total()).To(BeZero())

		// Flip the PVC to pending: the controller would wait for the external provisioner.
		pvc, _, _ := controller.PVCInformer.GetStore().GetByKey(previewNamespace + "/" + restorePVCName)
		pendingPVC := pvc.(*corev1.PersistentVolumeClaim).DeepCopy()
		pendingPVC.Status.Phase = corev1.ClaimPending
		Expect(controller.PVCInformer.GetStore().Update(pendingPVC)).To(Succeed())

		plan, err = planner.PreviewColdRestorePlan(context.Background(), r)
		Expect(err).ToNot(HaveOccurred())
		waitAction, ok := findAction(plan, PlannedActionWait, "PersistentVolumeClaim", restorePVCName)
		Expect(ok).To(BeTrue())
		Expect(waitAction.Note).To(ContainSubstring("cannot promise CSI restore success"))
	})

	It("plans the InPlace delete/recreate sequence with reclaim policy preconditions", func() {
		vm := createVirtualMachine(previewNamespace, previewVMName)
		seedSnapshot(vm)
		inPlace := snapshotv1.VolumeRestorePolicyInPlace
		r := restore()
		r.Spec.VolumeRestorePolicy = &inPlace
		addRestore(r)

		existingPVC := &corev1.PersistentVolumeClaim{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: previewNamespace,
				Name:      "alpine-dv",
				OwnerReferences: []metav1.OwnerReference{{
					APIVersion: cdiv1.SchemeGroupVersion.String(),
					Kind:       "DataVolume",
					Name:       "alpine-dv",
					UID:        "dv-uid",
				}},
			},
			Spec: corev1.PersistentVolumeClaimSpec{StorageClassName: pointer.P(storageClassName)},
		}
		Expect(controller.PVCInformer.GetStore().Add(existingPVC)).To(Succeed())

		plan, err := planner.PreviewColdRestorePlan(context.Background(), r)
		Expect(err).ToNot(HaveOccurred())
		dvPatch, ok := findAction(plan, PlannedActionPatch, "DataVolume", "alpine-dv")
		Expect(ok).To(BeTrue())
		Expect(dvPatch.Summary.PatchOpCount).To(BeNumerically(">", 0))
		deleteAction, ok := findAction(plan, PlannedActionDelete, "PersistentVolumeClaim", "alpine-dv")
		Expect(ok).To(BeTrue())
		Expect(deleteAction.DependsOn).To(ContainElement(dvPatch.ID))
		createAction, ok := findAction(plan, PlannedActionCreate, "PersistentVolumeClaim", "alpine-dv")
		Expect(ok).To(BeTrue())
		Expect(createAction.DependsOn).To(ContainElement(deleteAction.ID))
		Expect(hasPrecondition(deleteAction.Preconditions, preconditionStorageClassReclaimKnown, PreconditionMet)).To(BeTrue())
	})

	It("skips memory dump volumes and flags them as Unsupported", func() {
		vm := createVirtualMachine(previewNamespace, previewVMName)
		vm.Spec.Template.Spec.Volumes = append(vm.Spec.Template.Spec.Volumes, kubevirtv1.Volume{
			Name: "memorydump",
			VolumeSource: kubevirtv1.VolumeSource{
				MemoryDump: &kubevirtv1.MemoryDumpVolumeSource{
					PersistentVolumeClaimVolumeSource: kubevirtv1.PersistentVolumeClaimVolumeSource{
						PersistentVolumeClaimVolumeSource: corev1.PersistentVolumeClaimVolumeSource{ClaimName: "memorydump"},
					},
				},
			},
		})
		_, content := seedSnapshot(vm)
		content.Spec.VolumeBackups = append(content.Spec.VolumeBackups, snapshotv1.VolumeBackup{
			VolumeName: "memorydump",
			PersistentVolumeClaim: snapshotv1.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{Name: "memorydump", Namespace: previewNamespace},
			},
		})
		Expect(controller.VMSnapshotContentInformer.GetStore().Update(content)).To(Succeed())
		r := restore()
		addRestore(r)

		plan, err := planner.PreviewColdRestorePlan(context.Background(), r)
		Expect(err).ToNot(HaveOccurred())
		skipAction, ok := findAction(plan, PlannedActionSkip, "PersistentVolumeClaim", "memorydump")
		Expect(ok).To(BeTrue())
		Expect(hasPrecondition(skipAction.Preconditions, preconditionMemoryStateNotRestored, PreconditionUnmet)).To(BeTrue())
		Expect(plan.Phase).To(Equal(ColdRestorePlanUnsupported))
	})

	It("redacts inline cloud-init data and keeps only secret references", func() {
		vm := createVirtualMachine(previewNamespace, previewVMName)
		secretUserData := "#cloud-config\npassword: super-secret-password\n"
		vm.Spec.Template.Spec.Volumes = append(vm.Spec.Template.Spec.Volumes, kubevirtv1.Volume{
			Name: "cloudinit",
			VolumeSource: kubevirtv1.VolumeSource{
				CloudInitNoCloud: &kubevirtv1.CloudInitNoCloudSource{
					UserData:          secretUserData,
					UserDataSecretRef: &corev1.LocalObjectReference{Name: "userdata-secret"},
				},
			},
		})
		seedSnapshot(vm)
		r := restore()
		addRestore(r)

		plan, err := planner.PreviewColdRestorePlan(context.Background(), r)
		Expect(err).ToNot(HaveOccurred())
		var inlineData *SensitiveReference
		var secretRef *SensitiveReference
		for i := range plan.CandidateVM.Sensitive {
			entry := &plan.CandidateVM.Sensitive[i]
			if entry.Kind == "CloudInitNoCloud/userData" && entry.Name == "cloudinit" {
				inlineData = entry
			}
			if entry.Kind == "Secret" && entry.Name == "userdata-secret" {
				secretRef = entry
			}
		}
		Expect(inlineData).ToNot(BeNil())
		Expect(inlineData.FieldDigest).ToNot(BeEmpty())
		Expect(secretRef).ToNot(BeNil())
		Expect(secretRef.FieldDigest).To(BeEmpty())
		rendered, err := json.Marshal(plan)
		Expect(err).ToNot(HaveOccurred())
		Expect(string(rendered)).ToNot(ContainSubstring("super-secret-password"))
	})

	It("does not modify the informer cache while generating the candidate VM", func() {
		vm := createVirtualMachine(previewNamespace, previewVMName)
		seedSnapshot(vm)
		Expect(controller.VMInformer.GetStore().Add(vm)).To(Succeed())
		original, err := json.Marshal(vm)
		Expect(err).ToNot(HaveOccurred())

		r := restore()
		addRestore(r)
		_, err = planner.PreviewColdRestorePlan(context.Background(), r)
		Expect(err).ToNot(HaveOccurred())

		cached, exists, err := controller.VMInformer.GetStore().GetByKey(previewNamespace + "/" + previewVMName)
		Expect(err).ToNot(HaveOccurred())
		Expect(exists).To(BeTrue())
		cachedBytes, err := json.Marshal(cached)
		Expect(err).ToNot(HaveOccurred())
		Expect(cachedBytes).To(Equal(original))
	})

	Context("backend state (TPM/EFI/NVRAM)", func() {
		addBackendBackup := func(content *snapshotv1.VirtualMachineSnapshotContent, vm *kubevirtv1.VirtualMachine) string {
			backendVolumeName := storageutils.BackendPVCVolumeName(vm.Name)
			backendPVCName := "backend-pvc-" + vm.Name
			content.Spec.VolumeBackups = append(content.Spec.VolumeBackups, snapshotv1.VolumeBackup{
				VolumeName: backendVolumeName,
				PersistentVolumeClaim: snapshotv1.PersistentVolumeClaim{
					ObjectMeta: metav1.ObjectMeta{Name: backendPVCName, Namespace: previewNamespace},
					Spec:       corev1.PersistentVolumeClaimSpec{StorageClassName: pointer.P(storageClassName)},
				},
				VolumeSnapshotName: pointer.P("vmsnapshot-" + string(vmSnapshotUID) + "-volume-backend"),
			})
			Expect(controller.VMSnapshotContentInformer.GetStore().Update(content)).To(Succeed())
			volumeSnapshotProvider.Add(volumeSnapshotFor("vmsnapshot-" + string(vmSnapshotUID) + "-volume-backend"))
			return backendVolumeName
		}

		It("plans backend PVC restore and relabel as first-class backend actions", func() {
			vm := createVirtualMachine(previewNamespace, previewVMName)
			vm.Spec.Template.Spec.Domain.Devices.TPM = &kubevirtv1.TPMDevice{Persistent: pointer.P(true)}
			_, content := seedSnapshot(vm)
			backendVolumeName := addBackendBackup(content, vm)

			originalBackendPVC := &corev1.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: previewNamespace,
					Name:      "backend-pvc-" + vm.Name,
					Labels:    map[string]string{backendstorage.PVCPrefix: vm.Name},
				},
				Spec: corev1.PersistentVolumeClaimSpec{StorageClassName: pointer.P(storageClassName)},
			}
			Expect(controller.PVCInformer.GetStore().Add(originalBackendPVC)).To(Succeed())
			k8sClient.Fake.PrependReactor("list", "persistentvolumeclaims", func(action testing.Action) (bool, runtime.Object, error) {
				return true, &corev1.PersistentVolumeClaimList{Items: []corev1.PersistentVolumeClaim{*originalBackendPVC}}, nil
			})

			r := restore()
			addRestore(r)
			plan, err := planner.PreviewColdRestorePlan(context.Background(), r)
			Expect(err).ToNot(HaveOccurred())

			expectedRestorePVCName := "restore-" + previewUID + "-" + backendVolumeName
			createAction, ok := findAction(plan, PlannedActionCreate, "PersistentVolumeClaim", expectedRestorePVCName)
			Expect(ok).To(BeTrue())
			Expect(createAction.BackendState).To(BeTrue())

			relabelAction, ok := findAction(plan, PlannedActionPatch, "PersistentVolumeClaim", "backend-pvc-"+vm.Name)
			Expect(ok).To(BeTrue())
			Expect(relabelAction.BackendState).To(BeTrue())
			Expect(relabelAction.Summary.PatchDigest).ToNot(BeEmpty())

			// The backend label patch on the restore PVC is part of the legacy backend flow.
			labelPatch, ok := findAction(plan, PlannedActionPatch, "PersistentVolumeClaim", expectedRestorePVCName)
			Expect(ok).To(BeTrue())
			Expect(labelPatch.BackendState).To(BeTrue())
		})

		It("repoints declarative virtualMachineState source at the restored backend PVC", func() {
			vm := createVirtualMachine(previewNamespace, previewVMName)
			vm.Spec.Template.Spec.VirtualMachineState = &kubevirtv1.VirtualMachineStateSpec{
				VolumeClaimTemplate: &corev1.PersistentVolumeClaimTemplate{},
			}
			_, content := seedSnapshot(vm)
			backendVolumeName := addBackendBackup(content, vm)

			r := restore()
			addRestore(r)
			plan, err := planner.PreviewColdRestorePlan(context.Background(), r)
			Expect(err).ToNot(HaveOccurred())
			Expect(planHasGlobalPrecondition(plan, preconditionBackendStateCaptured, PreconditionMet)).To(BeTrue())
			Expect(plan.CandidateVM.Sensitive).To(BeNil())

			expectedRestorePVCName := "restore-" + previewUID + "-" + backendVolumeName
			createAction, ok := findAction(plan, PlannedActionCreate, "PersistentVolumeClaim", expectedRestorePVCName)
			Expect(ok).To(BeTrue())
			Expect(createAction.BackendState).To(BeTrue())
			// Declarative VMs do not get the legacy backend label patch.
			_, ok = findAction(plan, PlannedActionPatch, "PersistentVolumeClaim", expectedRestorePVCName)
			Expect(ok).To(BeFalse())
		})

		It("adopts the existing backend PVC when the state was not captured for the same VM", func() {
			vm := createVirtualMachine(previewNamespace, previewVMName)
			vm.Spec.Template.Spec.Domain.Devices.TPM = &kubevirtv1.TPMDevice{Persistent: pointer.P(true)}
			seedSnapshot(vm)
			Expect(controller.VMInformer.GetStore().Add(vm)).To(Succeed())

			r := restore()
			addRestore(r)
			plan, err := planner.PreviewColdRestorePlan(context.Background(), r)
			Expect(err).ToNot(HaveOccurred())
			adoptAction, ok := findAction(plan, PlannedActionAdopt, "PersistentVolumeClaim", "")
			Expect(ok).To(BeTrue())
			Expect(adoptAction.BackendState).To(BeTrue())
			Expect(hasPrecondition(adoptAction.Preconditions, preconditionBackendStateCaptured, PreconditionUnmet)).To(BeTrue())
		})

		It("requires a volumeClaimTemplate when moving uncaptured backend state to another VM", func() {
			vm := createVirtualMachine(previewNamespace, previewVMName)
			vm.Spec.Template.Spec.Domain.Devices.TPM = &kubevirtv1.TPMDevice{Persistent: pointer.P(true)}
			seedSnapshot(vm)

			r := restore()
			r.Spec.Target.Name = "new-vm-name"
			addRestore(r)
			plan, err := planner.PreviewColdRestorePlan(context.Background(), r)
			Expect(err).ToNot(HaveOccurred())
			Expect(plan.Phase).To(Equal(ColdRestorePlanBlocked))
			skipAction, ok := findAction(plan, PlannedActionSkip, "PersistentVolumeClaim", "")
			Expect(ok).To(BeTrue())
			Expect(skipAction.BackendState).To(BeTrue())
			Expect(hasPrecondition(skipAction.Preconditions, preconditionBackendStateCaptured, PreconditionUnmet)).To(BeTrue())

			// With a volumeClaimTemplate the new VM starts from fresh empty state cleanly. The
			// content keeps its own deep copy of the snapshot VM, so update it in the store as well.
			contentObj, _, getErr := controller.VMSnapshotContentInformer.GetStore().GetByKey(
				previewNamespace + "/" + "vmsnapshot-content-" + string(vmSnapshotUID))
			Expect(getErr).ToNot(HaveOccurred())
			contentCpy := contentObj.(*snapshotv1.VirtualMachineSnapshotContent).DeepCopy()
			contentCpy.Spec.Source.VirtualMachine.Spec.Template.Spec.VirtualMachineState = &kubevirtv1.VirtualMachineStateSpec{
				VolumeClaimTemplate: &corev1.PersistentVolumeClaimTemplate{},
			}
			Expect(controller.VMSnapshotContentInformer.GetStore().Update(contentCpy)).To(Succeed())
			stockProviderWithContent(contentCpy)
			plan, err = planner.PreviewColdRestorePlan(context.Background(), r)
			Expect(err).ToNot(HaveOccurred())
			skipAction, ok = findAction(plan, PlannedActionSkip, "PersistentVolumeClaim", "")
			Expect(ok).To(BeTrue())
			Expect(hasPrecondition(skipAction.Preconditions, preconditionBackendStateCaptured, PreconditionMet)).To(BeTrue())
		})
	})

	Context("instancetype and preference ControllerRevisions", func() {
		seedInstancetype := func(vm *kubevirtv1.VirtualMachine, vmSnapshot *snapshotv1.VirtualMachineSnapshot, content *snapshotv1.VirtualMachineSnapshotContent) (
			*appsv1.ControllerRevision, *appsv1.ControllerRevision,
		) {
			instancetypeObj := createInstancetype()
			originalCR, err := revision.CreateControllerRevision(vm, instancetypeObj)
			Expect(err).ToNot(HaveOccurred())
			snapshotCR := createInstancetypeVirtualMachineSnapshotCR(vm, vmSnapshot, instancetypeObj)
			Expect(controller.CRInformer.GetStore().Add(originalCR)).To(Succeed())
			Expect(controller.CRInformer.GetStore().Add(snapshotCR)).To(Succeed())

			vm.Spec.Instancetype = &kubevirtv1.InstancetypeMatcher{
				Name:         instancetypeObj.Name,
				Kind:         instancetypeapi.SingularResourceName,
				RevisionName: originalCR.Name,
			}
			content.Spec.Source.VirtualMachine.Spec.Instancetype = &kubevirtv1.InstancetypeMatcher{
				Name:         instancetypeObj.Name,
				Kind:         instancetypeapi.SingularResourceName,
				RevisionName: snapshotCR.Name,
			}
			Expect(controller.VMSnapshotContentInformer.GetStore().Update(content)).To(Succeed())
			return originalCR, snapshotCR
		}

		It("creates the renamed revision and claims ownership for a new target VM", func() {
			vm := createVirtualMachine(previewNamespace, previewVMName)
			s, content := seedSnapshot(vm)
			_, snapshotCR := seedInstancetype(vm, s, content)

			r := restore()
			r.Spec.Target.Name = "new-vm-name"
			addRestore(r)
			plan, err := planner.PreviewColdRestorePlan(context.Background(), r)
			Expect(err).ToNot(HaveOccurred())

			expectedCRName := strings.Replace(snapshotCR.Name, previewSnapName, "new-vm-name", 1)
			createAction, ok := findAction(plan, PlannedActionCreate, "ControllerRevision", expectedCRName)
			Expect(ok).To(BeTrue())
			claimAction, ok := findAction(plan, PlannedActionUpdate, "ControllerRevision", expectedCRName)
			Expect(ok).To(BeTrue())
			Expect(claimAction.DependsOn).To(ContainElement(createAction.ID))
			Expect(claimAction.DependsOn).To(ContainElement("create-vm-new-vm-name"))
		})

		It("adopts an existing equal revision instead of recreating it", func() {
			vm := createVirtualMachine(previewNamespace, previewVMName)
			s, content := seedSnapshot(vm)
			originalCR, snapshotCR := seedInstancetype(vm, s, content)
			Expect(controller.VMInformer.GetStore().Add(vm)).To(Succeed())
			// The restored name equals the original CR name for an in-place target.
			Expect(originalCR.Name).To(Equal(strings.Replace(snapshotCR.Name, previewSnapName, previewVMName, 1)))

			r := restore()
			addRestore(r)
			plan, err := planner.PreviewColdRestorePlan(context.Background(), r)
			Expect(err).ToNot(HaveOccurred())
			_, ok := findAction(plan, PlannedActionAdopt, "ControllerRevision", originalCR.Name)
			Expect(ok).To(BeTrue())
		})

		It("refuses to replace a divergent revision controlled by another VM", func() {
			vm := createVirtualMachine(previewNamespace, previewVMName)
			s, content := seedSnapshot(vm)
			originalCR, snapshotCR := seedInstancetype(vm, s, content)

			instancetypeObj := createInstancetype()
			instancetypeObj.Spec.CPU.Guest = uint32(5)
			divergent, err := revision.CreateControllerRevision(vm, instancetypeObj)
			Expect(err).ToNot(HaveOccurred())
			divergent.Name = originalCR.Name
			divergent.OwnerReferences = []metav1.OwnerReference{{
				APIVersion: kubevirtv1.GroupVersion.String(),
				Kind:       "VirtualMachine",
				Name:       "someone-else",
				UID:        "foreign-uid",
				Controller: pointer.P(true),
			}}
			Expect(controller.CRInformer.GetStore().Update(divergent)).To(Succeed())
			Expect(controller.VMInformer.GetStore().Add(vm)).To(Succeed())

			r := restore()
			addRestore(r)
			plan, err := planner.PreviewColdRestorePlan(context.Background(), r)
			Expect(err).ToNot(HaveOccurred())
			expectedCRName := strings.Replace(snapshotCR.Name, previewSnapName, previewVMName, 1)
			deleteAction, ok := findAction(plan, PlannedActionDelete, "ControllerRevision", expectedCRName)
			Expect(ok).To(BeTrue())
			Expect(hasPrecondition(deleteAction.Preconditions, preconditionControllerRevisionNotShared, PreconditionUnmet)).To(BeTrue())
			Expect(plan.Phase).To(Equal(ColdRestorePlanBlocked))
		})
	})

	Context("DAG versus real restore controller actions", func() {
		// installMirrorReactors keeps the informer caches aligned with fake-client writes and
		// simulates the external components (CSI binding, CDI population) the controller waits on.
		installMirrorReactors := func() {
			k8sClient.Fake.PrependReactor("*", "persistentvolumeclaims", func(action testing.Action) (bool, runtime.Object, error) {
				switch a := action.(type) {
				case testing.CreateAction:
					pvc := a.GetObject().(*corev1.PersistentVolumeClaim).DeepCopy()
					pvc.Status.Phase = corev1.ClaimBound
					Expect(controller.PVCInformer.GetStore().Add(pvc)).To(Succeed())
				case testing.UpdateAction:
					pvc := a.GetObject().(*corev1.PersistentVolumeClaim).DeepCopy()
					if pvc.Status.Phase == "" {
						pvc.Status.Phase = corev1.ClaimBound
					}
					Expect(controller.PVCInformer.GetStore().Update(pvc)).To(Succeed())
				case testing.DeleteAction:
					Expect(controller.PVCInformer.GetStore().Delete(&corev1.PersistentVolumeClaim{
						ObjectMeta: metav1.ObjectMeta{Namespace: a.GetNamespace(), Name: a.GetName()},
					})).To(Succeed())
				}
				return false, nil, nil
			})
			cdiClient.Fake.PrependReactor("*", "datavolumes", func(action testing.Action) (bool, runtime.Object, error) {
				switch a := action.(type) {
				case testing.CreateAction:
					dv := a.GetObject().(*cdiv1.DataVolume).DeepCopy()
					dv.Status.Phase = cdiv1.Succeeded
					Expect(controller.DataVolumeInformer.GetStore().Add(dv)).To(Succeed())
				case testing.UpdateAction:
					Expect(controller.DataVolumeInformer.GetStore().Update(a.GetObject())).To(Succeed())
				case testing.DeleteAction:
					Expect(controller.DataVolumeInformer.GetStore().Delete(&cdiv1.DataVolume{
						ObjectMeta: metav1.ObjectMeta{Namespace: a.GetNamespace(), Name: a.GetName()},
					})).To(Succeed())
				}
				return false, nil, nil
			})
			k8sClient.Fake.PrependReactor("*", "controllerrevisions", func(action testing.Action) (bool, runtime.Object, error) {
				switch a := action.(type) {
				case testing.CreateAction:
					Expect(controller.CRInformer.GetStore().Add(a.GetObject())).To(Succeed())
				case testing.UpdateAction:
					Expect(controller.CRInformer.GetStore().Update(a.GetObject())).To(Succeed())
				case testing.DeleteAction:
					Expect(controller.CRInformer.GetStore().Delete(&appsv1.ControllerRevision{
						ObjectMeta: metav1.ObjectMeta{Namespace: a.GetNamespace(), Name: a.GetName()},
					})).To(Succeed())
				}
				return false, nil, nil
			})
			kubevirtClient.Fake.PrependReactor("*", "virtualmachines", func(action testing.Action) (bool, runtime.Object, error) {
				switch a := action.(type) {
				case testing.CreateAction:
					vm := a.GetObject().(*kubevirtv1.VirtualMachine).DeepCopy()
					if vm.UID == "" {
						vm.UID = "created-vm-uid"
					}
					Expect(controller.VMInformer.GetStore().Add(vm)).To(Succeed())
					return true, vm, nil
				case testing.UpdateAction:
					vm := a.GetObject().(*kubevirtv1.VirtualMachine).DeepCopy()
					Expect(controller.VMInformer.GetStore().Update(vm)).To(Succeed())
					return true, vm, nil
				}
				return false, nil, nil
			})
			kubevirtClient.Fake.PrependReactor("*", "virtualmachinerestores", func(action testing.Action) (bool, runtime.Object, error) {
				switch a := action.(type) {
				case testing.CreateAction:
					restoreObj := a.GetObject().(*snapshotv1.VirtualMachineRestore).DeepCopy()
					Expect(controller.VMRestoreInformer.GetStore().Add(restoreObj)).To(Succeed())
					return true, restoreObj, nil
				case testing.UpdateAction:
					restoreObj := a.GetObject().(*snapshotv1.VirtualMachineRestore).DeepCopy()
					Expect(controller.VMRestoreInformer.GetStore().Update(restoreObj)).To(Succeed())
					return true, restoreObj, nil
				case testing.PatchAction:
					// No finalizer removal happens on the happy completion path; mirror generically.
					obj, exists, err := controller.VMRestoreInformer.GetStore().GetByKey(a.GetNamespace() + "/" + a.GetName())
					Expect(err).ToNot(HaveOccurred())
					if exists {
						patched := obj.(*snapshotv1.VirtualMachineRestore).DeepCopy()
						if err := applyPatch(a.GetPatch(), patched, patched); err != nil {
							return true, nil, err
						}
						Expect(controller.VMRestoreInformer.GetStore().Update(patched)).To(Succeed())
						return true, patched, nil
					}
				}
				return false, nil, nil
			})
		}

		recorded := func() []recordedAction {
			var actions []recordedAction
			for _, clientActions := range [][]testing.Action{k8sClient.Fake.Actions(), kubevirtClient.Fake.Actions(), cdiClient.Fake.Actions()} {
				for _, action := range clientActions {
					verb := action.GetVerb()
					if verb != "create" && verb != "update" && verb != "delete" && verb != "patch" {
						continue
					}
					resource := action.GetResource().Resource
					if resource != "persistentvolumeclaims" && resource != "datavolumes" &&
						resource != "controllerrevisions" && resource != "virtualmachines" {
						continue
					}
					name := ""
					switch a := action.(type) {
					case testing.CreateAction:
						name = a.GetObject().(metav1.Object).GetName()
					case testing.UpdateAction:
						name = a.GetObject().(metav1.Object).GetName()
					case testing.PatchAction:
						name = a.GetName()
					case testing.DeleteAction:
						name = a.GetName()
					}
					subresource := ""
					if typed, ok := action.(testing.UpdateAction); ok {
						subresource = typed.GetSubresource()
					}
					actions = append(actions, recordedAction{verb: verb, resource: resource, name: name, subresource: subresource})
				}
			}
			return actions
		}

		kindToResource := map[string]string{
			"PersistentVolumeClaim": "persistentvolumeclaims",
			"DataVolume":            "datavolumes",
			"ControllerRevision":    "controllerrevisions",
			"VirtualMachine":        "virtualmachines",
		}

		planTuples := func(plan *ColdRestorePlan) []string {
			var tuples []string
			for _, action := range plan.Actions {
				if action.Verb != PlannedActionCreate && action.Verb != PlannedActionUpdate &&
					action.Verb != PlannedActionDelete && action.Verb != PlannedActionPatch {
					continue
				}
				tuples = append(tuples, recordedAction{
					verb:        string(action.Verb),
					resource:    kindToResource[action.Resource.Kind],
					name:        action.Resource.Name,
					subresource: action.Resource.Subresource,
				}.key())
			}
			sort.Strings(tuples)
			return tuples
		}

		driveRestore := func(r *snapshotv1.VirtualMachineRestore) {
			key := previewNamespace + "/" + previewRestore
			for i := 0; i < 25; i++ {
				controller.vmRestoreQueue.Add(key)
				controller.processVMRestoreWorkItem()
				obj, exists, err := controller.VMRestoreInformer.GetStore().GetByKey(key)
				Expect(err).ToNot(HaveOccurred())
				if !exists {
					Fail("restore disappeared from the informer")
				}
				if vmRestoreCompleted(obj.(*snapshotv1.VirtualMachineRestore)) {
					return
				}
			}
			Fail("restore did not complete within the iteration budget")
		}

		It("matches the controller's actions for a new DV-backed target VM", func() {
			vm := createVirtualMachine(previewNamespace, previewVMName)
			seedSnapshot(vm)
			r := restore()
			addRestore(r)

			plan, err := planner.PreviewColdRestorePlan(context.Background(), r)
			Expect(err).ToNot(HaveOccurred())
			Expect(plan.Phase).To(Equal(ColdRestorePlanReady))
			Expect(spy.total()).To(BeZero())

			installMirrorReactors()
			driveRestore(r)

			var actual []string
			for _, action := range recorded() {
				actual = append(actual, action.key())
			}
			sort.Strings(actual)
			Expect(actual).To(Equal(planTuples(plan)))
		})

		It("matches the controller's actions for an existing target VM", func() {
			vm := createVirtualMachine(previewNamespace, previewVMName)
			seedSnapshot(vm)
			Expect(controller.VMInformer.GetStore().Add(vm)).To(Succeed())
			r := restore()
			addRestore(r)

			plan, err := planner.PreviewColdRestorePlan(context.Background(), r)
			Expect(err).ToNot(HaveOccurred())
			Expect(plan.Phase).To(Equal(ColdRestorePlanReady))

			installMirrorReactors()
			driveRestore(r)

			var actual []string
			for _, action := range recorded() {
				actual = append(actual, action.key())
			}
			sort.Strings(actual)
			Expect(actual).To(Equal(planTuples(plan)))
		})

		It("keeps the DAG acyclic with every dependency pointing to an earlier action", func() {
			vm := createVirtualMachine(previewNamespace, previewVMName)
			seedSnapshot(vm)
			r := restore()
			addRestore(r)

			plan, err := planner.PreviewColdRestorePlan(context.Background(), r)
			Expect(err).ToNot(HaveOccurred())
			index := map[string]int{}
			for i, action := range plan.Actions {
				index[action.ID] = i
			}
			for i, action := range plan.Actions {
				for _, dependency := range action.DependsOn {
					depIndex, ok := index[dependency]
					Expect(ok).To(BeTrue(), fmt.Sprintf("action %s depends on unknown %s", action.ID, dependency))
					Expect(depIndex).To(BeNumerically("<", i))
				}
			}
		})
	})

	Context("Apply", func() {
		It("re-validates preconditions and submits the restore through the regular API", func() {
			vm := createVirtualMachine(previewNamespace, previewVMName)
			s, content := seedSnapshot(vm)
			r := restore()
			addRestore(r)

			plan, err := planner.PreviewColdRestorePlan(context.Background(), r)
			Expect(err).ToNot(HaveOccurred())
			// Apply re-runs the preview, which consumes the mocked VolumeSnapshots again.
			stockProviderWithContent(content)
			Expect(s.Name).To(Equal(previewSnapName))

			submitted, err := planner.ApplyColdRestorePlan(context.Background(), plan)
			Expect(err).ToNot(HaveOccurred())
			Expect(submitted.Name).To(Equal(previewRestore))
			Expect(spy.totalForResource("virtualmachinerestores")).To(Equal(1))
			// No PVC/DV/VM/CR writes happen through Apply: the controller owns those.
			Expect(spy.totalForResource("persistentvolumeclaims")).To(BeZero())
			Expect(spy.totalForResource("datavolumes")).To(BeZero())
			Expect(spy.totalForResource("virtualmachines")).To(BeZero())
			Expect(spy.totalForResource("controllerrevisions")).To(BeZero())
		})

		It("refuses to apply when the target changed after the preview", func() {
			vm := createVirtualMachine(previewNamespace, previewVMName)
			_, content := seedSnapshot(vm)
			Expect(controller.VMInformer.GetStore().Add(vm)).To(Succeed())
			r := restore()
			addRestore(r)

			plan, err := planner.PreviewColdRestorePlan(context.Background(), r)
			Expect(err).ToNot(HaveOccurred())
			stockProviderWithContent(content)

			vm.ResourceVersion = "4242"
			Expect(controller.VMInformer.GetStore().Update(vm)).To(Succeed())
			_, err = planner.ApplyColdRestorePlan(context.Background(), plan)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("plan inputs changed"))
		})

		It("refuses to adopt an externally created restore PVC", func() {
			vm := createVirtualMachine(previewNamespace, previewVMName)
			_, content := seedSnapshot(vm)
			r := restore()
			addRestore(r)

			plan, err := planner.PreviewColdRestorePlan(context.Background(), r)
			Expect(err).ToNot(HaveOccurred())
			stockProviderWithContent(content)

			Expect(controller.PVCInformer.GetStore().Add(&corev1.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: previewNamespace,
					Name:      "restore-" + previewUID + "-disk1",
				},
			})).To(Succeed())
			_, err = planner.ApplyColdRestorePlan(context.Background(), plan)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("already exists"))
		})

		It("refuses to apply an Unsupported plan", func() {
			vm := createVirtualMachine(previewNamespace, previewVMName)
			_, content := seedSnapshot(vm)
			Expect(controller.VMInformer.GetStore().Add(vm)).To(Succeed())
			Expect(controller.VMIInformer.GetStore().Add(&kubevirtv1.VirtualMachineInstance{
				ObjectMeta: metav1.ObjectMeta{Name: vm.Name, Namespace: vm.Namespace},
			})).To(Succeed())
			r := restore()
			addRestore(r)

			plan, err := planner.PreviewColdRestorePlan(context.Background(), r)
			Expect(err).ToNot(HaveOccurred())
			stockProviderWithContent(content)
			Expect(err).ToNot(HaveOccurred())
			Expect(plan.Phase).To(Equal(ColdRestorePlanUnsupported))
			_, err = planner.ApplyColdRestorePlan(context.Background(), plan)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("Unsupported"))
		})
	})

	It("truncates the plan when the action budget is exhausted", func() {
		vm := createVirtualMachine(previewNamespace, previewVMName)
		seedSnapshot(vm)
		r := restore()
		addRestore(r)

		planner.limits.MaxActions = 2
		plan, err := planner.PreviewColdRestorePlan(context.Background(), r)
		Expect(err).ToNot(HaveOccurred())
		Expect(plan.Truncated).To(BeTrue())
		Expect(len(plan.Actions)).To(BeNumerically("<=", 2))
	})

	It("keeps patch payloads bounded by the patch byte budget", func() {
		vm := createVirtualMachine(previewNamespace, previewVMName)
		seedSnapshot(vm)
		inPlace := snapshotv1.VolumeRestorePolicyInPlace
		r := restore()
		r.Spec.VolumeRestorePolicy = &inPlace
		addRestore(r)
		Expect(controller.PVCInformer.GetStore().Add(&corev1.PersistentVolumeClaim{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:       previewNamespace,
				Name:            "alpine-dv",
				OwnerReferences: []metav1.OwnerReference{{Kind: "DataVolume", Name: "alpine-dv", UID: "dv-uid"}},
			},
			Spec: corev1.PersistentVolumeClaimSpec{StorageClassName: pointer.P(storageClassName)},
		})).To(Succeed())

		planner.limits.MaxPatchBytes = 1
		plan, err := planner.PreviewColdRestorePlan(context.Background(), r)
		Expect(err).ToNot(HaveOccurred())
		for _, action := range plan.Actions {
			if action.Summary != nil {
				Expect(len(action.Summary.PatchBytes)).To(BeNumerically("<=", 1))
				if action.Verb == PlannedActionPatch {
					Expect(action.Summary.PatchDigest).ToNot(BeEmpty())
				}
			}
		}
	})
})
