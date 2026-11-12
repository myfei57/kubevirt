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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"

	kubevirtv1 "kubevirt.io/api/core/v1"
	snapshotv1 "kubevirt.io/api/snapshot/v1beta1"
	"kubevirt.io/client-go/log"
	cdiv1 "kubevirt.io/containerized-data-importer-api/pkg/apis/core/v1beta1"

	"kubevirt.io/kubevirt/pkg/apimachinery/patch"
	"kubevirt.io/kubevirt/pkg/instancetype/revision"
	"kubevirt.io/kubevirt/pkg/pointer"
	backendstorage "kubevirt.io/kubevirt/pkg/storage/backend-storage"
	typesutil "kubevirt.io/kubevirt/pkg/storage/types"
	storageutils "kubevirt.io/kubevirt/pkg/storage/utils"
)

const (
	// maxPlannedActions bounds how many resource actions a single preview plan may hold.
	maxPlannedActions = 256
	// maxPlannedPatchBytes bounds the rendered size of any single planned patch. Patches
	// larger than this are only represented by their operation count and digest.
	maxPlannedPatchBytes = 64 * 1024
	// maxPlanOutputBytes bounds the serialized size of the whole plan. When the budget is
	// exhausted, object summaries are reduced to digests before actions get truncated.
	maxPlanOutputBytes = 2 * 1024 * 1024

	// maxSensitiveDigestLength keeps redacted secret/cloud-init references small.
	maxSensitiveDigestLength = 16
)

// ColdRestorePlanPhase is the overall verdict of a cold restore preview.
type ColdRestorePlanPhase string

const (
	// ColdRestorePlanReady means every observable precondition is met and the DAG can be
	// handed to the restore controller as-is. CSI restore success is still not guaranteed.
	ColdRestorePlanReady ColdRestorePlanPhase = "Ready"
	// ColdRestorePlanBlocked means at least one precondition is provably unmet with the
	// information currently observed in the cluster.
	ColdRestorePlanBlocked ColdRestorePlanPhase = "Blocked"
	// ColdRestorePlanUnknown means the cluster does not expose enough information to decide
	// one or more preconditions, e.g. a missing StorageClass or an unreadable VolumeSnapshot.
	ColdRestorePlanUnknown ColdRestorePlanPhase = "Unknown"
	// ColdRestorePlanUnsupported means the request cannot be served as a cold restore at all,
	// for example because the target is still running or it depends on state cold restore
	// cannot recreate (guest memory / volatile device state).
	ColdRestorePlanUnsupported ColdRestorePlanPhase = "Unsupported"
)

// PreconditionStatus mirrors the tri-state nature of a preview evaluation.
type PreconditionStatus string

const (
	PreconditionMet     PreconditionStatus = "Met"
	PreconditionUnmet   PreconditionStatus = "Unmet"
	PreconditionUnknown PreconditionStatus = "Unknown"
)

// Stable precondition identifiers. They are part of the plan contract and must not be renamed.
const (
	preconditionTargetPoweredOff            = "TargetPoweredOff"
	preconditionSnapshotReady               = "VirtualMachineSnapshotReady"
	preconditionContentReady                = "VirtualMachineSnapshotContentReady"
	preconditionTargetNotColliding          = "RestoreTargetNotColliding"
	preconditionVolumeSnapshotPresent       = "VolumeSnapshotPresent"
	preconditionStorageClassResolvable      = "StorageClassResolvable"
	preconditionStorageClassBindingKnown    = "StorageClassBindingModeKnown"
	preconditionStorageClassReclaimKnown    = "StorageClassReclaimPolicyKnown"
	preconditionRestorePVCNameAvailable     = "RestorePVCNameAvailable"
	preconditionRestorePVCBound             = "RestorePVCBound"
	preconditionDataVolumeReady             = "DataVolumeReady"
	preconditionControllerRevisionPresent   = "ControllerRevisionPresent"
	preconditionControllerRevisionNotShared = "ControllerRevisionNotOwnedByAnotherVM"
	preconditionBackendStatePVCResolvable   = "BackendStatePVCResolvable"
	preconditionBackendStateCaptured        = "BackendStateCaptured"
	preconditionTargetPatchesApplicable     = "TargetPatchesApplicable"
	preconditionMemoryStateNotRestored      = "MemoryDumpStateNotRestored"
)

// PlannedActionVerb describes what the restore controller would do to a resource.
type PlannedActionVerb string

const (
	PlannedActionCreate PlannedActionVerb = "create"
	PlannedActionUpdate PlannedActionVerb = "update"
	PlannedActionDelete PlannedActionVerb = "delete"
	PlannedActionPatch  PlannedActionVerb = "patch"
	// PlannedActionAdopt means no write is needed: the controller would reuse the existing
	// object because it already matches the restored state.
	PlannedActionAdopt PlannedActionVerb = "adopt"
	// PlannedActionWait means no write is needed: the controller would requeue and wait for
	// an external component (CSI, CDI) to finish changing the object.
	PlannedActionWait PlannedActionVerb = "wait"
	// PlannedActionSkip means the controller would deliberately not touch the resource
	// (e.g. a memory dump volume that cold restore never recreates).
	PlannedActionSkip PlannedActionVerb = "skip"
)

// PlannedResourceRef identifies the object an action operates on.
type PlannedResourceRef struct {
	APIVersion  string `json:"apiVersion"`
	Kind        string `json:"kind"`
	Namespace   string `json:"namespace"`
	Name        string `json:"name"`
	Subresource string `json:"subresource,omitempty"`
}

// SensitiveReference records that a VM field carries secret or inline cloud-init data without
// ever embedding the data itself. Only the reference name and a short digest are exposed.
type SensitiveReference struct {
	// Kind is either "Secret" for referenced secrets or the inline source kind, e.g.
	// "CloudInitNoCloud/userData".
	Kind string `json:"kind"`
	// Name is the secret name or the VM volume name carrying inline data.
	Name string `json:"name,omitempty"`
	// FieldDigest is the sha256 digest of the inline payload. It stays empty for secret refs,
	// whose content is never read by the planner.
	FieldDigest string `json:"fieldDigest,omitempty"`
}

// PlannedObjectSummary is the size-bounded, redacted representation of an intended object.
type PlannedObjectSummary struct {
	ByteSize        int                     `json:"byteSize"`
	SpecDigest      string                  `json:"specDigest"`
	Labels          map[string]string       `json:"labels,omitempty"`
	AnnotationKeys  []string                `json:"annotationKeys,omitempty"`
	OwnerReferences []metav1.OwnerReference `json:"ownerReferences,omitempty"`
	Sensitive       []SensitiveReference    `json:"sensitive,omitempty"`
	// PatchOpCount/PatchDigest/PatchBytes describe patch verbs. Raw patch bytes are only kept
	// while they fit the patch budget; callers always get the digest.
	PatchOpCount int    `json:"patchOpCount,omitempty"`
	PatchDigest  string `json:"patchDigest,omitempty"`
	PatchBytes   []byte `json:"patchBytes,omitempty"`
}

// PlannedAction is a single node of the restore action DAG.
type PlannedAction struct {
	ID            string                    `json:"id"`
	Verb          PlannedActionVerb         `json:"verb"`
	Resource      PlannedResourceRef        `json:"resource"`
	DependsOn     []string                  `json:"dependsOn,omitempty"`
	Preconditions []RestorePlanPrecondition `json:"preconditions,omitempty"`
	Summary       *PlannedObjectSummary     `json:"summary,omitempty"`
	// BackendState marks TPM/EFI/NVRAM VirtualMachineState actions so they can never be
	// mistaken for disposable scratch storage.
	BackendState bool   `json:"backendState,omitempty"`
	Note         string `json:"note,omitempty"`
}

// RestorePlanPrecondition is a single evaluated precondition attached to the plan or an action.
type RestorePlanPrecondition struct {
	Type    string             `json:"type"`
	Status  PreconditionStatus `json:"status"`
	Message string             `json:"message"`
}

// ColdRestorePlanInputs pins every piece of input the plan was derived from. Apply uses these
// fingerprints to refuse stale plans.
type ColdRestorePlanInputs struct {
	RestoreNamespace       string    `json:"restoreNamespace"`
	RestoreName            string    `json:"restoreName"`
	RestoreUID             types.UID `json:"restoreUID"`
	RestoreResourceVersion string    `json:"restoreResourceVersion,omitempty"`

	SnapshotName string    `json:"snapshotName"`
	SnapshotUID  types.UID `json:"snapshotUID,omitempty"`

	ContentName   string    `json:"snapshotContentName,omitempty"`
	ContentUID    types.UID `json:"snapshotContentUID,omitempty"`
	ContentDigest string    `json:"snapshotContentDigest"`

	TargetName            string    `json:"targetName"`
	TargetUID             types.UID `json:"targetUID,omitempty"`
	TargetResourceVersion string    `json:"targetResourceVersion,omitempty"`
	TargetSpecDigest      string    `json:"targetSpecDigest,omitempty"`
}

// RestorePlanLimits reports the budgets enforced while building the plan.
type RestorePlanLimits struct {
	MaxActions     int `json:"maxActions"`
	MaxPatchBytes  int `json:"maxPatchBytes"`
	MaxOutputBytes int `json:"maxOutputBytes"`
}

// ColdRestorePlan is the read-only result of PreviewColdRestorePlan. It never contains a
// create/update/delete call: every mutation the restore controller would perform is described
// as a DAG node with the preconditions that still have to hold when execution starts.
type ColdRestorePlan struct {
	GeneratedAt *metav1.Time `json:"generatedAt"`

	Inputs ColdRestorePlanInputs `json:"inputs"`

	Phase   ColdRestorePlanPhase `json:"phase"`
	Reasons []string             `json:"reasons,omitempty"`

	Preconditions []RestorePlanPrecondition `json:"preconditions,omitempty"`

	// Actions are topologically ordered; DependsOn only references earlier IDs.
	Actions []PlannedAction `json:"actions"`

	// CandidateVM is the redacted summary of the object produced by the same
	// generateRestoredVMSpec/patchVM logic the restore controller uses.
	CandidateVM *PlannedObjectSummary `json:"candidateVM,omitempty"`

	Limits    RestorePlanLimits `json:"limits"`
	Truncated bool              `json:"truncated,omitempty"`
}

// ColdRestorePlanner builds cold restore plans from controller informers without ever mutating
// the cluster. All reads reuse the VMRestoreController caches and the VolumeSnapshotProvider.
type ColdRestorePlanner struct {
	ctrl *VMRestoreController

	now func() metav1.Time

	limits RestorePlanLimits
}

// NewColdRestorePlanner wires a planner to the same read-only caches as the restore controller.
func NewColdRestorePlanner(ctrl *VMRestoreController) *ColdRestorePlanner {
	return &ColdRestorePlanner{
		ctrl: ctrl,
		now: func() metav1.Time {
			return metav1.Now()
		},
		limits: RestorePlanLimits{
			MaxActions:     maxPlannedActions,
			MaxPatchBytes:  maxPlannedPatchBytes,
			MaxOutputBytes: maxPlanOutputBytes,
		},
	}
}

// planBuilder accumulates DAG nodes while enforcing the action/patch/output budgets.
type planBuilder struct {
	planner *ColdRestorePlanner
	plan    *ColdRestorePlan

	actionCount int
	truncated   bool
}

// PreviewColdRestorePlan computes the resource action DAG for a cold restore. It is strictly
// read-only: no object is created, updated, patched, deleted and the target VM is never stopped.
func (p *ColdRestorePlanner) PreviewColdRestorePlan(ctx context.Context, vmRestoreIn *snapshotv1.VirtualMachineRestore) (*ColdRestorePlan, error) {
	if vmRestoreIn == nil {
		return nil, fmt.Errorf("cannot preview a nil VirtualMachineRestore")
	}
	// Never touch the caller's object or the informer cache.
	vmRestore := vmRestoreIn.DeepCopy()

	logger := log.Log.Object(vmRestore)

	plan := &ColdRestorePlan{
		GeneratedAt: pointer.P(p.now()),
		Inputs: ColdRestorePlanInputs{
			RestoreNamespace:       vmRestore.Namespace,
			RestoreName:            vmRestore.Name,
			RestoreUID:             vmRestore.UID,
			RestoreResourceVersion: vmRestore.ResourceVersion,
			SnapshotName:           vmRestore.Spec.VirtualMachineSnapshotName,
			TargetName:             vmRestore.Spec.Target.Name,
		},
		Limits: p.limits,
	}
	b := &planBuilder{planner: p, plan: plan}

	target, err := p.ctrl.getTarget(vmRestore)
	if err != nil {
		return nil, err
	}
	if target.Exists() {
		targetVM := target.VirtualMachine()
		plan.Inputs.TargetUID = targetVM.UID
		plan.Inputs.TargetResourceVersion = targetVM.ResourceVersion
		digest, err := digestOf(targetVM.Spec)
		if err != nil {
			return nil, err
		}
		plan.Inputs.TargetSpecDigest = digest
	}

	// Running targets are an explicit Unsupported verdict. The planner never schedules a stop:
	// powering off the target stays the caller's decision, matching the zero-auto-stop rule.
	p.planTargetReadiness(vmRestore, target, b)

	vmSnapshot, snapshotPreconditions := p.planSnapshotReadiness(vmRestore, b)
	if vmSnapshot != nil {
		plan.Inputs.SnapshotUID = vmSnapshot.UID
	}
	// Without a usable snapshot/content nothing below can be evaluated truthfully.
	content, contentPreconditions := p.planContentReadiness(vmSnapshot, b)
	plan.Preconditions = append(plan.Preconditions, snapshotPreconditions...)
	plan.Preconditions = append(plan.Preconditions, contentPreconditions...)
	if content == nil {
		b.finalizePhase()
		return b.enforceBudgets()
	}

	plan.Inputs.ContentName = content.Name
	plan.Inputs.ContentUID = content.UID
	contentDigest, err := digestOf(content.Spec)
	if err != nil {
		return nil, err
	}
	plan.Inputs.ContentDigest = contentDigest

	snapshotVM := content.Spec.Source.VirtualMachine
	if snapshotVM == nil {
		return nil, fmt.Errorf("unexpected snapshot source in %s", content.Name)
	}

	// Same hard rule as updateVMRestore: a different, already existing target is rejected.
	if target.Exists() && !target.TargetRestored() && sourceAndTargetAreDifferent(target, vmSnapshot) {
		b.addGlobalPrecondition(RestorePlanPrecondition{
			Type:    preconditionTargetNotColliding,
			Status:  PreconditionUnmet,
			Message: errorRestoreToExistingTarget,
		})
	}

	noRestore, err := p.ctrl.volumesNotForRestore(content)
	if err != nil {
		return nil, err
	}

	restores := p.planVolumeRestores(vmRestore, content, noRestore, b)
	// DataVolume names are derived the same way updateVMRestoreRestores does, but the mapping is
	// only computed locally: no populatedFor annotation is written during a preview.
	restores = p.planDataVolumeNameMapping(vmRestore, content, restores, b)

	p.planPVCActions(vmRestore, target, content, snapshotVM, restores, b)

	candidateVM, err := p.planCandidateVM(vmRestore, target, snapshotVM, restores, b)
	if err != nil {
		return nil, err
	}

	p.planDataVolumeActions(vmRestore, target, candidateVM, restores, b)
	p.planBackendStateActions(ctx, vmRestore, target, content, snapshotVM, candidateVM, restores, b)
	p.planControllerRevisionActions(vmRestore, target, snapshotVM, candidateVM, b)
	p.planVMActions(vmRestore, target, candidateVM, b)
	p.planControllerRevisionOwnershipActions(vmRestore, target, candidateVM, b)
	p.planPVCOwnershipActions(vmRestore, target, candidateVM, b)
	p.planObsoleteResourceActions(vmRestore, target, candidateVM, b)

	if err := b.validateDAG(); err != nil {
		logger.Reason(err).Error("failed to validate restore preview DAG")
		return nil, err
	}

	b.finalizePhase()

	return b.enforceBudgets()
}

// planTargetReadiness mirrors vmRestoreTarget.Ready, which only consults the VMI informer.
func (p *ColdRestorePlanner) planTargetReadiness(vmRestore *snapshotv1.VirtualMachineRestore, target restoreTarget, b *planBuilder) {
	ready, err := target.Ready()
	if err != nil {
		b.addGlobalPrecondition(RestorePlanPrecondition{
			Type:    preconditionTargetPoweredOff,
			Status:  PreconditionUnknown,
			Message: fmt.Sprintf("cannot determine target readiness: %v", err),
		})
		return
	}
	if ready {
		b.addGlobalPrecondition(RestorePlanPrecondition{
			Type:    preconditionTargetPoweredOff,
			Status:  PreconditionMet,
			Message: "no VirtualMachineInstance exists for the restore target",
		})
		return
	}
	b.addGlobalPrecondition(RestorePlanPrecondition{
		Type:    preconditionTargetPoweredOff,
		Status:  PreconditionUnmet,
		Message: vmiExistsEventMessage,
	})
}

// planSnapshotReadiness replicates getVMSnapshot but turns failures into preconditions instead
// of hard errors, so a plan can still explain why it cannot be executed yet.
func (p *ColdRestorePlanner) planSnapshotReadiness(vmRestore *snapshotv1.VirtualMachineRestore, b *planBuilder) (*snapshotv1.VirtualMachineSnapshot, []RestorePlanPrecondition) {
	objKey := cacheKeyFunc(vmRestore.Namespace, vmRestore.Spec.VirtualMachineSnapshotName)
	obj, exists, err := p.ctrl.VMSnapshotInformer.GetStore().GetByKey(objKey)
	if err != nil {
		return nil, []RestorePlanPrecondition{{
			Type: preconditionSnapshotReady, Status: PreconditionUnknown,
			Message: fmt.Sprintf("cannot read VirtualMachineSnapshot %s: %v", objKey, err),
		}}
	}
	if !exists {
		return nil, []RestorePlanPrecondition{{
			Type: preconditionSnapshotReady, Status: PreconditionUnmet,
			Message: fmt.Sprintf("VMSnapshot %s does not exist", objKey),
		}}
	}
	vmSnapshot := obj.(*snapshotv1.VirtualMachineSnapshot).DeepCopy()
	switch {
	case vmSnapshotFailed(vmSnapshot):
		return vmSnapshot, []RestorePlanPrecondition{{
			Type: preconditionSnapshotReady, Status: PreconditionUnmet,
			Message: fmt.Sprintf("VMSnapshot %s failed and is invalid to use", objKey),
		}}
	case !VmSnapshotReady(vmSnapshot):
		return vmSnapshot, []RestorePlanPrecondition{{
			Type: preconditionSnapshotReady, Status: PreconditionUnknown,
			Message: fmt.Sprintf("VMSnapshot %s not ready", objKey),
		}}
	case vmSnapshot.Status.VirtualMachineSnapshotContentName == nil:
		return vmSnapshot, []RestorePlanPrecondition{{
			Type: preconditionSnapshotReady, Status: PreconditionUnknown,
			Message: fmt.Sprintf("no snapshot content name in %s", objKey),
		}}
	}
	return vmSnapshot, []RestorePlanPrecondition{{
		Type: preconditionSnapshotReady, Status: PreconditionMet,
		Message: fmt.Sprintf("VMSnapshot %s is ready", objKey),
	}}
}

// planContentReadiness replicates getSnapshotContent with precondition-based error handling.
func (p *ColdRestorePlanner) planContentReadiness(vmSnapshot *snapshotv1.VirtualMachineSnapshot, b *planBuilder) (*snapshotv1.VirtualMachineSnapshotContent, []RestorePlanPrecondition) {
	if vmSnapshot == nil || vmSnapshot.Status == nil || vmSnapshot.Status.VirtualMachineSnapshotContentName == nil {
		return nil, nil
	}
	objKey := cacheKeyFunc(vmSnapshot.Namespace, *vmSnapshot.Status.VirtualMachineSnapshotContentName)
	obj, exists, err := p.ctrl.VMSnapshotContentInformer.GetStore().GetByKey(objKey)
	if err != nil {
		return nil, []RestorePlanPrecondition{{
			Type: preconditionContentReady, Status: PreconditionUnknown,
			Message: fmt.Sprintf("cannot read VirtualMachineSnapshotContent %s: %v", objKey, err),
		}}
	}
	if !exists {
		return nil, []RestorePlanPrecondition{{
			Type: preconditionContentReady, Status: PreconditionUnmet,
			Message: fmt.Sprintf("VMSnapshotContent %s does not exist", objKey),
		}}
	}
	content := obj.(*snapshotv1.VirtualMachineSnapshotContent).DeepCopy()
	if !vmSnapshotContentReady(content) {
		return content, []RestorePlanPrecondition{{
			Type: preconditionContentReady, Status: PreconditionUnknown,
			Message: fmt.Sprintf("VMSnapshotContent %s not ready", objKey),
		}}
	}
	return content, []RestorePlanPrecondition{{
		Type: preconditionContentReady, Status: PreconditionMet,
		Message: fmt.Sprintf("VMSnapshotContent %s is ready", objKey),
	}}
}

// planVolumeRestores computes the exact VolumeRestore list reconcileVolumeRestores would persist,
// including the restore PVC naming semantics (override/in-place/prefix/randomized).
func (p *ColdRestorePlanner) planVolumeRestores(
	vmRestore *snapshotv1.VirtualMachineRestore,
	content *snapshotv1.VirtualMachineSnapshotContent,
	noRestore sets.String,
	b *planBuilder,
) []snapshotv1.VolumeRestore {
	var restores []snapshotv1.VolumeRestore
	for _, vb := range content.Spec.VolumeBackups {
		if _, skipped := noRestore[vb.VolumeName]; skipped {
			// Cold restore never recreates memory dump volumes. Surface that as an explicit
			// Unsupported skip instead of silently dropping the volume.
			b.addAction(PlannedAction{
				ID:   actionID(PlannedActionSkip, "volumedump", vb.VolumeName),
				Verb: PlannedActionSkip,
				Resource: PlannedResourceRef{
					APIVersion: corev1.SchemeGroupVersion.String(),
					Kind:       "PersistentVolumeClaim",
					Namespace:  vmRestore.Namespace,
					Name:       vb.PersistentVolumeClaim.Name,
				},
				Preconditions: []RestorePlanPrecondition{{
					Type: preconditionMemoryStateNotRestored, Status: PreconditionUnmet,
					Message: "memory dump volumes hold volatile guest state and are not restored by a cold restore",
				}},
				Note: "memory dump volume excluded from restore",
			})
			continue
		}
		if vb.VolumeSnapshotName == nil {
			b.addAction(PlannedAction{
				ID:   actionID(PlannedActionSkip, "volume", vb.VolumeName),
				Verb: PlannedActionSkip,
				Resource: PlannedResourceRef{
					APIVersion: corev1.SchemeGroupVersion.String(),
					Kind:       "PersistentVolumeClaim",
					Namespace:  vmRestore.Namespace,
					Name:       vb.PersistentVolumeClaim.Name,
				},
				Preconditions: []RestorePlanPrecondition{{
					Type: preconditionVolumeSnapshotPresent, Status: PreconditionUnmet,
					Message: fmt.Sprintf("volume %s has no VolumeSnapshot in the snapshot content", vb.VolumeName),
				}},
			})
			continue
		}
		restores = append(restores, snapshotv1.VolumeRestore{
			VolumeName:                vb.VolumeName,
			PersistentVolumeClaimName: restorePVCName(vmRestore, vb.VolumeName, vb.PersistentVolumeClaim.Name),
			VolumeSnapshotName:        *vb.VolumeSnapshotName,
		})
	}
	return restores
}

// planDataVolumeNameMapping mirrors updateVMRestoreRestores' DataVolumeName derivation without
// performing the populatedFor annotation write.
func (p *ColdRestorePlanner) planDataVolumeNameMapping(
	vmRestore *snapshotv1.VirtualMachineRestore,
	content *snapshotv1.VirtualMachineSnapshotContent,
	restores []snapshotv1.VolumeRestore,
	b *planBuilder,
) []snapshotv1.VolumeRestore {
	snapshotVM := content.Spec.Source.VirtualMachine
	volumes, err := storageutils.GetVolumes(snapshotVM, p.ctrl.Client)
	if err != nil {
		b.addGlobalPrecondition(RestorePlanPrecondition{
			Type:    preconditionDataVolumeReady,
			Status:  PreconditionUnknown,
			Message: fmt.Sprintf("cannot enumerate snapshot VM volumes: %v", err),
		})
		return restores
	}
	for i := range restores {
		restore := &restores[i]
		for _, volume := range volumes {
			if volume.Name != restore.VolumeName || volume.DataVolume == nil {
				continue
			}
			if findDVTemplateIndex(volume.DataVolume.Name, snapshotVM) >= 0 {
				dvName := restoreDVName(vmRestore, restore.VolumeName, volume.DataVolume.Name)
				restore.DataVolumeName = pointer.P(dvName)
			}
		}
	}
	return restores
}

// planPVCActions walks the planned VolumeRestores the same way reconcileVolumeRestores does and
// turns each branch into DAG nodes.
func (p *ColdRestorePlanner) planPVCActions(
	vmRestore *snapshotv1.VirtualMachineRestore,
	target restoreTarget,
	content *snapshotv1.VirtualMachineSnapshotContent,
	snapshotVM *snapshotv1.VirtualMachine,
	restores []snapshotv1.VolumeRestore,
	b *planBuilder,
) {
	for _, restore := range restores {
		backup, err := getRestoreVolumeBackup(restore.VolumeName, content)
		if err != nil {
			b.addGlobalPrecondition(RestorePlanPrecondition{
				Type: preconditionVolumeSnapshotPresent, Status: PreconditionUnmet, Message: err.Error(),
			})
			continue
		}
		isBackend := restore.VolumeName == storageutils.BackendPVCVolumeName(snapshotVM.Name)

		pvc, err := p.ctrl.getPVC(vmRestore.Namespace, restore.PersistentVolumeClaimName)
		if err != nil {
			b.addGlobalPrecondition(RestorePlanPrecondition{
				Type: preconditionRestorePVCNameAvailable, Status: PreconditionUnknown,
				Message: fmt.Sprintf("cannot read restore PVC %s: %v", restore.PersistentVolumeClaimName, err),
			})
			continue
		}

		if pvc == nil {
			p.planPVCCreate(vmRestore, target, backup, &restore, snapshotVM, isBackend, b)
			continue
		}

		if isVolumeRestorePolicyInPlace(vmRestore) && !hasLastRestoreAnnotation(vmRestore, pvc) {
			p.planInPlacePVCReplacement(vmRestore, pvc, backup, &restore, isBackend, b)
			continue
		}

		// Existing restore PVC: the controller only waits for binding here.
		switch pvc.Status.Phase {
		case corev1.ClaimBound:
			b.addAction(PlannedAction{
				ID:   actionID(PlannedActionAdopt, "pvc", pvc.Name),
				Verb: PlannedActionAdopt,
				Resource: PlannedResourceRef{
					APIVersion: corev1.SchemeGroupVersion.String(), Kind: "PersistentVolumeClaim",
					Namespace: pvc.Namespace, Name: pvc.Name,
				},
				BackendState: isBackend,
				Preconditions: []RestorePlanPrecondition{{
					Type: preconditionRestorePVCBound, Status: PreconditionMet,
					Message: fmt.Sprintf("restore PVC %s already exists and is Bound", pvc.Name),
				}},
				Note: "restore PVC already present from an earlier reconcile",
			})
		case corev1.ClaimPending:
			preconditions := p.planBindingPreconditions(pvc)
			b.addAction(PlannedAction{
				ID:   actionID(PlannedActionWait, "pvc", pvc.Name),
				Verb: PlannedActionWait,
				Resource: PlannedResourceRef{
					APIVersion: corev1.SchemeGroupVersion.String(), Kind: "PersistentVolumeClaim",
					Namespace: pvc.Namespace, Name: pvc.Name,
				},
				BackendState:  isBackend,
				Preconditions: preconditions,
				Note:          "wait for the CSI-provisioned restore PVC to bind; the planner cannot promise CSI restore success",
			})
		default:
			b.addAction(PlannedAction{
				ID:   actionID(PlannedActionWait, "pvc", pvc.Name),
				Verb: PlannedActionWait,
				Resource: PlannedResourceRef{
					APIVersion: corev1.SchemeGroupVersion.String(), Kind: "PersistentVolumeClaim",
					Namespace: pvc.Namespace, Name: pvc.Name,
				},
				BackendState: isBackend,
				Preconditions: []RestorePlanPrecondition{{
					Type: preconditionRestorePVCBound, Status: PreconditionUnmet,
					Message: fmt.Sprintf("PVC %s/%s in status %q", pvc.Namespace, pvc.Name, pvc.Status.Phase),
				}},
			})
		}
	}
}

// planPVCCreate replicates createRestorePVC/CreateRestorePVCDefFromVMRestore without writing.
func (p *ColdRestorePlanner) planPVCCreate(
	vmRestore *snapshotv1.VirtualMachineRestore,
	target restoreTarget,
	volumeBackup *snapshotv1.VolumeBackup,
	volumeRestore *snapshotv1.VolumeRestore,
	snapshotVM *snapshotv1.VirtualMachine,
	isBackend bool,
	b *planBuilder,
) {
	preconditions := []RestorePlanPrecondition{{
		Type: preconditionRestorePVCNameAvailable, Status: PreconditionMet,
		Message: fmt.Sprintf("no PersistentVolumeClaim named %s exists yet", volumeRestore.PersistentVolumeClaimName),
	}}

	if volumeBackup.VolumeSnapshotName == nil {
		preconditions = append(preconditions, RestorePlanPrecondition{
			Type: preconditionVolumeSnapshotPresent, Status: PreconditionUnmet,
			Message: fmt.Sprintf("VolumeSnapshot name missing for volume %s", volumeBackup.VolumeName),
		})
		b.addAction(p.plannedPVCErrorAction(vmRestore, volumeRestore, volumeBackup, isBackend, preconditions))
		return
	}

	volumeSnapshot, err := p.ctrl.VolumeSnapshotProvider.GetVolumeSnapshot(vmRestore.Namespace, *volumeBackup.VolumeSnapshotName)
	if err != nil {
		preconditions = append(preconditions, RestorePlanPrecondition{
			Type: preconditionVolumeSnapshotPresent, Status: PreconditionUnknown,
			Message: fmt.Sprintf("cannot read VolumeSnapshot %s: %v", *volumeBackup.VolumeSnapshotName, err),
		})
		b.addAction(p.plannedPVCErrorAction(vmRestore, volumeRestore, volumeBackup, isBackend, preconditions))
		return
	}
	if volumeSnapshot == nil {
		preconditions = append(preconditions, RestorePlanPrecondition{
			Type: preconditionVolumeSnapshotPresent, Status: PreconditionUnmet,
			Message: fmt.Sprintf("missing volumeSnapshot %s", *volumeBackup.VolumeSnapshotName),
		})
		b.addAction(p.plannedPVCErrorAction(vmRestore, volumeRestore, volumeBackup, isBackend, preconditions))
		return
	}
	preconditions = append(preconditions, RestorePlanPrecondition{
		Type: preconditionVolumeSnapshotPresent, Status: PreconditionMet,
		Message: fmt.Sprintf("VolumeSnapshot %s is present", *volumeBackup.VolumeSnapshotName),
	})

	// The exact PVC definition the controller would send, including restore naming,
	// annotation filtering and restore overrides.
	pvc, err := CreateRestorePVCDefFromVMRestore(
		vmRestore,
		volumeRestore.PersistentVolumeClaimName,
		volumeSnapshot,
		volumeBackup,
		snapshotVM.Name,
		snapshotVM.Namespace,
	)
	if err != nil {
		preconditions = append(preconditions, RestorePlanPrecondition{
			Type: preconditionVolumeSnapshotPresent, Status: PreconditionUnmet, Message: err.Error(),
		})
		b.addAction(p.plannedPVCErrorAction(vmRestore, volumeRestore, volumeBackup, isBackend, preconditions))
		return
	}

	// Replicate the ownership decision from createRestorePVC on the local object only.
	var dvOwner string
	if volumeRestore.DataVolumeName != nil {
		dvOwner = *volumeRestore.DataVolumeName
	}
	if dvOwner != "" {
		if pvc.Annotations == nil {
			pvc.Annotations = make(map[string]string)
		}
		pvc.Annotations[populatedForPVCAnnotation] = dvOwner
	} else if !isVolumeOwnershipPolicyNone(vmRestore) {
		if target.Exists() {
			target.Own(pvc)
		} else if sourcePVCOwnedBySourceVM(volumeBackup, snapshotVM) {
			pvc.Annotations[restoreOwnedByVMLabel] = vmRestore.Name
		}
	}

	preconditions = append(preconditions, p.planStorageClassPreconditions(pvc)...)

	summary, err := summarizePVC(pvc)
	if err != nil {
		b.addGlobalPrecondition(RestorePlanPrecondition{
			Type: preconditionRestorePVCNameAvailable, Status: PreconditionUnknown, Message: err.Error(),
		})
		return
	}

	action := PlannedAction{
		ID:   actionID(PlannedActionCreate, "pvc", pvc.Name),
		Verb: PlannedActionCreate,
		Resource: PlannedResourceRef{
			APIVersion: corev1.SchemeGroupVersion.String(), Kind: "PersistentVolumeClaim",
			Namespace: pvc.Namespace, Name: pvc.Name,
		},
		BackendState:  isBackend,
		Preconditions: preconditions,
		Summary:       summary,
		Note:          "CSI restores the VolumeSnapshot into a new PVC; completion depends on the storage driver and is not guaranteed by the plan",
	}
	// A DV-backed restore PVC is created first and the prepopulated DataVolume adopts it later,
	// so the PVC action intentionally has no dependency on the DataVolume action.
	_ = dvOwner
	b.addAction(action)
}

func (p *ColdRestorePlanner) plannedPVCErrorAction(
	vmRestore *snapshotv1.VirtualMachineRestore,
	volumeRestore *snapshotv1.VolumeRestore,
	volumeBackup *snapshotv1.VolumeBackup,
	isBackend bool,
	preconditions []RestorePlanPrecondition,
) PlannedAction {
	return PlannedAction{
		ID:   actionID(PlannedActionSkip, "pvc", volumeRestore.PersistentVolumeClaimName),
		Verb: PlannedActionSkip,
		Resource: PlannedResourceRef{
			APIVersion: corev1.SchemeGroupVersion.String(), Kind: "PersistentVolumeClaim",
			Namespace: vmRestore.Namespace, Name: volumeRestore.PersistentVolumeClaimName,
		},
		BackendState:  isBackend,
		Preconditions: preconditions,
		Note:          fmt.Sprintf("restore of volume %s cannot proceed until its preconditions are met", volumeBackup.VolumeName),
	}
}

// planInPlacePVCReplacement models the InPlace branch: prepopulate the owning DataVolume, delete
// the existing PVC and let the regular create branch restore it under the same name.
func (p *ColdRestorePlanner) planInPlacePVCReplacement(
	vmRestore *snapshotv1.VirtualMachineRestore,
	existingPVC *corev1.PersistentVolumeClaim,
	volumeBackup *snapshotv1.VolumeBackup,
	volumeRestore *snapshotv1.VolumeRestore,
	isBackend bool,
	b *planBuilder,
) {
	var dependsOn []string
	ownerReference := metav1.GetControllerOf(existingPVC)
	if ownerReference != nil && ownerReference.Kind == "DataVolume" {
		patchAction := p.planPrepopulateDataVolumePatch(vmRestore.Namespace, ownerReference.Name)
		b.addAction(patchAction)
		dependsOn = append(dependsOn, patchAction.ID)
	}

	deleteAction := PlannedAction{
		ID:   actionID(PlannedActionDelete, "pvc", existingPVC.Name),
		Verb: PlannedActionDelete,
		Resource: PlannedResourceRef{
			APIVersion: corev1.SchemeGroupVersion.String(), Kind: "PersistentVolumeClaim",
			Namespace: existingPVC.Namespace, Name: existingPVC.Name,
		},
		BackendState: isBackend,
		DependsOn:    dependsOn,
		Preconditions: append(p.planReclaimPreconditions(existingPVC), RestorePlanPrecondition{
			Type: preconditionRestorePVCNameAvailable, Status: PreconditionMet,
			Message: "InPlace policy wipes the existing PVC before restoring it",
		}),
		Note: "existing PVC is deleted so the VolumeSnapshot can be restored in place",
	}
	b.addAction(deleteAction)

	// The recreated PVC is the same object a randomized restore would create; express it as a
	// create that depends on the delete.
	recreate := PlannedAction{
		ID:   actionID(PlannedActionCreate, "pvc", existingPVC.Name),
		Verb: PlannedActionCreate,
		Resource: PlannedResourceRef{
			APIVersion: corev1.SchemeGroupVersion.String(), Kind: "PersistentVolumeClaim",
			Namespace: existingPVC.Namespace, Name: existingPVC.Name,
		},
		BackendState: isBackend,
		DependsOn:    []string{deleteAction.ID},
		Preconditions: []RestorePlanPrecondition{{
			Type: preconditionVolumeSnapshotPresent, Status: p.volumeSnapshotStatus(vmRestore.Namespace, volumeBackup),
			Message: fmt.Sprintf("VolumeSnapshot %s must stay available until the PVC is recreated", ptrString(volumeBackup.VolumeSnapshotName)),
		}},
		Note: "PVC recreated from the VolumeSnapshot after the in-place delete",
	}
	b.addAction(recreate)
}

// planPrepopulateDataVolumePatch renders the exact prepopulate patch prepopulateDataVolume sends.
func (p *ColdRestorePlanner) planPrepopulateDataVolumePatch(namespace, dataVolume string) PlannedAction {
	restoreNameAnnotation := fmt.Sprintf("/metadata/annotations/%s", patch.EscapeJSONPointer(RestoreNameAnnotation))
	prePopulatedAnnotation := fmt.Sprintf("/metadata/annotations/%s", patch.EscapeJSONPointer(cdiv1.AnnPrePopulated))
	payload, err := patch.New(
		patch.WithAdd(restoreNameAnnotation, dataVolume),
		patch.WithAdd(prePopulatedAnnotation, dataVolume),
	).GeneratePayload()
	summary := patchSummary(payload, err)
	return PlannedAction{
		ID:   actionID(PlannedActionPatch, "dv", dataVolume),
		Verb: PlannedActionPatch,
		Resource: PlannedResourceRef{
			APIVersion: cdiv1.SchemeGroupVersion.String(), Kind: "DataVolume",
			Namespace: namespace, Name: dataVolume,
		},
		Summary: summary,
		Note:    "mark the DataVolume prepopulated so CDI does not recreate the PVC during the in-place restore",
	}
}

// planStorageClassPreconditions evaluates StorageClass presence, binding mode and reclaim policy
// for a prospective restore PVC. Missing dynamic information always degrades to Unknown.
func (p *ColdRestorePlanner) planStorageClassPreconditions(pvc *corev1.PersistentVolumeClaim) []RestorePlanPrecondition {
	var preconditions []RestorePlanPrecondition
	if pvc.Spec.StorageClassName == nil {
		preconditions = append(preconditions, RestorePlanPrecondition{
			Type: preconditionStorageClassResolvable, Status: PreconditionUnknown,
			Message: "restore PVC does not pin a StorageClass; cluster default resolution happens at apply time",
		})
		return preconditions
	}
	scName := *pvc.Spec.StorageClassName
	obj, exists, err := p.ctrl.StorageClassInformer.GetStore().GetByKey(scName)
	if err != nil {
		preconditions = append(preconditions, RestorePlanPrecondition{
			Type: preconditionStorageClassResolvable, Status: PreconditionUnknown,
			Message: fmt.Sprintf("cannot read StorageClass %s: %v", scName, err),
		})
		return preconditions
	}
	if !exists {
		preconditions = append(preconditions, RestorePlanPrecondition{
			Type: preconditionStorageClassResolvable, Status: PreconditionUnmet,
			Message: fmt.Sprintf("StorageClass %s does not exist", scName),
		})
		return preconditions
	}
	sc := obj.(*storagev1.StorageClass)
	preconditions = append(preconditions, RestorePlanPrecondition{
		Type: preconditionStorageClassResolvable, Status: PreconditionMet,
		Message: fmt.Sprintf("StorageClass %s exists", scName),
	})
	if sc.VolumeBindingMode == nil {
		preconditions = append(preconditions, RestorePlanPrecondition{
			Type: preconditionStorageClassBindingKnown, Status: PreconditionUnknown,
			Message: fmt.Sprintf("StorageClass %s does not report a volume binding mode", scName),
		})
	} else {
		preconditions = append(preconditions, RestorePlanPrecondition{
			Type: preconditionStorageClassBindingKnown, Status: PreconditionMet,
			Message: fmt.Sprintf("StorageClass %s binding mode is %s", scName, *sc.VolumeBindingMode),
		})
	}
	if sc.ReclaimPolicy == nil {
		preconditions = append(preconditions, RestorePlanPrecondition{
			Type: preconditionStorageClassReclaimKnown, Status: PreconditionUnknown,
			Message: fmt.Sprintf("StorageClass %s does not report a reclaim policy", scName),
		})
	} else {
		preconditions = append(preconditions, RestorePlanPrecondition{
			Type: preconditionStorageClassReclaimKnown, Status: PreconditionMet,
			Message: fmt.Sprintf("StorageClass %s reclaim policy is %s; Retain keeps the backing PV after an in-place delete", scName, *sc.ReclaimPolicy),
		})
	}
	return preconditions
}

func (p *ColdRestorePlanner) planBindingPreconditions(pvc *corev1.PersistentVolumeClaim) []RestorePlanPrecondition {
	bindingMode, err := p.ctrl.getBindingMode(pvc)
	if err != nil {
		return []RestorePlanPrecondition{{
			Type: preconditionStorageClassBindingKnown, Status: PreconditionUnknown, Message: err.Error(),
		}}
	}
	if bindingMode == nil {
		return []RestorePlanPrecondition{{
			Type: preconditionStorageClassBindingKnown, Status: PreconditionUnknown,
			Message: "StorageClass binding mode cannot be determined; the restore may stay Pending until a consumer schedules",
		}}
	}
	return []RestorePlanPrecondition{{
		Type: preconditionStorageClassBindingKnown, Status: PreconditionMet,
		Message: fmt.Sprintf("StorageClass binding mode is %s; waiting for the external provisioner to bind the restore PVC", *bindingMode),
	}}
}

func (p *ColdRestorePlanner) planReclaimPreconditions(pvc *corev1.PersistentVolumeClaim) []RestorePlanPrecondition {
	if pvc.Spec.StorageClassName == nil {
		return []RestorePlanPrecondition{{
			Type: preconditionStorageClassReclaimKnown, Status: PreconditionUnknown,
			Message: "PVC has no StorageClass; reclaim behavior after delete is unknown",
		}}
	}
	obj, exists, err := p.ctrl.StorageClassInformer.GetStore().GetByKey(*pvc.Spec.StorageClassName)
	if err != nil || !exists {
		return []RestorePlanPrecondition{{
			Type: preconditionStorageClassReclaimKnown, Status: PreconditionUnknown,
			Message: fmt.Sprintf("StorageClass %s cannot be read", ptrString(pvc.Spec.StorageClassName)),
		}}
	}
	sc := obj.(*storagev1.StorageClass)
	if sc.ReclaimPolicy == nil {
		return []RestorePlanPrecondition{{
			Type: preconditionStorageClassReclaimKnown, Status: PreconditionUnknown,
			Message: fmt.Sprintf("StorageClass %s reports no reclaim policy", sc.Name),
		}}
	}
	return []RestorePlanPrecondition{{
		Type: preconditionStorageClassReclaimKnown, Status: PreconditionMet,
		Message: fmt.Sprintf("StorageClass %s reclaim policy is %s", sc.Name, *sc.ReclaimPolicy),
	}}
}

func (p *ColdRestorePlanner) volumeSnapshotStatus(namespace string, volumeBackup *snapshotv1.VolumeBackup) PreconditionStatus {
	if volumeBackup == nil || volumeBackup.VolumeSnapshotName == nil {
		return PreconditionUnmet
	}
	volumeSnapshot, err := p.ctrl.VolumeSnapshotProvider.GetVolumeSnapshot(namespace, *volumeBackup.VolumeSnapshotName)
	if err != nil || volumeSnapshot == nil {
		return PreconditionUnknown
	}
	return PreconditionMet
}

// planCandidateVM runs the real generateRestoredVMSpec on deep copies, so the informer caches and
// the caller's objects are untouched. New targets additionally go through the real patchVM.
func (p *ColdRestorePlanner) planCandidateVM(
	vmRestore *snapshotv1.VirtualMachineRestore,
	target restoreTarget,
	snapshotVM *snapshotv1.VirtualMachine,
	restores []snapshotv1.VolumeRestore,
	b *planBuilder,
) (*kubevirtv1.VirtualMachine, error) {
	vmRestoreCopy := vmRestore.DeepCopy()
	vmRestoreCopy.Status.Restores = restores

	var targetVM *kubevirtv1.VirtualMachine
	if target.Exists() {
		targetVM = target.VirtualMachine().DeepCopy()
	}
	privateTarget := &vmRestoreTarget{
		controller: p.ctrl,
		vmRestore:  vmRestoreCopy,
		vm:         targetVM,
	}

	candidateVM, err := privateTarget.generateRestoredVMSpec(snapshotVM)
	if err != nil {
		b.addGlobalPrecondition(RestorePlanPrecondition{
			Type: preconditionBackendStateCaptured, Status: PreconditionUnmet, Message: err.Error(),
		})
		return nil, nil
	}

	if !privateTarget.Exists() && len(vmRestore.Spec.Patches) > 0 {
		patchedVM, patchErr := patchVM(candidateVM.DeepCopy(), vmRestore.Spec.Patches)
		if patchErr != nil {
			b.addGlobalPrecondition(RestorePlanPrecondition{
				Type: preconditionTargetPatchesApplicable, Status: PreconditionUnmet,
				Message: fmt.Sprintf("restore patches cannot be applied to the candidate VM: %v", patchErr),
			})
		} else {
			candidateVM = patchedVM
			b.addGlobalPrecondition(RestorePlanPrecondition{
				Type: preconditionTargetPatchesApplicable, Status: PreconditionMet,
				Message: fmt.Sprintf("%d JSON patch(es) apply cleanly to the candidate VM", len(vmRestore.Spec.Patches)),
			})
		}
	}

	summary, err := summarizeVirtualMachine(candidateVM)
	if err != nil {
		return nil, err
	}
	b.plan.CandidateVM = summary
	return candidateVM, nil
}

// planDataVolumeActions mirrors reconcileDataVolumes/createDataVolume using only cache reads.
func (p *ColdRestorePlanner) planDataVolumeActions(
	vmRestore *snapshotv1.VirtualMachineRestore,
	target restoreTarget,
	candidateVM *kubevirtv1.VirtualMachine,
	restores []snapshotv1.VolumeRestore,
	b *planBuilder,
) {
	if candidateVM == nil {
		return
	}
	for _, dvt := range candidateVM.Spec.DataVolumeTemplates {
		dv, err := p.ctrl.getDV(vmRestore.Namespace, dvt.Name)
		if err != nil {
			b.addGlobalPrecondition(RestorePlanPrecondition{
				Type: preconditionDataVolumeReady, Status: PreconditionUnknown,
				Message: fmt.Sprintf("cannot read DataVolume %s: %v", dvt.Name, err),
			})
			continue
		}
		if dv != nil {
			if dv.Status.Phase == cdiv1.Succeeded ||
				dv.Status.Phase == cdiv1.WaitForFirstConsumer ||
				dv.Status.Phase == cdiv1.PendingPopulation {
				b.addAction(PlannedAction{
					ID:   actionID(PlannedActionAdopt, "dv", dv.Name),
					Verb: PlannedActionAdopt,
					Resource: PlannedResourceRef{
						APIVersion: cdiv1.SchemeGroupVersion.String(), Kind: "DataVolume",
						Namespace: dv.Namespace, Name: dv.Name,
					},
					Preconditions: []RestorePlanPrecondition{{
						Type: preconditionDataVolumeReady, Status: PreconditionMet,
						Message: fmt.Sprintf("DataVolume %s already exists in phase %s", dv.Name, dv.Status.Phase),
					}},
				})
				continue
			}
			b.addAction(PlannedAction{
				ID:   actionID(PlannedActionWait, "dv", dv.Name),
				Verb: PlannedActionWait,
				Resource: PlannedResourceRef{
					APIVersion: cdiv1.SchemeGroupVersion.String(), Kind: "DataVolume",
					Namespace: dv.Namespace, Name: dv.Name,
				},
				Preconditions: []RestorePlanPrecondition{{
					Type: preconditionDataVolumeReady, Status: PreconditionUnknown,
					Message: fmt.Sprintf("DataVolume %s is in phase %s; CDI must finish populating it", dv.Name, dv.Status.Phase),
				}},
			})
			continue
		}

		// Same gating as createDataVolume: the restore PVC must exist and carry the
		// populatedFor annotation without owner references before the DV is created.
		pvc, err := p.ctrl.getPVC(vmRestore.Namespace, dvt.Name)
		if err != nil {
			b.addGlobalPrecondition(RestorePlanPrecondition{
				Type: preconditionDataVolumeReady, Status: PreconditionUnknown,
				Message: fmt.Sprintf("cannot read backing PVC %s: %v", dvt.Name, err),
			})
			continue
		}
		pvcCreateID := actionID(PlannedActionCreate, "pvc", dvt.Name)
		pvcCreatePlanned := b.hasAction(pvcCreateID)
		populatedForUpdateID := actionID(PlannedActionUpdate, "pvc", dvt.Name)
		preconditions := []RestorePlanPrecondition{}
		var dependsOn []string
		if pvcCreatePlanned {
			dependsOn = append(dependsOn, pvcCreateID)
		}

		if pvc == nil {
			// The PVC does not exist yet. When the DAG already creates it, every follow-up step is
			// guaranteed by ordering; otherwise the DataVolume has no backing PVC to adopt.
			if pvcCreatePlanned {
				preconditions = append(preconditions, RestorePlanPrecondition{
					Type: preconditionRestorePVCBound, Status: PreconditionMet,
					Message: fmt.Sprintf("backing PVC %s is created by an earlier DAG action before DataVolume adoption", dvt.Name),
				})
			} else {
				preconditions = append(preconditions, RestorePlanPrecondition{
					Type: preconditionRestorePVCBound, Status: PreconditionUnmet,
					Message: fmt.Sprintf("backing PVC %s/%s does not exist and no create action is planned for it", vmRestore.Namespace, dvt.Name),
				})
			}
			// updateVMRestoreRestores stamps populatedFor as soon as the created PVC appears, so the
			// update is a deterministic consequence of the create action, even at preview time.
			if pvcCreatePlanned {
				b.addAction(PlannedAction{
					ID:   populatedForUpdateID,
					Verb: PlannedActionUpdate,
					Resource: PlannedResourceRef{
						APIVersion: corev1.SchemeGroupVersion.String(), Kind: "PersistentVolumeClaim",
						Namespace: vmRestore.Namespace, Name: dvt.Name,
					},
					DependsOn: []string{pvcCreateID},
					Preconditions: []RestorePlanPrecondition{{
						Type: preconditionRestorePVCBound, Status: PreconditionMet,
						Message: fmt.Sprintf("restore PVC %s receives the %s=%s annotation for DataVolume adoption",
							dvt.Name, populatedForPVCAnnotation, dvt.Name),
					}},
					Note: "stamp populatedFor so the DataVolume takes ownership of the restore PVC",
				})
				dependsOn = append(dependsOn, populatedForUpdateID)
			}
		} else {
			status := PreconditionMet
			message := fmt.Sprintf("backing PVC %s is ready to be adopted by DataVolume %s", dvt.Name, dvt.Name)
			if pvc.Annotations[populatedForPVCAnnotation] != dvt.Name || len(pvc.OwnerReferences) > 0 {
				status = PreconditionUnknown
				message = fmt.Sprintf("backing PVC %s must carry %s=%s and have no owner references before DV adoption",
					dvt.Name, populatedForPVCAnnotation, dvt.Name)
			}
			preconditions = append(preconditions, RestorePlanPrecondition{
				Type: preconditionRestorePVCBound, Status: status, Message: message,
			})

			// Render the same DV manifest the controller would create. The template generation only
			// performs read-only cluster lookups (e.g. clone source resolution); failures surface as
			// Unknown preconditions rather than blocking the preview.
			if _, dvErr := typesutil.GenerateDataVolumeFromTemplate(
				p.ctrl.Client, dvt, vmRestore.Namespace, candidateVM.Spec.Template.Spec.PriorityClassName); dvErr != nil {
				b.addGlobalPrecondition(RestorePlanPrecondition{
					Type: preconditionDataVolumeReady, Status: PreconditionUnknown, Message: dvErr.Error(),
				})
			}
			if pvc.Annotations[populatedForPVCAnnotation] != dvt.Name {
				b.addAction(PlannedAction{
					ID:   populatedForUpdateID,
					Verb: PlannedActionUpdate,
					Resource: PlannedResourceRef{
						APIVersion: corev1.SchemeGroupVersion.String(), Kind: "PersistentVolumeClaim",
						Namespace: vmRestore.Namespace, Name: dvt.Name,
					},
					Preconditions: []RestorePlanPrecondition{{
						Type: preconditionRestorePVCBound, Status: PreconditionMet,
						Message: fmt.Sprintf("existing restore PVC %s receives the %s=%s annotation for DataVolume adoption",
							dvt.Name, populatedForPVCAnnotation, dvt.Name),
					}},
					Note: "stamp populatedFor so the DataVolume takes ownership of the restore PVC",
				})
				dependsOn = append(dependsOn, populatedForUpdateID)
			}
		}

		b.addAction(PlannedAction{
			ID:   actionID(PlannedActionCreate, "dv", dvt.Name),
			Verb: PlannedActionCreate,
			Resource: PlannedResourceRef{
				APIVersion: cdiv1.SchemeGroupVersion.String(), Kind: "DataVolume",
				Namespace: vmRestore.Namespace, Name: dvt.Name,
			},
			DependsOn:     dependsOn,
			Preconditions: preconditions,
			Note:          "prepopulated DataVolume adopts the restore PVC instead of importing data",
		})
	}
}

// planBackendStateActions gives TPM/EFI/NVRAM VirtualMachineState the same first-class treatment
// as regular disks. It is never modeled as a disposable temporary directory.
func (p *ColdRestorePlanner) planBackendStateActions(
	ctx context.Context,
	vmRestore *snapshotv1.VirtualMachineRestore,
	target restoreTarget,
	content *snapshotv1.VirtualMachineSnapshotContent,
	snapshotVM *snapshotv1.VirtualMachine,
	candidateVM *kubevirtv1.VirtualMachine,
	restores []snapshotv1.VolumeRestore,
	b *planBuilder,
) {
	if !backendstorage.IsBackendStorageNeeded(snapshotVM) {
		return
	}
	backendVolumeName := storageutils.BackendPVCVolumeName(snapshotVM.Name)

	var backupPVCName string
	for _, vb := range content.Spec.VolumeBackups {
		if vb.VolumeName == backendVolumeName {
			backupPVCName = vb.PersistentVolumeClaim.Name
			break
		}
	}

	// The backend volume was not captured: reproduce reconcileBackendVolume/restoreVirtualMachineState
	// semantics instead of pretending the state simply does not matter.
	if backupPVCName == "" {
		p.planUncapturedBackendState(vmRestore, target, snapshotVM, candidateVM, b)
		return
	}

	// Live lookup wins over the snapshot recorded name, matching the controller.
	backendPVCName := backupPVCName
	volumes, err := storageutils.GetVolumes(snapshotVM, p.ctrl.Client, storageutils.WithBackendVolume)
	switch {
	case err == nil && len(volumes) > 0:
		backendPVCName = volumes[0].VolumeSource.PersistentVolumeClaim.ClaimName
	case err != nil && !storageutils.IsErrNoBackendPVC(err):
		b.addGlobalPrecondition(RestorePlanPrecondition{
			Type: preconditionBackendStatePVCResolvable, Status: PreconditionUnknown, Message: err.Error(),
		})
	}

	originalPVC, err := p.ctrl.getPVC(snapshotVM.Namespace, backendPVCName)
	if err != nil {
		b.addGlobalPrecondition(RestorePlanPrecondition{
			Type: preconditionBackendStatePVCResolvable, Status: PreconditionUnknown, Message: err.Error(),
		})
	}

	// Step 1: the original backend PVC loses its backend label and gets the cleanup label, but
	// only when it still exists and is not itself a restore PVC.
	if originalPVC != nil && vmRestore.Spec.Target.Name == snapshotVM.Name {
		isRestorePVC := false
		for _, vr := range restores {
			if vr.PersistentVolumeClaimName == originalPVC.Name {
				isRestorePVC = true
				break
			}
		}
		if !isRestorePVC && originalPVC.Labels != nil {
			newLabels := getFilteredLabels(originalPVC.Labels)
			newLabels[restoreCleanupBackendPVCLabel] = getCleanupLabelValue(vmRestore)
			payload, payloadErr := patch.New(
				patch.WithTest("/metadata/labels", originalPVC.Labels),
				patch.WithReplace("/metadata/labels", newLabels),
			).GeneratePayload()
			b.addAction(PlannedAction{
				ID:   actionID(PlannedActionPatch, "backend-pvc", originalPVC.Name),
				Verb: PlannedActionPatch,
				Resource: PlannedResourceRef{
					APIVersion: corev1.SchemeGroupVersion.String(), Kind: "PersistentVolumeClaim",
					Namespace: originalPVC.Namespace, Name: originalPVC.Name,
				},
				BackendState: true,
				Summary:      patchSummary(payload, payloadErr),
				Preconditions: []RestorePlanPrecondition{{
					Type: preconditionBackendStateCaptured, Status: PreconditionMet,
					Message: "original TPM/EFI backend PVC is detached from the VM and marked for cleanup",
				}},
				Note: "persistent TPM/EFI/NVRAM state: relabel, never discard the restore PVC",
			})
		}
	}

	// Step 2 only applies to the legacy implicit backend storage.
	if !backendstorage.HasLegacyBackendStorage(snapshotVM) {
		p.planBackendSourceRepoint(vmRestore, snapshotVM, candidateVM, restores, b)
		return
	}

	for _, vr := range restores {
		if vr.VolumeName != backendVolumeName {
			continue
		}
		restorePVC, err := p.ctrl.getPVC(vmRestore.Namespace, vr.PersistentVolumeClaimName)
		if err != nil {
			b.addGlobalPrecondition(RestorePlanPrecondition{
				Type: preconditionBackendStatePVCResolvable, Status: PreconditionUnknown, Message: err.Error(),
			})
			return
		}
		alreadyLabelled := restorePVC != nil && restorePVC.Labels[backendstorage.PVCPrefix] == vmRestore.Spec.Target.Name
		if (originalPVC != nil && restorePVC != nil && restorePVC.Name == originalPVC.Name) || alreadyLabelled {
			continue
		}
		createActionID := actionID(PlannedActionCreate, "pvc", vr.PersistentVolumeClaimName)
		if restorePVC == nil {
			// The PVC does not exist yet. When the DAG creates it, the label patch is a deterministic
			// follow-up; otherwise there is nothing to label and this stays an Unknown precondition.
			if !b.hasAction(createActionID) {
				b.addGlobalPrecondition(RestorePlanPrecondition{
					Type: preconditionBackendStatePVCResolvable, Status: PreconditionUnknown,
					Message: fmt.Sprintf("restore backend PVC %s does not exist yet", vr.PersistentVolumeClaimName),
				})
				continue
			}
			payload, payloadErr := patch.New(
				patch.WithAdd("/metadata/labels", map[string]string{
					backendstorage.PVCPrefix: vmRestore.Spec.Target.Name,
				}),
			).GeneratePayload()
			b.addAction(PlannedAction{
				ID:   actionID(PlannedActionPatch, "backend-restore-pvc", vr.PersistentVolumeClaimName),
				Verb: PlannedActionPatch,
				Resource: PlannedResourceRef{
					APIVersion: corev1.SchemeGroupVersion.String(), Kind: "PersistentVolumeClaim",
					Namespace: vmRestore.Namespace, Name: vr.PersistentVolumeClaimName,
				},
				BackendState: true,
				DependsOn:    []string{createActionID},
				Summary:      patchSummary(payload, payloadErr),
				Preconditions: []RestorePlanPrecondition{{
					Type: preconditionBackendStateCaptured, Status: PreconditionMet,
					Message: "created restore PVC receives the backend storage label",
				}},
			})
			continue
		}
		var payload []byte
		var payloadErr error
		if restorePVC.Labels == nil {
			payload, payloadErr = patch.New(
				patch.WithAdd("/metadata/labels", map[string]string{
					backendstorage.PVCPrefix: vmRestore.Spec.Target.Name,
				}),
			).GeneratePayload()
		} else {
			updatedLabels := map[string]string{backendstorage.PVCPrefix: vmRestore.Spec.Target.Name}
			for k, v := range restorePVC.Labels {
				updatedLabels[k] = v
			}
			payload, payloadErr = patch.New(
				patch.WithTest("/metadata/labels", restorePVC.Labels),
				patch.WithReplace("/metadata/labels", updatedLabels),
			).GeneratePayload()
		}
		b.addAction(PlannedAction{
			ID:   actionID(PlannedActionPatch, "backend-restore-pvc", vr.PersistentVolumeClaimName),
			Verb: PlannedActionPatch,
			Resource: PlannedResourceRef{
				APIVersion: corev1.SchemeGroupVersion.String(), Kind: "PersistentVolumeClaim",
				Namespace: vmRestore.Namespace, Name: vr.PersistentVolumeClaimName,
			},
			BackendState: true,
			Summary:      patchSummary(payload, payloadErr),
			Preconditions: []RestorePlanPrecondition{{
				Type: preconditionBackendStateCaptured, Status: PreconditionMet,
				Message: "restore PVC receives the backend storage label",
			}},
		})
	}
	p.planBackendSourceRepoint(vmRestore, snapshotVM, candidateVM, restores, b)
}

// planUncapturedBackendState covers the case where the backend PVC had no VolumeSnapshot support
// at backup time. Same-name VMs adopt the existing PVC; different-name VMs start from fresh state
// or fail exactly like restoreVirtualMachineState.
func (p *ColdRestorePlanner) planUncapturedBackendState(
	vmRestore *snapshotv1.VirtualMachineRestore,
	target restoreTarget,
	snapshotVM *snapshotv1.VirtualMachine,
	candidateVM *kubevirtv1.VirtualMachine,
	b *planBuilder,
) {
	if candidateVM == nil {
		b.addGlobalPrecondition(RestorePlanPrecondition{
			Type: preconditionBackendStateCaptured, Status: PreconditionUnknown,
			Message: "candidate VM could not be generated; backend state handling cannot be resolved",
		})
		return
	}
	if candidateVM.Name == snapshotVM.Name {
		volumes, err := storageutils.GetVolumes(snapshotVM, p.ctrl.Client, storageutils.WithBackendVolume)
		status := PreconditionMet
		message := "VM reuses its existing TPM/EFI backend PVC"
		if err != nil {
			if storageutils.IsErrNoBackendPVC(err) {
				status = PreconditionUnknown
				message = "no backend PVC exists yet; a fresh empty one is created when the VM starts"
			} else {
				status = PreconditionUnknown
				message = err.Error()
			}
		} else if len(volumes) == 0 || volumes[0].PersistentVolumeClaim == nil {
			status = PreconditionUnknown
			message = "backend PVC cannot be resolved; a fresh empty one is created when the VM starts"
		}
		b.addAction(PlannedAction{
			ID:   actionID(PlannedActionAdopt, "backend-pvc", vmRestore.Spec.Target.Name),
			Verb: PlannedActionAdopt,
			Resource: PlannedResourceRef{
				APIVersion: corev1.SchemeGroupVersion.String(), Kind: "PersistentVolumeClaim",
				Namespace: vmRestore.Namespace,
			},
			BackendState: true,
			Preconditions: []RestorePlanPrecondition{{
				Type: preconditionBackendStatePVCResolvable, Status: status, Message: message,
			}, {
				Type: preconditionBackendStateCaptured, Status: PreconditionUnmet,
				Message: "backend storage volume was not included in the snapshot; TPM/EFI state is not carried over",
			}},
		})
		return
	}

	// Different target VM: restoreVirtualMachineState either requires volumeClaimTemplate or errors.
	vmState := snapshotVM.Spec.Template.Spec.VirtualMachineState
	status := PreconditionMet
	message := "target starts with a fresh, empty TPM/EFI state from volumeClaimTemplate"
	if vmState == nil || vmState.VolumeClaimTemplate == nil {
		status = PreconditionUnmet
		message = "cannot restore virtualMachineState to a different VM: backend volume wasn't included in the snapshot and no volumeClaimTemplate is set"
	}
	b.addAction(PlannedAction{
		ID:   actionID(PlannedActionSkip, "backend-pvc", vmRestore.Spec.Target.Name),
		Verb: PlannedActionSkip,
		Resource: PlannedResourceRef{
			APIVersion: corev1.SchemeGroupVersion.String(), Kind: "PersistentVolumeClaim",
			Namespace: vmRestore.Namespace,
		},
		BackendState: true,
		Preconditions: []RestorePlanPrecondition{{
			Type: preconditionBackendStateCaptured, Status: status, Message: message,
		}},
		Note: "no foreign VM may adopt the original backend PVC; fresh state is provisioned instead",
	})
}

// planBackendSourceRepoint verifies the candidate VM points virtualMachineState.source at the
// restored backend PVC, matching restoreVirtualMachineState.
func (p *ColdRestorePlanner) planBackendSourceRepoint(
	vmRestore *snapshotv1.VirtualMachineRestore,
	snapshotVM *snapshotv1.VirtualMachine,
	candidateVM *kubevirtv1.VirtualMachine,
	restores []snapshotv1.VolumeRestore,
	b *planBuilder,
) {
	if candidateVM == nil || candidateVM.Spec.Template.Spec.VirtualMachineState == nil {
		return
	}
	backendVolumeName := storageutils.BackendPVCVolumeName(snapshotVM.Name)
	for _, vr := range restores {
		if vr.VolumeName != backendVolumeName {
			continue
		}
		source := candidateVM.Spec.Template.Spec.VirtualMachineState.Source
		status := PreconditionMet
		message := fmt.Sprintf("virtualMachineState.source repointed to restore PVC %s", vr.PersistentVolumeClaimName)
		if source == nil || source.Name != vr.PersistentVolumeClaimName {
			status = PreconditionUnmet
			message = fmt.Sprintf("virtualMachineState.source must point at restore PVC %s", vr.PersistentVolumeClaimName)
		}
		b.addGlobalPrecondition(RestorePlanPrecondition{
			Type: preconditionBackendStateCaptured, Status: status, Message: message,
		})
		return
	}
}

// planControllerRevisionActions reproduces restoreInstancetypeControllerRevisions naming and
// sharing semantics.
func (p *ColdRestorePlanner) planControllerRevisionActions(
	vmRestore *snapshotv1.VirtualMachineRestore,
	target restoreTarget,
	snapshotVM *snapshotv1.VirtualMachine,
	candidateVM *kubevirtv1.VirtualMachine,
	b *planBuilder,
) {
	if candidateVM == nil {
		return
	}
	if candidateVM.Spec.Instancetype != nil {
		p.planControllerRevision(vmRestore, target, candidateVM.Spec.Instancetype.RevisionName, "instancetype", b)
	}
	if candidateVM.Spec.Preference != nil {
		p.planControllerRevision(vmRestore, target, candidateVM.Spec.Preference.RevisionName, "preference", b)
	}
}

func (p *ColdRestorePlanner) planControllerRevision(
	vmRestore *snapshotv1.VirtualMachineRestore,
	target restoreTarget,
	revisionName string,
	kind string,
	b *planBuilder,
) {
	if revisionName == "" {
		return
	}
	snapshotCR, err := p.getControllerRevisionForPreview(vmRestore.Namespace, revisionName)
	if err != nil {
		b.addAction(PlannedAction{
			ID:   actionID(PlannedActionSkip, "controllerrevision", revisionName),
			Verb: PlannedActionSkip,
			Resource: PlannedResourceRef{
				APIVersion: appsv1.SchemeGroupVersion.String(), Kind: "ControllerRevision",
				Namespace: vmRestore.Namespace, Name: revisionName,
			},
			Preconditions: []RestorePlanPrecondition{{
				Type: preconditionControllerRevisionPresent, Status: PreconditionUnmet, Message: err.Error(),
			}},
		})
		return
	}

	restoredCRName := strings.Replace(revisionName, vmRestore.Spec.VirtualMachineSnapshotName, vmRestore.Spec.Target.Name, 1)
	restoredCR := snapshotCR.DeepCopy()
	restoredCR.ObjectMeta.Reset()
	restoredCR.ObjectMeta.SetLabels(snapshotCR.Labels)
	restoredCR.Name = restoredCRName
	if target.Exists() {
		restoredCR.OwnerReferences = []metav1.OwnerReference{
			*metav1.NewControllerRef(target.VirtualMachine(), kubevirtv1.VirtualMachineGroupVersionKind),
		}
	}

	existingCR, err := p.getControllerRevisionForPreview(vmRestore.Namespace, restoredCRName)
	if err != nil && !k8serrors.IsNotFound(err) {
		b.addGlobalPrecondition(RestorePlanPrecondition{
			Type: preconditionControllerRevisionPresent, Status: PreconditionUnknown, Message: err.Error(),
		})
		return
	}
	if existingCR != nil {
		equal, compareErr := revision.Compare(snapshotCR, existingCR)
		if compareErr != nil {
			b.addGlobalPrecondition(RestorePlanPrecondition{
				Type: preconditionControllerRevisionPresent, Status: PreconditionUnknown, Message: compareErr.Error(),
			})
			return
		}
		if equal {
			b.addAction(PlannedAction{
				ID:   actionID(PlannedActionAdopt, "controllerrevision", restoredCRName),
				Verb: PlannedActionAdopt,
				Resource: PlannedResourceRef{
					APIVersion: appsv1.SchemeGroupVersion.String(), Kind: "ControllerRevision",
					Namespace: vmRestore.Namespace, Name: restoredCRName,
				},
				Preconditions: []RestorePlanPrecondition{{
					Type: preconditionControllerRevisionPresent, Status: PreconditionMet,
					Message: fmt.Sprintf("existing %s ControllerRevision already matches the snapshot revision", kind),
				}},
			})
			return
		}
		// ControllerRevisions are immutable, so the controller deletes and recreates. Refuse to
		// plan a delete against a revision owned by another VM, which would break that VM.
		status := PreconditionMet
		message := fmt.Sprintf("existing %s ControllerRevision differs and is replaced with the snapshot revision", kind)
		if owner := metav1.GetControllerOf(existingCR); owner != nil &&
			!(target.Exists() && owner.Kind == "VirtualMachine" && owner.UID == target.UID()) {
			status = PreconditionUnmet
			message = fmt.Sprintf("ControllerRevision %s is controlled by %s/%s and cannot be deleted for this restore",
				restoredCRName, owner.Kind, owner.Name)
		}
		deleteID := actionID(PlannedActionDelete, "controllerrevision", restoredCRName)
		b.addAction(PlannedAction{
			ID:   deleteID,
			Verb: PlannedActionDelete,
			Resource: PlannedResourceRef{
				APIVersion: appsv1.SchemeGroupVersion.String(), Kind: "ControllerRevision",
				Namespace: vmRestore.Namespace, Name: restoredCRName,
			},
			Preconditions: []RestorePlanPrecondition{{
				Type: preconditionControllerRevisionNotShared, Status: status, Message: message,
			}},
		})
		summary, _ := summarizeControllerRevision(restoredCR)
		b.addAction(PlannedAction{
			ID:   actionID(PlannedActionCreate, "controllerrevision", restoredCRName),
			Verb: PlannedActionCreate,
			Resource: PlannedResourceRef{
				APIVersion: appsv1.SchemeGroupVersion.String(), Kind: "ControllerRevision",
				Namespace: vmRestore.Namespace, Name: restoredCRName,
			},
			DependsOn:     []string{deleteID},
			Summary:       summary,
			Preconditions: []RestorePlanPrecondition{{Type: preconditionControllerRevisionPresent, Status: PreconditionMet, Message: "snapshot revision is available"}},
		})
		return
	}

	summary, _ := summarizeControllerRevision(restoredCR)
	b.addAction(PlannedAction{
		ID:   actionID(PlannedActionCreate, "controllerrevision", restoredCRName),
		Verb: PlannedActionCreate,
		Resource: PlannedResourceRef{
			APIVersion: appsv1.SchemeGroupVersion.String(), Kind: "ControllerRevision",
			Namespace: vmRestore.Namespace, Name: restoredCRName,
		},
		Summary: summary,
		Preconditions: []RestorePlanPrecondition{{
			Type: preconditionControllerRevisionPresent, Status: PreconditionMet,
			Message: fmt.Sprintf("snapshot %s ControllerRevision %s is present", kind, revisionName),
		}},
		Note: fmt.Sprintf("restored %s revision renamed from %s to %s", kind, revisionName, restoredCRName),
	})
}

// planControllerRevisionOwnershipActions emits the ownership claim that reconcileSpec performs
// only after the target VM itself has been created.
func (p *ColdRestorePlanner) planControllerRevisionOwnershipActions(
	vmRestore *snapshotv1.VirtualMachineRestore,
	target restoreTarget,
	candidateVM *kubevirtv1.VirtualMachine,
	b *planBuilder,
) {
	if candidateVM == nil || target.Exists() {
		return
	}
	claim := func(revisionName string) {
		if revisionName == "" {
			return
		}
		restoredCRName := strings.Replace(revisionName, vmRestore.Spec.VirtualMachineSnapshotName, vmRestore.Spec.Target.Name, 1)
		crCreateID := actionID(PlannedActionCreate, "controllerrevision", restoredCRName)
		vmCreateID := actionID(PlannedActionCreate, "vm", vmRestore.Spec.Target.Name)
		if !b.hasAction(crCreateID) || !b.hasAction(vmCreateID) {
			// Without the create actions there is nothing to claim ownership of; the snapshot CR
			// precondition already explains why the revision could not be planned.
			return
		}
		b.addAction(PlannedAction{
			ID:   actionID(PlannedActionUpdate, "controllerrevision", restoredCRName),
			Verb: PlannedActionUpdate,
			Resource: PlannedResourceRef{
				APIVersion: appsv1.SchemeGroupVersion.String(), Kind: "ControllerRevision",
				Namespace: vmRestore.Namespace, Name: restoredCRName,
			},
			DependsOn: []string{crCreateID, vmCreateID},
			Note:      "newly created VirtualMachine claims controller ownership of the revision",
		})
	}
	if candidateVM.Spec.Instancetype != nil {
		claim(candidateVM.Spec.Instancetype.RevisionName)
	}
	if candidateVM.Spec.Preference != nil {
		claim(candidateVM.Spec.Preference.RevisionName)
	}
}

func (p *ColdRestorePlanner) getControllerRevisionForPreview(namespace, name string) (*appsv1.ControllerRevision, error) {
	revisionKey := cacheKeyFunc(namespace, name)
	obj, exists, err := p.ctrl.CRInformer.GetStore().GetByKey(revisionKey)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, k8serrors.NewNotFound(appsv1.Resource("controllerrevisions"), name)
	}
	return obj.(*appsv1.ControllerRevision).DeepCopy(), nil
}

// planVMActions covers the target VM status transitions and the final spec create/update.
func (p *ColdRestorePlanner) planVMActions(
	vmRestore *snapshotv1.VirtualMachineRestore,
	target restoreTarget,
	candidateVM *kubevirtv1.VirtualMachine,
	b *planBuilder,
) {
	if candidateVM == nil {
		return
	}

	var dependsOn []string
	for _, action := range b.plan.Actions {
		if action.Resource.Kind == "PersistentVolumeClaim" ||
			action.Resource.Kind == "DataVolume" ||
			action.Resource.Kind == "ControllerRevision" {
			if action.Verb == PlannedActionCreate || action.Verb == PlannedActionUpdate ||
				action.Verb == PlannedActionPatch || action.Verb == PlannedActionDelete {
				dependsOn = append(dependsOn, action.ID)
			}
		}
	}

	if target.Exists() {
		// RestoreInProgress status bookkeeping, mirroring UpdateRestoreInProgress/UpdateDoneRestore.
		b.addAction(PlannedAction{
			ID:   actionID(PlannedActionUpdate, "vm-status-inprogress", target.VirtualMachine().Name),
			Verb: PlannedActionUpdate,
			Resource: PlannedResourceRef{
				APIVersion: kubevirtv1.GroupVersion.String(), Kind: "VirtualMachine",
				Namespace: target.VirtualMachine().Namespace, Name: target.VirtualMachine().Name, Subresource: "status",
			},
			Note: "sets status.restoreInProgress while the restore reconciles",
		})
		summary, _ := summarizeVirtualMachine(candidateVM)
		b.addAction(PlannedAction{
			ID:   actionID(PlannedActionUpdate, "vm", candidateVM.Name),
			Verb: PlannedActionUpdate,
			Resource: PlannedResourceRef{
				APIVersion: kubevirtv1.GroupVersion.String(), Kind: "VirtualMachine",
				Namespace: candidateVM.Namespace, Name: candidateVM.Name,
			},
			DependsOn:     dependsOn,
			Summary:       summary,
			Preconditions: []RestorePlanPrecondition{{Type: preconditionTargetNotColliding, Status: PreconditionMet, Message: "existing target VM is updated in place"}},
		})
		b.addAction(PlannedAction{
			ID:   actionID(PlannedActionUpdate, "vm-status-done", target.VirtualMachine().Name),
			Verb: PlannedActionUpdate,
			Resource: PlannedResourceRef{
				APIVersion: kubevirtv1.GroupVersion.String(), Kind: "VirtualMachine",
				Namespace: target.VirtualMachine().Namespace, Name: target.VirtualMachine().Name, Subresource: "status",
			},
			DependsOn: []string{actionID(PlannedActionUpdate, "vm", candidateVM.Name)},
			Note:      "clears status.restoreInProgress once the restore completed",
		})
		return
	}

	summary, _ := summarizeVirtualMachine(candidateVM)
	b.addAction(PlannedAction{
		ID:   actionID(PlannedActionCreate, "vm", candidateVM.Name),
		Verb: PlannedActionCreate,
		Resource: PlannedResourceRef{
			APIVersion: kubevirtv1.GroupVersion.String(), Kind: "VirtualMachine",
			Namespace: candidateVM.Namespace, Name: candidateVM.Name,
		},
		DependsOn: dependsOn,
		Summary:   summary,
		Preconditions: []RestorePlanPrecondition{{
			Type: preconditionTargetNotColliding, Status: PreconditionMet,
			Message: "target VirtualMachine does not exist and is created from the snapshot spec plus restore patches",
		}},
	})
}

// planPVCOwnershipActions mirrors updateRestorePVCOwnership for existing targets.
func (p *ColdRestorePlanner) planPVCOwnershipActions(
	vmRestore *snapshotv1.VirtualMachineRestore,
	target restoreTarget,
	candidateVM *kubevirtv1.VirtualMachine,
	b *planBuilder,
) {
	if isVolumeOwnershipPolicyNone(vmRestore) || !target.Exists() || candidateVM == nil {
		return
	}
	for _, volume := range candidateVM.Spec.Template.Spec.Volumes {
		if volume.PersistentVolumeClaim == nil {
			continue
		}
		pvcName := volume.PersistentVolumeClaim.ClaimName
		pvc, err := p.ctrl.getPVC(vmRestore.Namespace, pvcName)
		if err != nil {
			b.addGlobalPrecondition(RestorePlanPrecondition{
				Type: preconditionRestorePVCNameAvailable, Status: PreconditionUnknown,
				Message: fmt.Sprintf("cannot read PVC %s for ownership transfer: %v", pvcName, err),
			})
			continue
		}
		if pvc == nil || len(pvc.OwnerReferences) > 0 {
			continue
		}
		if pvc.Annotations[restoreOwnedByVMLabel] != vmRestore.Name {
			continue
		}
		b.addAction(PlannedAction{
			ID:   actionID(PlannedActionUpdate, "pvc-ownership", pvcName),
			Verb: PlannedActionUpdate,
			Resource: PlannedResourceRef{
				APIVersion: corev1.SchemeGroupVersion.String(), Kind: "PersistentVolumeClaim",
				Namespace: pvc.Namespace, Name: pvc.Name,
			},
			DependsOn: []string{actionID(PlannedActionUpdate, "vm", candidateVM.Name)},
			Preconditions: []RestorePlanPrecondition{{
				Type: preconditionRestorePVCNameAvailable, Status: PreconditionMet,
				Message: "unowned restore PVC is transferred to the restored VM",
			}},
			Note: "VolumeOwnershipPolicy=Vm: the restore annotation is replaced by a VM owner reference",
		})
	}
}

// planObsoleteResourceActions covers the deleteObsoleteVolumes phase: obsolete DataVolumes and
// garbage-collected original backend PVCs.
func (p *ColdRestorePlanner) planObsoleteResourceActions(
	vmRestore *snapshotv1.VirtualMachineRestore,
	target restoreTarget,
	candidateVM *kubevirtv1.VirtualMachine,
	b *planBuilder,
) {
	if !target.Exists() || candidateVM == nil {
		return
	}
	obsoleteDVs := findDatavolumesForDeletion(target.VirtualMachine().Spec.DataVolumeTemplates, candidateVM.Spec.DataVolumeTemplates)
	for _, dvName := range obsoleteDVs {
		objKey := cacheKeyFunc(vmRestore.Namespace, dvName)
		_, exists, err := p.ctrl.DataVolumeInformer.GetStore().GetByKey(objKey)
		if err != nil {
			b.addGlobalPrecondition(RestorePlanPrecondition{
				Type: preconditionDataVolumeReady, Status: PreconditionUnknown, Message: err.Error(),
			})
			continue
		}
		if !exists {
			continue
		}
		b.addAction(PlannedAction{
			ID:   actionID(PlannedActionDelete, "dv", dvName),
			Verb: PlannedActionDelete,
			Resource: PlannedResourceRef{
				APIVersion: cdiv1.SchemeGroupVersion.String(), Kind: "DataVolume",
				Namespace: vmRestore.Namespace, Name: dvName,
			},
			DependsOn: []string{actionID(PlannedActionUpdate, "vm", candidateVM.Name)},
			Note:      "DataVolume no longer referenced by the restored spec is deleted",
		})
	}

	if !backendstorage.IsBackendStorageNeeded(target.VirtualMachine()) {
		return
	}
	pvcs, err := p.ctrl.Client.CoreV1().PersistentVolumeClaims(vmRestore.Namespace).List(context.Background(), metav1.ListOptions{
		LabelSelector: fmt.Sprintf("%s=%s", restoreCleanupBackendPVCLabel, getCleanupLabelValue(vmRestore)),
	})
	if err != nil {
		b.addGlobalPrecondition(RestorePlanPrecondition{
			Type: preconditionBackendStatePVCResolvable, Status: PreconditionUnknown, Message: err.Error(),
		})
		return
	}
	for i := range pvcs.Items {
		pvc := &pvcs.Items[i]
		// Source-adopted PVCs are not controller-owned and must not be deleted.
		if !backendstorage.IsControllerOwnedPVC(pvc) {
			b.addAction(PlannedAction{
				ID:   actionID(PlannedActionAdopt, "backend-pvc-source", pvc.Name),
				Verb: PlannedActionAdopt,
				Resource: PlannedResourceRef{
					APIVersion: corev1.SchemeGroupVersion.String(), Kind: "PersistentVolumeClaim",
					Namespace: pvc.Namespace, Name: pvc.Name,
				},
				BackendState: true,
				Note:         "source-adopted backend PVC is kept, not garbage-collected",
			})
			continue
		}
		b.addAction(PlannedAction{
			ID:   actionID(PlannedActionDelete, "backend-pvc", pvc.Name),
			Verb: PlannedActionDelete,
			Resource: PlannedResourceRef{
				APIVersion: corev1.SchemeGroupVersion.String(), Kind: "PersistentVolumeClaim",
				Namespace: pvc.Namespace, Name: pvc.Name,
			},
			BackendState: true,
			DependsOn:    []string{actionID(PlannedActionUpdate, "vm", candidateVM.Name)},
			Preconditions: []RestorePlanPrecondition{{
				Type: preconditionBackendStateCaptured, Status: PreconditionMet,
				Message: "controller-owned original TPM/EFI backend PVC is garbage-collected after the relabel",
			}},
		})
	}
}

// ApplyColdRestorePlan re-validates every fingerprint and precondition against the live caches
// and then creates the VirtualMachineRestore through the regular API. It never bypasses the
// controller's finalizer/state machine and never creates PVCs or any other resource directly.
func (p *ColdRestorePlanner) ApplyColdRestorePlan(ctx context.Context, plan *ColdRestorePlan) (*snapshotv1.VirtualMachineRestore, error) {
	if plan == nil {
		return nil, fmt.Errorf("cannot apply a nil plan")
	}

	storeObj, exists, err := p.ctrl.VMRestoreInformer.GetStore().GetByKey(
		cacheKeyFunc(plan.Inputs.RestoreNamespace, plan.Inputs.RestoreName))
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, fmt.Errorf("VirtualMachineRestore %s no longer exists; build a new plan before applying", plan.Inputs.RestoreName)
	}
	liveRestore := storeObj.(*snapshotv1.VirtualMachineRestore).DeepCopy()

	fresh, err := p.PreviewColdRestorePlan(ctx, liveRestore)
	if err != nil {
		return nil, fmt.Errorf("failed to re-evaluate the plan before apply: %w", err)
	}
	if fresh.Phase != ColdRestorePlanReady {
		return nil, fmt.Errorf("refusing to apply plan in phase %s: %v", fresh.Phase, fresh.Reasons)
	}
	if fresh.Inputs.RestoreUID != plan.Inputs.RestoreUID ||
		fresh.Inputs.RestoreResourceVersion != plan.Inputs.RestoreResourceVersion ||
		fresh.Inputs.ContentDigest != plan.Inputs.ContentDigest ||
		fresh.Inputs.TargetUID != plan.Inputs.TargetUID ||
		fresh.Inputs.TargetResourceVersion != plan.Inputs.TargetResourceVersion ||
		fresh.Inputs.TargetSpecDigest != plan.Inputs.TargetSpecDigest {
		return nil, fmt.Errorf("plan inputs changed since preview; regenerate the plan before applying")
	}

	// Refuse to proceed if any PVC the submitted plan expected to create has appeared externally.
	// The submitted plan is authoritative here: a re-planned adopt action must not silently turn an
	// external PVC into something the restore owns.
	for _, action := range plan.Actions {
		if action.Resource.Kind != "PersistentVolumeClaim" || action.Verb != PlannedActionCreate {
			continue
		}
		existingPVC, getErr := p.ctrl.getPVC(action.Resource.Namespace, action.Resource.Name)
		if getErr != nil {
			return nil, getErr
		}
		if existingPVC != nil {
			return nil, fmt.Errorf("restore PVC %s/%s already exists; refusing to adopt an externally created PVC",
				action.Resource.Namespace, action.Resource.Name)
		}
	}

	// Hand the object to the normal restore API path. The controller adds the finalizer and owns
	// every subsequent write through its existing state machine.
	if _, err := p.ctrl.Client.VirtualMachineRestore(liveRestore.Namespace).Get(ctx, liveRestore.Name, metav1.GetOptions{}); err == nil {
		return nil, fmt.Errorf("VirtualMachineRestore %s/%s is already submitted", liveRestore.Namespace, liveRestore.Name)
	} else if !k8serrors.IsNotFound(err) {
		return nil, err
	}
	return p.ctrl.Client.VirtualMachineRestore(liveRestore.Namespace).Create(ctx, liveRestore, metav1.CreateOptions{})
}

// --- plan builder helpers ---

func (b *planBuilder) addAction(action PlannedAction) {
	if b.truncated {
		return
	}
	if b.actionCount >= b.planner.limits.MaxActions {
		b.truncated = true
		b.plan.Truncated = true
		return
	}
	b.plan.Actions = append(b.plan.Actions, action)
	b.actionCount++
}

func (b *planBuilder) addGlobalPrecondition(precondition RestorePlanPrecondition) {
	b.plan.Preconditions = append(b.plan.Preconditions, precondition)
}

func (b *planBuilder) hasAction(id string) bool {
	for _, action := range b.plan.Actions {
		if action.ID == id {
			return true
		}
	}
	return false
}

// finalizePhase aggregates action- and plan-level preconditions into the overall plan verdict.
func (b *planBuilder) finalizePhase() {
	hasUnsupported := false
	hasUnmet := false
	hasUnknown := false
	consider := func(preconditions []RestorePlanPrecondition) {
		for _, precondition := range preconditions {
			switch precondition.Status {
			case PreconditionUnmet:
				if precondition.Type == preconditionTargetPoweredOff ||
					precondition.Type == preconditionMemoryStateNotRestored {
					hasUnsupported = true
				} else {
					hasUnmet = true
				}
			case PreconditionUnknown:
				hasUnknown = true
			}
		}
	}
	consider(b.plan.Preconditions)
	for i := range b.plan.Actions {
		consider(b.plan.Actions[i].Preconditions)
	}

	switch {
	case hasUnsupported:
		b.plan.Phase = ColdRestorePlanUnsupported
	case hasUnmet:
		b.plan.Phase = ColdRestorePlanBlocked
	case hasUnknown:
		b.plan.Phase = ColdRestorePlanUnknown
	default:
		b.plan.Phase = ColdRestorePlanReady
	}

	b.plan.Reasons = b.plan.Reasons[:0]
	for _, precondition := range b.plan.Preconditions {
		if precondition.Status != PreconditionMet {
			b.plan.Reasons = append(b.plan.Reasons, fmt.Sprintf("%s: %s", precondition.Type, precondition.Message))
		}
	}
	for i := range b.plan.Actions {
		for _, precondition := range b.plan.Actions[i].Preconditions {
			if precondition.Status != PreconditionMet {
				b.plan.Reasons = append(b.plan.Reasons,
					fmt.Sprintf("%s (%s/%s): %s", precondition.Type, b.plan.Actions[i].Resource.Kind, b.plan.Actions[i].Resource.Name, precondition.Message))
			}
		}
	}
}

// validateDAG guarantees every dependency exists, points backwards and there are no cycles.
func (b *planBuilder) validateDAG() error {
	index := make(map[string]int, len(b.plan.Actions))
	for i, action := range b.plan.Actions {
		if _, duplicated := index[action.ID]; duplicated {
			return fmt.Errorf("duplicate planned action ID %s", action.ID)
		}
		index[action.ID] = i
	}
	for i, action := range b.plan.Actions {
		for _, dependency := range action.DependsOn {
			depIndex, ok := index[dependency]
			if !ok {
				return fmt.Errorf("action %s depends on unknown action %s", action.ID, dependency)
			}
			if depIndex >= i {
				return fmt.Errorf("action %s depends on later action %s; DAG must be topologically ordered", action.ID, dependency)
			}
		}
	}
	return nil
}

// enforceBudgets shrinks summaries before giving up on actions, then re-checks serialized size.
func (b *planBuilder) enforceBudgets() (*ColdRestorePlan, error) {
	rendered, err := json.Marshal(b.plan)
	if err != nil {
		return nil, err
	}
	if len(rendered) <= b.planner.limits.MaxOutputBytes {
		return b.plan, nil
	}

	// Drop raw patch payloads and verbose labels first; digests always remain.
	for i := range b.plan.Actions {
		if b.plan.Actions[i].Summary != nil {
			b.plan.Actions[i].Summary.PatchBytes = nil
			b.plan.Actions[i].Summary.Labels = nil
			b.plan.Actions[i].Summary.AnnotationKeys = nil
			b.plan.Actions[i].Summary.OwnerReferences = nil
		}
	}
	if b.plan.CandidateVM != nil {
		b.plan.CandidateVM.Labels = nil
		b.plan.CandidateVM.AnnotationKeys = nil
		b.plan.CandidateVM.OwnerReferences = nil
		b.plan.CandidateVM.Sensitive = nil
	}
	rendered, err = json.Marshal(b.plan)
	if err != nil {
		return nil, err
	}
	if len(rendered) <= b.planner.limits.MaxOutputBytes {
		b.plan.Truncated = true
		return b.plan, nil
	}
	b.plan.Truncated = true
	return b.plan, nil
}

// --- summarization helpers ---

func digestOf(obj interface{}) (string, error) {
	marshalled, err := json.Marshal(obj)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(marshalled)
	return hex.EncodeToString(sum[:]), nil
}

func shortDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])[:maxSensitiveDigestLength]
}

func patchSummary(payload []byte, err error) *PlannedObjectSummary {
	summary := &PlannedObjectSummary{}
	if err != nil {
		summary.SpecDigest = ""
		return summary
	}
	summary.ByteSize = len(payload)
	summary.PatchBytes = payload
	summary.PatchDigest = shortDigest(payload)
	var decoded []map[string]interface{}
	if jsonErr := json.Unmarshal(payload, &decoded); jsonErr == nil {
		summary.PatchOpCount = len(decoded)
	}
	if len(payload) > maxPlannedPatchBytes {
		summary.PatchBytes = nil
	}
	return summary
}

func summarizePVC(pvc *corev1.PersistentVolumeClaim) (*PlannedObjectSummary, error) {
	marshalled, err := json.Marshal(pvc)
	if err != nil {
		return nil, err
	}
	digest, err := digestOf(pvc)
	if err != nil {
		return nil, err
	}
	return &PlannedObjectSummary{
		ByteSize:        len(marshalled),
		SpecDigest:      digest,
		Labels:          mapsClone(pvc.Labels),
		AnnotationKeys:  mapKeys(pvc.Annotations),
		OwnerReferences: append([]metav1.OwnerReference(nil), pvc.OwnerReferences...),
	}, nil
}

func summarizeControllerRevision(cr *appsv1.ControllerRevision) (*PlannedObjectSummary, error) {
	marshalled, err := json.Marshal(cr)
	if err != nil {
		return nil, err
	}
	digest, err := digestOf(cr)
	if err != nil {
		return nil, err
	}
	return &PlannedObjectSummary{
		ByteSize:        len(marshalled),
		SpecDigest:      digest,
		Labels:          mapsClone(cr.Labels),
		AnnotationKeys:  mapKeys(cr.Annotations),
		OwnerReferences: append([]metav1.OwnerReference(nil), cr.OwnerReferences...),
	}, nil
}

// summarizeVirtualMachine redacts every sensitive payload: inline cloud-init data is reduced to
// digests and only secret names are kept. The full candidate spec is represented by its digest.
func summarizeVirtualMachine(vm *kubevirtv1.VirtualMachine) (*PlannedObjectSummary, error) {
	marshalled, err := json.Marshal(vm)
	if err != nil {
		return nil, err
	}
	digest, err := digestOf(vm.Spec)
	if err != nil {
		return nil, err
	}
	summary := &PlannedObjectSummary{
		ByteSize:        len(marshalled),
		SpecDigest:      digest,
		Labels:          mapsClone(vm.Labels),
		AnnotationKeys:  mapKeys(vm.Annotations),
		OwnerReferences: append([]metav1.OwnerReference(nil), vm.OwnerReferences...),
	}
	if vm.Spec.Template != nil {
		for _, volume := range vm.Spec.Template.Spec.Volumes {
			collectSensitiveVolume(volume, summary)
		}
	}
	return summary, nil
}

func collectSensitiveVolume(volume kubevirtv1.Volume, summary *PlannedObjectSummary) {
	if noCloud := volume.CloudInitNoCloud; noCloud != nil {
		if noCloud.UserData != "" {
			summary.Sensitive = append(summary.Sensitive, SensitiveReference{
				Kind: "CloudInitNoCloud/userData", Name: volume.Name, FieldDigest: shortDigest([]byte(noCloud.UserData)),
			})
		}
		if noCloud.NetworkData != "" {
			summary.Sensitive = append(summary.Sensitive, SensitiveReference{
				Kind: "CloudInitNoCloud/networkData", Name: volume.Name, FieldDigest: shortDigest([]byte(noCloud.NetworkData)),
			})
		}
		if noCloud.UserDataSecretRef != nil {
			summary.Sensitive = append(summary.Sensitive, SensitiveReference{
				Kind: "Secret", Name: noCloud.UserDataSecretRef.Name,
			})
		}
		if noCloud.NetworkDataSecretRef != nil {
			summary.Sensitive = append(summary.Sensitive, SensitiveReference{
				Kind: "Secret", Name: noCloud.NetworkDataSecretRef.Name,
			})
		}
	}
	if configDrive := volume.CloudInitConfigDrive; configDrive != nil {
		if configDrive.UserData != "" {
			summary.Sensitive = append(summary.Sensitive, SensitiveReference{
				Kind: "CloudInitConfigDrive/userData", Name: volume.Name, FieldDigest: shortDigest([]byte(configDrive.UserData)),
			})
		}
		if configDrive.NetworkData != "" {
			summary.Sensitive = append(summary.Sensitive, SensitiveReference{
				Kind: "CloudInitConfigDrive/networkData", Name: volume.Name, FieldDigest: shortDigest([]byte(configDrive.NetworkData)),
			})
		}
		if configDrive.UserDataSecretRef != nil {
			summary.Sensitive = append(summary.Sensitive, SensitiveReference{
				Kind: "Secret", Name: configDrive.UserDataSecretRef.Name,
			})
		}
		if configDrive.NetworkDataSecretRef != nil {
			summary.Sensitive = append(summary.Sensitive, SensitiveReference{
				Kind: "Secret", Name: configDrive.NetworkDataSecretRef.Name,
			})
		}
	}
	if secretVolume := volume.Secret; secretVolume != nil {
		summary.Sensitive = append(summary.Sensitive, SensitiveReference{
			Kind: "Secret", Name: secretVolume.SecretName,
		})
	}
}

func mapsClone(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func mapKeys(in map[string]string) []string {
	if len(in) == 0 {
		return nil
	}
	keys := make([]string, 0, len(in))
	for k := range in {
		keys = append(keys, k)
	}
	return keys
}

func ptrString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func actionID(verb PlannedActionVerb, kind, name string) string {
	return fmt.Sprintf("%s-%s-%s", verb, kind, name)
}
