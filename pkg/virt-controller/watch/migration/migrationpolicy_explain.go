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

package migration

import (
	"fmt"
	"reflect"
	"sort"

	k8sv1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"

	k6tv1 "kubevirt.io/api/core/v1"
	"kubevirt.io/api/migrations/v1alpha1"
)

// Bounds keep the explanation output proportional to the explicitly requested
// target set instead of the whole cluster.
const (
	MaxExplainMigrationTargets  = 32
	MaxExplainMigrationPolicies = 64
)

// Stable ordering ranks for policy entries inside one VMI explanation.
const (
	matchOutcomeRankSelected = iota
	matchOutcomeRankShadowed
	matchOutcomeRankOther
)

// MigrationPolicyFieldSource identifies where the effective value of a resolved
// migration option came from.
type MigrationPolicyFieldSource string

const (
	// FieldSourceClusterDefault means the selected policy leaves the field
	// unset (nil) and the value is inherited from the cluster configuration.
	FieldSourceClusterDefault MigrationPolicyFieldSource = "cluster-default"
	// FieldSourcePolicyOverride means the policy explicitly sets the field.
	// An explicit false or zero value is reported as an override and is
	// distinguished from a nil field (which inherits the cluster default).
	FieldSourcePolicyOverride MigrationPolicyFieldSource = "policy-override"
	// FieldSourcePostCopyFallback applies only to allowWorkloadDisruption:
	// the policy leaves it unset but specifies allowPostCopy, so the real
	// applyMigrationPolicySpec backward-compatibility shim derives
	// allowWorkloadDisruption from allowPostCopy.
	FieldSourcePostCopyFallback MigrationPolicyFieldSource = "postcopy-fallback"
)

// MigrationPolicyMatchOutcome classifies a single policy against one VMI.
type MigrationPolicyMatchOutcome string

const (
	// MatchOutcomeSelected is the policy that matchPolicy effectively applies.
	MatchOutcomeSelected MigrationPolicyMatchOutcome = "selected"
	// MatchOutcomeShadowed means the policy matches but loses precedence,
	// either on the two-dimensional label score or on the lexicographic
	// name tie-break.
	MatchOutcomeShadowed MigrationPolicyMatchOutcome = "shadowed"
	// MatchOutcomeUnmatched means at least one selector requirement is not
	// satisfied, as reported by countMatchingLabels.
	MatchOutcomeUnmatched MigrationPolicyMatchOutcome = "unmatched"
	// MatchOutcomeNotPresent marks a policy that exists in the other
	// snapshot of a comparison but not in this one.
	MatchOutcomeNotPresent MigrationPolicyMatchOutcome = "not-present"
)

// MigrationPolicyShadowReason explains why a matching policy was not selected.
type MigrationPolicyShadowReason string

const (
	ShadowReasonNone                  MigrationPolicyShadowReason = ""
	ShadowReasonLowerScore            MigrationPolicyShadowReason = "lower-score"
	ShadowReasonLexicographicTieBreak MigrationPolicyShadowReason = "lexicographic-tie-break"
)

// MigrationPolicyScoreExplanation is the two-dimensional label score returned
// verbatim by the real countMatchingLabels path.
type MigrationPolicyScoreExplanation struct {
	MatchingVMILabels       int `json:"matchingVMILabels"`
	MatchingNamespaceLabels int `json:"matchingNamespaceLabels"`
	// Total is the sum of both dimensions; it is the first comparison key
	// used by migrationPolicyMatchScore.greaterThan.
	Total int `json:"total"`
}

// MigrationPolicyMatchExplanation describes one policy against one VMI.
// It intentionally carries no label keys or values: label content can be
// sensitive and only the counts are needed to explain precedence.
type MigrationPolicyMatchExplanation struct {
	PolicyName string                          `json:"policyName"`
	Matched    bool                            `json:"matched"`
	Outcome    MigrationPolicyMatchOutcome     `json:"outcome"`
	Score      MigrationPolicyScoreExplanation `json:"score"`
	// ShadowReason is empty unless Outcome is MatchOutcomeShadowed.
	ShadowReason MigrationPolicyShadowReason `json:"shadowReason,omitempty"`
}

// MigrationPolicyFieldExplanation attributes the effective value of one leaf
// option to its source. Nested experimental options keep leaf granularity,
// e.g. experimental.stallDetector.stallMargin.
type MigrationPolicyFieldExplanation struct {
	FieldPath string                     `json:"fieldPath"`
	Source    MigrationPolicyFieldSource `json:"source"`
	// PolicyExplicitlySet is true when the matched policy spec carries a
	// non-nil value at this path. Explicit false/0 therefore stays
	// distinguishable from nil (cluster inheritance).
	PolicyExplicitlySet bool `json:"policyExplicitlySet"`
}

// MigrationPolicyVMIExplanation is the per-VMI section of the report.
type MigrationPolicyVMIExplanation struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	// SelectedPolicyName is empty when no policy matches the VMI.
	SelectedPolicyName string `json:"selectedPolicyName,omitempty"`
	// Policies is stably ordered: selected first, then shadowed policies by
	// descending score, then unmatched policies, each group by policy name.
	Policies []MigrationPolicyMatchExplanation `json:"policies"`
	// Fields covers every leaf that applyMigrationPolicySpec can touch.
	Fields []MigrationPolicyFieldExplanation `json:"fields"`
	// ResolvedOptions is produced by the real applyMigrationPolicySpec path
	// (or a deep copy of the cluster defaults when nothing matches).
	ResolvedOptions *k6tv1.VMIMConfigurationOptions `json:"resolvedOptions"`
}

// MigrationPolicyExplanationReport is the bounded, read-only explanation of
// how migration policies resolve on the explicitly provided VMI set. It only
// describes this set; it makes no claim about shadowing for VMIs or label
// combinations that were not supplied.
type MigrationPolicyExplanationReport struct {
	VMIs []MigrationPolicyVMIExplanation `json:"vmis"`
	// Comparison is populated only when BaselinePolicies is supplied.
	Comparison *MigrationPolicyComparison `json:"comparison,omitempty"`
}

// MigrationPolicyOutcomeSnapshot is one side of an outcome comparison.
type MigrationPolicyOutcomeSnapshot struct {
	Present bool                        `json:"present"`
	Outcome MigrationPolicyMatchOutcome `json:"outcome,omitempty"`
}

// MigrationPolicyOutcomeChange records a policy whose presence or match
// outcome differs between the two policy snapshots.
type MigrationPolicyOutcomeChange struct {
	PolicyName string                         `json:"policyName"`
	Baseline   MigrationPolicyOutcomeSnapshot `json:"baseline"`
	Candidate  MigrationPolicyOutcomeSnapshot `json:"candidate"`
}

// MigrationPolicyFieldChange records a resolved leaf value that differs
// between the two policy snapshots.
type MigrationPolicyFieldChange struct {
	FieldPath      string `json:"fieldPath"`
	BaselineValue  any    `json:"baselineValue,omitempty"`
	CandidateValue any    `json:"candidateValue,omitempty"`
}

// MigrationPolicyVMIComparison compares baseline and candidate policy
// snapshots for one VMI.
type MigrationPolicyVMIComparison struct {
	Namespace               string                         `json:"namespace"`
	Name                    string                         `json:"name"`
	BaselineSelectedPolicy  string                         `json:"baselineSelectedPolicy,omitempty"`
	CandidateSelectedPolicy string                         `json:"candidateSelectedPolicy,omitempty"`
	SelectedPolicyChanged   bool                           `json:"selectedPolicyChanged"`
	PolicyOutcomeChanges    []MigrationPolicyOutcomeChange `json:"policyOutcomeChanges,omitempty"`
	FieldChanges            []MigrationPolicyFieldChange   `json:"fieldChanges,omitempty"`
}

// MigrationPolicyComparison holds per-VMI diffs between two policy snapshots.
type MigrationPolicyComparison struct {
	VMIs []MigrationPolicyVMIComparison `json:"vmis"`
}

// ExplainMigrationTarget is one fixed VMI together with the namespace object
// whose labels participate in matching. Namespace may be nil, in which case
// nil-label-map semantics of the real functions apply.
type ExplainMigrationTarget struct {
	VMI       *k6tv1.VirtualMachineInstance
	Namespace *k8sv1.Namespace
}

// ExplainMigrationPoliciesInput is a read-only snapshot. Nothing is fetched
// from the cluster, updated or migrated while explaining.
type ExplainMigrationPoliciesInput struct {
	Targets         []ExplainMigrationTarget
	Policies        *v1alpha1.MigrationPolicyList
	ClusterDefaults *k6tv1.VMIMConfigurationOptions
	// BaselinePolicies is optional. When set, the report additionally
	// compares baseline versus Policies on the same target set.
	BaselinePolicies *v1alpha1.MigrationPolicyList
}

// migrationPolicyFieldLeaf describes one option leaf that can be attributed.
// specExplicitlySet and optionsValue only read pointers; they never mutate.
type migrationPolicyFieldLeaf struct {
	path              string
	specExplicitlySet func(spec *v1alpha1.MigrationPolicySpec) bool
	optionsValue      func(opts *k6tv1.VMIMConfigurationOptions) any
}

func ptrValue[T any](p *T) any {
	if p == nil {
		return nil
	}
	return *p
}

func experimentalSpecSet[T any](spec *v1alpha1.MigrationPolicySpec, get func(*k6tv1.ExperimentalMigrationOptions) *T) bool {
	if spec.ExperimentalMigrationOptions == nil {
		return false
	}
	return get(spec.ExperimentalMigrationOptions) != nil
}

func stallSpecSet[T any](spec *v1alpha1.MigrationPolicySpec, get func(*k6tv1.StallDetectorOptions) *T) bool {
	if spec.ExperimentalMigrationOptions == nil || spec.ExperimentalMigrationOptions.StallDetector == nil {
		return false
	}
	return get(spec.ExperimentalMigrationOptions.StallDetector) != nil
}

func downtimeSpecSet[T any](spec *v1alpha1.MigrationPolicySpec, get func(*k6tv1.DowntimeTuningOptions) *T) bool {
	if spec.ExperimentalMigrationOptions == nil || spec.ExperimentalMigrationOptions.DowntimeTuning == nil {
		return false
	}
	return get(spec.ExperimentalMigrationOptions.DowntimeTuning) != nil
}

func experimentalOptionsValue[T any](opts *k6tv1.VMIMConfigurationOptions, get func(*k6tv1.ExperimentalMigrationOptions) *T) any {
	if opts.ExperimentalMigrationOptions == nil {
		return nil
	}
	return ptrValue(get(opts.ExperimentalMigrationOptions))
}

func stallOptionsValue[T any](opts *k6tv1.VMIMConfigurationOptions, get func(*k6tv1.StallDetectorOptions) *T) any {
	if opts.ExperimentalMigrationOptions == nil || opts.ExperimentalMigrationOptions.StallDetector == nil {
		return nil
	}
	return ptrValue(get(opts.ExperimentalMigrationOptions.StallDetector))
}

func downtimeOptionsValue[T any](opts *k6tv1.VMIMConfigurationOptions, get func(*k6tv1.DowntimeTuningOptions) *T) any {
	if opts.ExperimentalMigrationOptions == nil || opts.ExperimentalMigrationOptions.DowntimeTuning == nil {
		return nil
	}
	return ptrValue(get(opts.ExperimentalMigrationOptions.DowntimeTuning))
}

// migrationPolicyFieldLeaves enumerates every leaf reachable through
// applyMigrationPolicySpec, including field-granular experimental options.
var migrationPolicyFieldLeaves = []migrationPolicyFieldLeaf{
	{
		path:              "allowAutoConverge",
		specExplicitlySet: func(spec *v1alpha1.MigrationPolicySpec) bool { return spec.AllowAutoConverge != nil },
		optionsValue:      func(opts *k6tv1.VMIMConfigurationOptions) any { return ptrValue(opts.AllowAutoConverge) },
	},
	{
		path:              "bandwidthPerMigration",
		specExplicitlySet: func(spec *v1alpha1.MigrationPolicySpec) bool { return spec.BandwidthPerMigration != nil },
		optionsValue:      func(opts *k6tv1.VMIMConfigurationOptions) any { return ptrValue(opts.BandwidthPerMigration) },
	},
	{
		path:              "completionTimeoutPerGiB",
		specExplicitlySet: func(spec *v1alpha1.MigrationPolicySpec) bool { return spec.CompletionTimeoutPerGiB != nil },
		optionsValue:      func(opts *k6tv1.VMIMConfigurationOptions) any { return ptrValue(opts.CompletionTimeoutPerGiB) },
	},
	{
		path:              "maxDowntimeMs",
		specExplicitlySet: func(spec *v1alpha1.MigrationPolicySpec) bool { return spec.MaxDowntimeMs != nil },
		optionsValue:      func(opts *k6tv1.VMIMConfigurationOptions) any { return ptrValue(opts.MaxDowntimeMs) },
	},
	{
		path:              "allowPostCopy",
		specExplicitlySet: func(spec *v1alpha1.MigrationPolicySpec) bool { return spec.AllowPostCopy != nil },
		optionsValue:      func(opts *k6tv1.VMIMConfigurationOptions) any { return ptrValue(opts.AllowPostCopy) },
	},
	{
		path:              "allowWorkloadDisruption",
		specExplicitlySet: func(spec *v1alpha1.MigrationPolicySpec) bool { return spec.AllowWorkloadDisruption != nil },
		optionsValue:      func(opts *k6tv1.VMIMConfigurationOptions) any { return ptrValue(opts.AllowWorkloadDisruption) },
	},
	{
		path: "experimental.compression",
		specExplicitlySet: func(spec *v1alpha1.MigrationPolicySpec) bool {
			return experimentalSpecSet(spec, func(e *k6tv1.ExperimentalMigrationOptions) *k6tv1.MigrationCompression { return e.Compression })
		},
		optionsValue: func(opts *k6tv1.VMIMConfigurationOptions) any {
			return experimentalOptionsValue(opts, func(e *k6tv1.ExperimentalMigrationOptions) *k6tv1.MigrationCompression { return e.Compression })
		},
	},
	{
		path: "experimental.stallDetector.stallMargin",
		specExplicitlySet: func(spec *v1alpha1.MigrationPolicySpec) bool {
			return stallSpecSet(spec, func(s *k6tv1.StallDetectorOptions) *int64 { return s.StallMargin })
		},
		optionsValue: func(opts *k6tv1.VMIMConfigurationOptions) any {
			return stallOptionsValue(opts, func(s *k6tv1.StallDetectorOptions) *int64 { return s.StallMargin })
		},
	},
	{
		path: "experimental.stallDetector.ewmaAlpha",
		specExplicitlySet: func(spec *v1alpha1.MigrationPolicySpec) bool {
			return stallSpecSet(spec, func(s *k6tv1.StallDetectorOptions) *resource.Quantity { return s.EwmaAlpha })
		},
		optionsValue: func(opts *k6tv1.VMIMConfigurationOptions) any {
			return stallOptionsValue(opts, func(s *k6tv1.StallDetectorOptions) *resource.Quantity { return s.EwmaAlpha })
		},
	},
	{
		path: "experimental.stallDetector.stallProgressTimeout",
		specExplicitlySet: func(spec *v1alpha1.MigrationPolicySpec) bool {
			return stallSpecSet(spec, func(s *k6tv1.StallDetectorOptions) *int64 { return s.StallProgressTimeout })
		},
		optionsValue: func(opts *k6tv1.VMIMConfigurationOptions) any {
			return stallOptionsValue(opts, func(s *k6tv1.StallDetectorOptions) *int64 { return s.StallProgressTimeout })
		},
	},
	{
		path: "experimental.stallDetector.switchoverTimeout",
		specExplicitlySet: func(spec *v1alpha1.MigrationPolicySpec) bool {
			return stallSpecSet(spec, func(s *k6tv1.StallDetectorOptions) *int64 { return s.SwitchoverTimeout })
		},
		optionsValue: func(opts *k6tv1.VMIMConfigurationOptions) any {
			return stallOptionsValue(opts, func(s *k6tv1.StallDetectorOptions) *int64 { return s.SwitchoverTimeout })
		},
	},
	{
		path: "experimental.stallDetector.precopyPossibleFactor",
		specExplicitlySet: func(spec *v1alpha1.MigrationPolicySpec) bool {
			return stallSpecSet(spec, func(s *k6tv1.StallDetectorOptions) *resource.Quantity { return s.PrecopyPossibleFactor })
		},
		optionsValue: func(opts *k6tv1.VMIMConfigurationOptions) any {
			return stallOptionsValue(opts, func(s *k6tv1.StallDetectorOptions) *resource.Quantity { return s.PrecopyPossibleFactor })
		},
	},
	{
		path: "experimental.stallDetector.patienceWindowDecayFactor",
		specExplicitlySet: func(spec *v1alpha1.MigrationPolicySpec) bool {
			return stallSpecSet(spec, func(s *k6tv1.StallDetectorOptions) *resource.Quantity { return s.PatienceWindowDecayFactor })
		},
		optionsValue: func(opts *k6tv1.VMIMConfigurationOptions) any {
			return stallOptionsValue(opts, func(s *k6tv1.StallDetectorOptions) *resource.Quantity { return s.PatienceWindowDecayFactor })
		},
	},
	{
		path: "experimental.stallDetector.searchLocalMinima",
		specExplicitlySet: func(spec *v1alpha1.MigrationPolicySpec) bool {
			return stallSpecSet(spec, func(s *k6tv1.StallDetectorOptions) *bool { return s.SearchLocalMinima })
		},
		optionsValue: func(opts *k6tv1.VMIMConfigurationOptions) any {
			return stallOptionsValue(opts, func(s *k6tv1.StallDetectorOptions) *bool { return s.SearchLocalMinima })
		},
	},
	{
		path: "experimental.stallDetector.completionTimeoutFactor",
		specExplicitlySet: func(spec *v1alpha1.MigrationPolicySpec) bool {
			return stallSpecSet(spec, func(s *k6tv1.StallDetectorOptions) *resource.Quantity { return s.CompletionTimeoutFactor })
		},
		optionsValue: func(opts *k6tv1.VMIMConfigurationOptions) any {
			return stallOptionsValue(opts, func(s *k6tv1.StallDetectorOptions) *resource.Quantity { return s.CompletionTimeoutFactor })
		},
	},
	{
		path: "experimental.downtimeTuning.initialMs",
		specExplicitlySet: func(spec *v1alpha1.MigrationPolicySpec) bool {
			return downtimeSpecSet(spec, func(d *k6tv1.DowntimeTuningOptions) *int64 { return d.InitialMs })
		},
		optionsValue: func(opts *k6tv1.VMIMConfigurationOptions) any {
			return downtimeOptionsValue(opts, func(d *k6tv1.DowntimeTuningOptions) *int64 { return d.InitialMs })
		},
	},
	{
		path: "experimental.downtimeTuning.steps",
		specExplicitlySet: func(spec *v1alpha1.MigrationPolicySpec) bool {
			return downtimeSpecSet(spec, func(d *k6tv1.DowntimeTuningOptions) *int32 { return d.Steps })
		},
		optionsValue: func(opts *k6tv1.VMIMConfigurationOptions) any {
			return downtimeOptionsValue(opts, func(d *k6tv1.DowntimeTuningOptions) *int32 { return d.Steps })
		},
	},
	{
		path: "experimental.downtimeTuning.startAfterIteration",
		specExplicitlySet: func(spec *v1alpha1.MigrationPolicySpec) bool {
			return downtimeSpecSet(spec, func(d *k6tv1.DowntimeTuningOptions) *int64 { return d.StartAfterIteration })
		},
		optionsValue: func(opts *k6tv1.VMIMConfigurationOptions) any {
			return downtimeOptionsValue(opts, func(d *k6tv1.DowntimeTuningOptions) *int64 { return d.StartAfterIteration })
		},
	},
	{
		path: "experimental.downtimeTuning.cooldownSeconds",
		specExplicitlySet: func(spec *v1alpha1.MigrationPolicySpec) bool {
			return downtimeSpecSet(spec, func(d *k6tv1.DowntimeTuningOptions) *int32 { return d.CooldownSeconds })
		},
		optionsValue: func(opts *k6tv1.VMIMConfigurationOptions) any {
			return downtimeOptionsValue(opts, func(d *k6tv1.DowntimeTuningOptions) *int32 { return d.CooldownSeconds })
		},
	},
}

// ExplainMigrationPolicies explains how the given policy snapshot resolves on
// the explicitly fixed VMI/namespace set against a cluster-default snapshot.
//
// The explanation never reimplements matching or merging: policy selection
// comes from matchPolicy, scores from countMatchingLabels and resolved options
// from applyMigrationPolicySpec, all called on this package's real code paths.
// Inputs are deep-copied first, so enabling the explanation cannot modify the
// caller's base configuration or policy objects, and no policy is updated and
// no migration triggered. The guarantee is scoped to the supplied targets; it
// does not claim anything about unlisted VMIs or future label combinations.
func ExplainMigrationPolicies(input ExplainMigrationPoliciesInput) (*MigrationPolicyExplanationReport, error) {
	if err := validateExplainInput(input); err != nil {
		return nil, err
	}

	clusterDefaults := input.ClusterDefaults.DeepCopy()
	candidatePolicies := input.Policies.DeepCopy()

	report := &MigrationPolicyExplanationReport{VMIs: make([]MigrationPolicyVMIExplanation, 0, len(input.Targets))}
	for _, target := range input.Targets {
		report.VMIs = append(report.VMIs, explainOneTarget(target, candidatePolicies, clusterDefaults))
	}
	sort.Slice(report.VMIs, func(i, j int) bool {
		return vmiReferenceLess(report.VMIs[i].Namespace, report.VMIs[i].Name, report.VMIs[j].Namespace, report.VMIs[j].Name)
	})

	if input.BaselinePolicies != nil {
		baselinePolicies := input.BaselinePolicies.DeepCopy()
		report.Comparison = buildComparison(input.Targets, baselinePolicies, candidatePolicies, clusterDefaults)
	}

	return report, nil
}

func validateExplainInput(input ExplainMigrationPoliciesInput) error {
	if len(input.Targets) == 0 {
		return fmt.Errorf("ExplainMigrationPolicies requires at least one target VMI")
	}
	if len(input.Targets) > MaxExplainMigrationTargets {
		return fmt.Errorf("ExplainMigrationPolicies is limited to %d target VMIs, got %d", MaxExplainMigrationTargets, len(input.Targets))
	}
	for idx, target := range input.Targets {
		if target.VMI == nil {
			return fmt.Errorf("ExplainMigrationPolicies target at index %d has a nil VMI", idx)
		}
	}
	if input.Policies == nil {
		return fmt.Errorf("ExplainMigrationPolicies requires a non-nil policy list snapshot (an empty list is valid)")
	}
	if len(input.Policies.Items) > MaxExplainMigrationPolicies {
		return fmt.Errorf("ExplainMigrationPolicies is limited to %d policies, got %d", MaxExplainMigrationPolicies, len(input.Policies.Items))
	}
	if input.BaselinePolicies != nil && len(input.BaselinePolicies.Items) > MaxExplainMigrationPolicies {
		return fmt.Errorf(
			"ExplainMigrationPolicies baseline is limited to %d policies, got %d",
			MaxExplainMigrationPolicies, len(input.BaselinePolicies.Items),
		)
	}
	if input.ClusterDefaults == nil {
		return fmt.Errorf("ExplainMigrationPolicies requires a non-nil cluster defaults snapshot")
	}
	return nil
}

func explainOneTarget(
	target ExplainMigrationTarget,
	policies *v1alpha1.MigrationPolicyList,
	base *k6tv1.VMIMConfigurationOptions,
) MigrationPolicyVMIExplanation {
	vmi := target.VMI.DeepCopy()
	namespace := target.Namespace
	if namespace == nil {
		// A nil namespace behaves like one with nil labels for the real functions.
		namespace = &k8sv1.Namespace{}
	} else {
		namespace = namespace.DeepCopy()
	}

	// Real selection path; its result is the authoritative selected policy.
	selected := matchPolicy(policies, vmi, namespace)

	explanation := MigrationPolicyVMIExplanation{
		Namespace:       vmi.Namespace,
		Name:            vmi.Name,
		Policies:        make([]MigrationPolicyMatchExplanation, 0, len(policies.Items)),
		Fields:          make([]MigrationPolicyFieldExplanation, 0, len(migrationPolicyFieldLeaves)),
		ResolvedOptions: base.DeepCopy(),
	}

	var bestScore migrationPolicyMatchScore
	if selected != nil {
		explanation.SelectedPolicyName = selected.Name
		_, bestScore = countMatchingLabels(selected, vmi.Labels, namespace.Labels)
		// Real merge path; base is deep-copied inside applyMigrationPolicySpec.
		explanation.ResolvedOptions = applyMigrationPolicySpec(base, &selected.Spec)
	}

	for idx := range policies.Items {
		policy := &policies.Items[idx]
		doesMatch, score := countMatchingLabels(policy, vmi.Labels, namespace.Labels)

		entry := MigrationPolicyMatchExplanation{
			PolicyName: policy.Name,
			Matched:    doesMatch,
			Score: MigrationPolicyScoreExplanation{
				MatchingVMILabels:       score.matchingVMILabels,
				MatchingNamespaceLabels: score.matchingNSLabels,
				Total:                   score.matchingVMILabels + score.matchingNSLabels,
			},
		}

		switch {
		case !doesMatch:
			entry.Outcome = MatchOutcomeUnmatched
		case selected != nil && policy.Name == selected.Name:
			entry.Outcome = MatchOutcomeSelected
		case score.equals(bestScore):
			// Same two-dimensional score as the winner: only the lexicographic
			// name tie-break performed inside matchPolicy decides.
			entry.Outcome = MatchOutcomeShadowed
			entry.ShadowReason = ShadowReasonLexicographicTieBreak
		default:
			entry.Outcome = MatchOutcomeShadowed
			entry.ShadowReason = ShadowReasonLowerScore
		}

		explanation.Policies = append(explanation.Policies, entry)
	}
	sort.SliceStable(explanation.Policies, func(i, j int) bool {
		return policyEntryLess(explanation.Policies[i], explanation.Policies[j])
	})

	for _, leaf := range migrationPolicyFieldLeaves {
		fieldExplanation := MigrationPolicyFieldExplanation{FieldPath: leaf.path}
		if selected != nil {
			fieldExplanation.PolicyExplicitlySet = leaf.specExplicitlySet(&selected.Spec)
			fieldExplanation.Source = resolveFieldSource(&selected.Spec, leaf)
		} else {
			fieldExplanation.Source = FieldSourceClusterDefault
		}
		explanation.Fields = append(explanation.Fields, fieldExplanation)
	}
	sort.SliceStable(explanation.Fields, func(i, j int) bool {
		return explanation.Fields[i].FieldPath < explanation.Fields[j].FieldPath
	})

	return explanation
}

// resolveFieldSource attributes a leaf without reimplementing the merge:
// nil-ness of the real spec pointers is observed, and the effective values
// remain those produced by applyMigrationPolicySpec.
func resolveFieldSource(spec *v1alpha1.MigrationPolicySpec, leaf migrationPolicyFieldLeaf) MigrationPolicyFieldSource {
	if leaf.path == "allowWorkloadDisruption" {
		switch {
		case spec.AllowWorkloadDisruption != nil:
			return FieldSourcePolicyOverride
		case spec.AllowPostCopy != nil:
			// Mirrors the backward-compatibility shim at the top of
			// applyMigrationPolicySpec.
			return FieldSourcePostCopyFallback
		default:
			return FieldSourceClusterDefault
		}
	}
	if leaf.specExplicitlySet(spec) {
		return FieldSourcePolicyOverride
	}
	return FieldSourceClusterDefault
}

func policyEntryLess(a, b MigrationPolicyMatchExplanation) bool {
	if rank := outcomeRank(a.Outcome) - outcomeRank(b.Outcome); rank != 0 {
		return rank < 0
	}
	if a.Score.Total != b.Score.Total {
		return a.Score.Total > b.Score.Total
	}
	if a.Score.MatchingVMILabels != b.Score.MatchingVMILabels {
		return a.Score.MatchingVMILabels > b.Score.MatchingVMILabels
	}
	return a.PolicyName < b.PolicyName
}

func outcomeRank(outcome MigrationPolicyMatchOutcome) int {
	switch outcome {
	case MatchOutcomeSelected:
		return matchOutcomeRankSelected
	case MatchOutcomeShadowed:
		return matchOutcomeRankShadowed
	case MatchOutcomeUnmatched, MatchOutcomeNotPresent:
		return matchOutcomeRankOther
	default:
		return matchOutcomeRankOther
	}
}

func vmiReferenceLess(namespaceA, nameA, namespaceB, nameB string) bool {
	if namespaceA != namespaceB {
		return namespaceA < namespaceB
	}
	return nameA < nameB
}

func buildComparison(
	targets []ExplainMigrationTarget,
	baselinePolicies, candidatePolicies *v1alpha1.MigrationPolicyList,
	base *k6tv1.VMIMConfigurationOptions,
) *MigrationPolicyComparison {
	comparison := &MigrationPolicyComparison{VMIs: make([]MigrationPolicyVMIComparison, 0, len(targets))}

	for _, target := range targets {
		baseline := explainOneTarget(target, baselinePolicies, base)
		candidate := explainOneTarget(target, candidatePolicies, base)

		vmiComparison := MigrationPolicyVMIComparison{
			Namespace:               candidate.Namespace,
			Name:                    candidate.Name,
			BaselineSelectedPolicy:  baseline.SelectedPolicyName,
			CandidateSelectedPolicy: candidate.SelectedPolicyName,
			SelectedPolicyChanged:   baseline.SelectedPolicyName != candidate.SelectedPolicyName,
			PolicyOutcomeChanges:    diffPolicyOutcomes(baseline.Policies, candidate.Policies),
			FieldChanges:            diffResolvedFields(baseline.ResolvedOptions, candidate.ResolvedOptions),
		}
		comparison.VMIs = append(comparison.VMIs, vmiComparison)
	}

	sort.Slice(comparison.VMIs, func(i, j int) bool {
		return vmiReferenceLess(comparison.VMIs[i].Namespace, comparison.VMIs[i].Name, comparison.VMIs[j].Namespace, comparison.VMIs[j].Name)
	})
	return comparison
}

func diffPolicyOutcomes(baselineEntries, candidateEntries []MigrationPolicyMatchExplanation) []MigrationPolicyOutcomeChange {
	baselineByName := make(map[string]MigrationPolicyMatchExplanation, len(baselineEntries))
	for _, entry := range baselineEntries {
		baselineByName[entry.PolicyName] = entry
	}
	candidateByName := make(map[string]MigrationPolicyMatchExplanation, len(candidateEntries))
	for _, entry := range candidateEntries {
		candidateByName[entry.PolicyName] = entry
	}

	changes := make([]MigrationPolicyOutcomeChange, 0)
	for policyName := range baselineByName {
		if _, ok := candidateByName[policyName]; !ok {
			candidateByName[policyName] = MigrationPolicyMatchExplanation{}
		}
	}
	for policyName := range candidateByName {
		if _, ok := baselineByName[policyName]; !ok {
			baselineByName[policyName] = MigrationPolicyMatchExplanation{}
		}
	}

	for policyName, baselineEntry := range baselineByName {
		candidateEntry := candidateByName[policyName]
		baselineSnapshot := MigrationPolicyOutcomeSnapshot{
			Present: baselineEntry.PolicyName != "",
			Outcome: baselineEntry.Outcome,
		}
		candidateSnapshot := MigrationPolicyOutcomeSnapshot{
			Present: candidateEntry.PolicyName != "",
			Outcome: candidateEntry.Outcome,
		}
		if !baselineSnapshot.Present {
			baselineSnapshot.Outcome = MatchOutcomeNotPresent
		}
		if !candidateSnapshot.Present {
			candidateSnapshot.Outcome = MatchOutcomeNotPresent
		}
		if baselineSnapshot == candidateSnapshot {
			continue
		}
		changes = append(changes, MigrationPolicyOutcomeChange{
			PolicyName: policyName,
			Baseline:   baselineSnapshot,
			Candidate:  candidateSnapshot,
		})
	}

	sort.SliceStable(changes, func(i, j int) bool { return changes[i].PolicyName < changes[j].PolicyName })
	return changes
}

func diffResolvedFields(baselineOptions, candidateOptions *k6tv1.VMIMConfigurationOptions) []MigrationPolicyFieldChange {
	changes := make([]MigrationPolicyFieldChange, 0)
	for _, leaf := range migrationPolicyFieldLeaves {
		baselineValue := leaf.optionsValue(baselineOptions)
		candidateValue := leaf.optionsValue(candidateOptions)
		if reflect.DeepEqual(baselineValue, candidateValue) {
			continue
		}
		changes = append(changes, MigrationPolicyFieldChange{
			FieldPath:      leaf.path,
			BaselineValue:  baselineValue,
			CandidateValue: candidateValue,
		})
	}
	sort.SliceStable(changes, func(i, j int) bool { return changes[i].FieldPath < changes[j].FieldPath })
	return changes
}
