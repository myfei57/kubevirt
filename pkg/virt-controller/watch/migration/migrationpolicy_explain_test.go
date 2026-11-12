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
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	k8sv1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "kubevirt.io/api/core/v1"
	migrationsv1 "kubevirt.io/api/migrations/v1alpha1"

	"kubevirt.io/kubevirt/pkg/pointer"
)

var _ = Describe("ExplainMigrationPolicies", func() {
	const (
		nsName  = "ns-a"
		vmiName = "vmi-a"
	)

	var base *v1.VMIMConfigurationOptions

	BeforeEach(func() {
		base = &v1.VMIMConfigurationOptions{
			AllowAutoConverge:       pointer.P(true),
			CompletionTimeoutPerGiB: pointer.P(int64(150)),
			MaxDowntimeMs:           pointer.P(uint64(900)),
			AllowPostCopy:           pointer.P(false),
			AllowWorkloadDisruption: pointer.P(true),
		}
	})

	DescribeTable("rejects invalid snapshots", func(input ExplainMigrationPoliciesInput) {
		_, err := ExplainMigrationPolicies(input)
		Expect(err).To(HaveOccurred())
	},
		Entry("without targets", ExplainMigrationPoliciesInput{
			Policies:        &migrationsv1.MigrationPolicyList{},
			ClusterDefaults: &v1.VMIMConfigurationOptions{},
		}),
		Entry("with a nil policy list", ExplainMigrationPoliciesInput{
			Targets:         []ExplainMigrationTarget{{VMI: newExplainVMI(vmiName, nsName, nil)}},
			ClusterDefaults: &v1.VMIMConfigurationOptions{},
		}),
		Entry("with nil cluster defaults", ExplainMigrationPoliciesInput{
			Targets:  []ExplainMigrationTarget{{VMI: newExplainVMI(vmiName, nsName, nil)}},
			Policies: &migrationsv1.MigrationPolicyList{},
		}),
		Entry("with a nil VMI target", ExplainMigrationPoliciesInput{
			Targets:         []ExplainMigrationTarget{{}},
			Policies:        &migrationsv1.MigrationPolicyList{},
			ClusterDefaults: &v1.VMIMConfigurationOptions{},
		}),
		Entry("with too many targets", ExplainMigrationPoliciesInput{
			Targets:         make([]ExplainMigrationTarget, MaxExplainMigrationTargets+1),
			Policies:        &migrationsv1.MigrationPolicyList{},
			ClusterDefaults: &v1.VMIMConfigurationOptions{},
		}),
		Entry("with too many policies", ExplainMigrationPoliciesInput{
			Targets:         []ExplainMigrationTarget{{VMI: newExplainVMI(vmiName, nsName, nil)}},
			Policies:        &migrationsv1.MigrationPolicyList{Items: make([]migrationsv1.MigrationPolicy, MaxExplainMigrationPolicies+1)},
			ClusterDefaults: &v1.VMIMConfigurationOptions{},
		}),
	)

	It("reports every policy as unmatched and cluster defaults when the policy list is empty", func() {
		input := ExplainMigrationPoliciesInput{
			Targets:         []ExplainMigrationTarget{{VMI: newExplainVMI(vmiName, nsName, map[string]string{"app": "web"})}},
			Policies:        &migrationsv1.MigrationPolicyList{},
			ClusterDefaults: base,
		}

		report, err := ExplainMigrationPolicies(input)
		Expect(err).ToNot(HaveOccurred())
		Expect(report.VMIs).To(HaveLen(1))
		Expect(report.VMIs[0].SelectedPolicyName).To(BeEmpty())
		Expect(report.VMIs[0].Policies).To(BeEmpty())
		Expect(report.VMIs[0].ResolvedOptions).To(Equal(base.DeepCopy()))
		for _, field := range report.VMIs[0].Fields {
			Expect(field.Source).To(Equal(FieldSourceClusterDefault))
			Expect(field.PolicyExplicitlySet).To(BeFalse())
		}
	})

	It("explains unmatched, score-shadowed, lexicographic tie-break and the selected policy", func() {
		vmiLabels := map[string]string{"app": "web", "tier": "cache"}
		namespaceLabels := map[string]string{"env": "prod", "zone": "a"}
		target := ExplainMigrationTarget{
			VMI:       newExplainVMI(vmiName, nsName, vmiLabels),
			Namespace: newExplainNamespace(nsName, namespaceLabels),
		}

		// "zz" is listed first to prove order independence of the lexicographic tie-break.
		zz := newExplainPolicy("zz", map[string]string{"app": "web", "tier": "cache"}, map[string]string{"env": "prod"})
		aa := newExplainPolicy("aa", map[string]string{"app": "web", "tier": "cache"}, map[string]string{"env": "prod"})
		// Same total score (3) but fewer VMI labels: loses on the VMI-label dimension.
		nsHeavy := newExplainPolicy("ns-heavy", map[string]string{"app": "web"}, map[string]string{"env": "prod", "zone": "a"})
		miss := newExplainPolicy("miss", map[string]string{"app": "db"}, nil)
		nilSelectors := &migrationsv1.MigrationPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "nil-selectors"},
			Spec:       migrationsv1.MigrationPolicySpec{},
		}

		policies := explainPolicyList(zz, aa, nsHeavy, miss, nilSelectors)

		// The explanation must agree with the real selection path.
		realSelected := matchPolicy(policies, target.VMI, target.Namespace)
		Expect(realSelected).ToNot(BeNil())
		Expect(realSelected.Name).To(Equal("aa"))

		report, err := ExplainMigrationPolicies(ExplainMigrationPoliciesInput{
			Targets:         []ExplainMigrationTarget{target},
			Policies:        policies,
			ClusterDefaults: base,
		})
		Expect(err).ToNot(HaveOccurred())

		vmiExplanation := report.VMIs[0]
		Expect(vmiExplanation.SelectedPolicyName).To(Equal("aa"))
		Expect(vmiExplanation.Policies).To(HaveLen(5))

		By("checking every entry against the real countMatchingLabels path")
		for _, policy := range policies.Items {
			realMatch, realScore := countMatchingLabels(&policy, vmiLabels, namespaceLabels)
			entry := findPolicyExplanation(vmiExplanation.Policies, policy.Name)
			Expect(entry.Matched).To(Equal(realMatch))
			Expect(entry.Score.MatchingVMILabels).To(Equal(realScore.matchingVMILabels))
			Expect(entry.Score.MatchingNamespaceLabels).To(Equal(realScore.matchingNSLabels))
			Expect(entry.Score.Total).To(Equal(realScore.matchingVMILabels + realScore.matchingNSLabels))
		}

		selected := findPolicyExplanation(vmiExplanation.Policies, "aa")
		Expect(selected.Outcome).To(Equal(MatchOutcomeSelected))
		Expect(selected.ShadowReason).To(Equal(ShadowReasonNone))

		tied := findPolicyExplanation(vmiExplanation.Policies, "zz")
		Expect(tied.Outcome).To(Equal(MatchOutcomeShadowed))
		Expect(tied.ShadowReason).To(Equal(ShadowReasonLexicographicTieBreak))
		Expect(tied.Score).To(Equal(selected.Score))

		shadowedOnScore := findPolicyExplanation(vmiExplanation.Policies, "ns-heavy")
		Expect(shadowedOnScore.Outcome).To(Equal(MatchOutcomeShadowed))
		Expect(shadowedOnScore.ShadowReason).To(Equal(ShadowReasonLowerScore))
		Expect(shadowedOnScore.Score).To(Equal(MigrationPolicyScoreExplanation{
			MatchingVMILabels:       1,
			MatchingNamespaceLabels: 2,
			Total:                   3,
		}))

		for _, unmatchedName := range []string{"miss", "nil-selectors"} {
			unmatched := findPolicyExplanation(vmiExplanation.Policies, unmatchedName)
			Expect(unmatched.Outcome).To(Equal(MatchOutcomeUnmatched))
			Expect(unmatched.Matched).To(BeFalse())
			Expect(unmatched.Score).To(Equal(MigrationPolicyScoreExplanation{}))
		}

		By("checking stable ordering: selected, shadowed by score, then unmatched by name")
		Expect([]string{
			vmiExplanation.Policies[0].PolicyName,
			vmiExplanation.Policies[1].PolicyName,
			vmiExplanation.Policies[2].PolicyName,
			vmiExplanation.Policies[3].PolicyName,
			vmiExplanation.Policies[4].PolicyName,
		}).To(Equal([]string{"aa", "zz", "ns-heavy", "miss", "nil-selectors"}))
	})

	It("distinguishes explicit false/zero overrides from nil inheritance and explains the post-copy fallback", func() {
		target := ExplainMigrationTarget{
			VMI:       newExplainVMI(vmiName, nsName, map[string]string{"app": "web"}),
			Namespace: newExplainNamespace(nsName, nil),
		}
		policy := newExplainPolicy("p", map[string]string{"app": "web"}, nil)
		policy.Spec.AllowAutoConverge = pointer.P(false)
		policy.Spec.CompletionTimeoutPerGiB = pointer.P(int64(0))
		policy.Spec.AllowPostCopy = pointer.P(true)
		// AllowWorkloadDisruption intentionally nil: must follow AllowPostCopy.
		policies := explainPolicyList(policy)

		report, err := ExplainMigrationPolicies(ExplainMigrationPoliciesInput{
			Targets:         []ExplainMigrationTarget{target},
			Policies:        policies,
			ClusterDefaults: base,
		})
		Expect(err).ToNot(HaveOccurred())
		fields := report.VMIs[0].Fields

		allowAutoConverge := findFieldExplanation(fields, "allowAutoConverge")
		Expect(allowAutoConverge.Source).To(Equal(FieldSourcePolicyOverride))
		Expect(allowAutoConverge.PolicyExplicitlySet).To(BeTrue())
		Expect(*report.VMIs[0].ResolvedOptions.AllowAutoConverge).To(BeFalse())

		timeout := findFieldExplanation(fields, "completionTimeoutPerGiB")
		Expect(timeout.Source).To(Equal(FieldSourcePolicyOverride))
		Expect(timeout.PolicyExplicitlySet).To(BeTrue())
		Expect(*report.VMIs[0].ResolvedOptions.CompletionTimeoutPerGiB).To(Equal(int64(0)))

		maxDowntime := findFieldExplanation(fields, "maxDowntimeMs")
		Expect(maxDowntime.Source).To(Equal(FieldSourceClusterDefault))
		Expect(maxDowntime.PolicyExplicitlySet).To(BeFalse())
		Expect(*report.VMIs[0].ResolvedOptions.MaxDowntimeMs).To(Equal(uint64(900)))

		workloadDisruption := findFieldExplanation(fields, "allowWorkloadDisruption")
		Expect(workloadDisruption.Source).To(Equal(FieldSourcePostCopyFallback))
		Expect(workloadDisruption.PolicyExplicitlySet).To(BeFalse())
		Expect(*report.VMIs[0].ResolvedOptions.AllowWorkloadDisruption).To(BeTrue())

		postCopy := findFieldExplanation(fields, "allowPostCopy")
		Expect(postCopy.Source).To(Equal(FieldSourcePolicyOverride))
		Expect(*report.VMIs[0].ResolvedOptions.AllowPostCopy).To(BeTrue())

		By("explicit AllowWorkloadDisruption wins over the fallback")
		explicitPolicy := policy.DeepCopy()
		explicitPolicy.Spec.AllowWorkloadDisruption = pointer.P(false)
		explicitReport, err := ExplainMigrationPolicies(ExplainMigrationPoliciesInput{
			Targets:         []ExplainMigrationTarget{target},
			Policies:        explainPolicyList(explicitPolicy),
			ClusterDefaults: base,
		})
		Expect(err).ToNot(HaveOccurred())
		explicitField := findFieldExplanation(explicitReport.VMIs[0].Fields, "allowWorkloadDisruption")
		Expect(explicitField.Source).To(Equal(FieldSourcePolicyOverride))
		Expect(explicitField.PolicyExplicitlySet).To(BeTrue())
		Expect(*explicitReport.VMIs[0].ResolvedOptions.AllowWorkloadDisruption).To(BeFalse())

		By("without either field set, the cluster default is inherited")
		plainPolicy := newExplainPolicy("plain", map[string]string{"app": "web"}, nil)
		plainReport, err := ExplainMigrationPolicies(ExplainMigrationPoliciesInput{
			Targets:         []ExplainMigrationTarget{target},
			Policies:        explainPolicyList(plainPolicy),
			ClusterDefaults: base,
		})
		Expect(err).ToNot(HaveOccurred())
		plainField := findFieldExplanation(plainReport.VMIs[0].Fields, "allowWorkloadDisruption")
		Expect(plainField.Source).To(Equal(FieldSourceClusterDefault))
		Expect(plainField.PolicyExplicitlySet).To(BeFalse())
		Expect(*plainReport.VMIs[0].ResolvedOptions.AllowWorkloadDisruption).To(BeTrue())
	})

	It("keeps field granularity for nested experimental options while matching the real merge result", func() {
		base.ExperimentalMigrationOptions = &v1.ExperimentalMigrationOptions{
			Compression: pointer.P(v1.MigrationCompressionZstd),
			StallDetector: &v1.StallDetectorOptions{
				StallMargin: pointer.P(int64(4)),
			},
			DowntimeTuning: &v1.DowntimeTuningOptions{
				Steps: pointer.P(int32(7)),
			},
		}

		target := ExplainMigrationTarget{
			VMI:       newExplainVMI(vmiName, nsName, map[string]string{"app": "web"}),
			Namespace: newExplainNamespace(nsName, nil),
		}
		policy := newExplainPolicy("p", map[string]string{"app": "web"}, nil)
		policy.Spec.ExperimentalMigrationOptions = &v1.ExperimentalMigrationOptions{
			StallDetector: &v1.StallDetectorOptions{
				StallMargin: pointer.P(int64(8)),
			},
		}
		policies := explainPolicyList(policy)

		report, err := ExplainMigrationPolicies(ExplainMigrationPoliciesInput{
			Targets:         []ExplainMigrationTarget{target},
			Policies:        policies,
			ClusterDefaults: base,
		})
		Expect(err).ToNot(HaveOccurred())
		fields := report.VMIs[0].Fields

		stallMargin := findFieldExplanation(fields, "experimental.stallDetector.stallMargin")
		Expect(stallMargin.Source).To(Equal(FieldSourcePolicyOverride))
		Expect(stallMargin.PolicyExplicitlySet).To(BeTrue())
		Expect(*report.VMIs[0].ResolvedOptions.ExperimentalMigrationOptions.StallDetector.StallMargin).To(Equal(int64(8)))

		searchLocalMinima := findFieldExplanation(fields, "experimental.stallDetector.searchLocalMinima")
		Expect(searchLocalMinima.Source).To(Equal(FieldSourceClusterDefault))
		Expect(searchLocalMinima.PolicyExplicitlySet).To(BeFalse())

		steps := findFieldExplanation(fields, "experimental.downtimeTuning.steps")
		Expect(steps.Source).To(Equal(FieldSourceClusterDefault))
		Expect(*report.VMIs[0].ResolvedOptions.ExperimentalMigrationOptions.DowntimeTuning.Steps).To(Equal(int32(7)))

		compression := findFieldExplanation(fields, "experimental.compression")
		Expect(compression.Source).To(Equal(FieldSourceClusterDefault))
		Expect(*report.VMIs[0].ResolvedOptions.ExperimentalMigrationOptions.Compression).To(Equal(v1.MigrationCompressionZstd))

		By("an empty experimental block still mirrors the real structural merge")
		emptyBlockPolicy := newExplainPolicy("empty", map[string]string{"app": "web"}, nil)
		emptyBlockPolicy.Spec.ExperimentalMigrationOptions = &v1.ExperimentalMigrationOptions{}
		emptyReport, err := ExplainMigrationPolicies(ExplainMigrationPoliciesInput{
			Targets:         []ExplainMigrationTarget{target},
			Policies:        explainPolicyList(emptyBlockPolicy),
			ClusterDefaults: base,
		})
		Expect(err).ToNot(HaveOccurred())
		for _, field := range emptyReport.VMIs[0].Fields {
			if field.FieldPath == "experimental.compression" ||
				field.FieldPath == "experimental.stallDetector.stallMargin" ||
				field.FieldPath == "experimental.downtimeTuning.steps" {
				Expect(field.Source).To(Equal(FieldSourceClusterDefault))
				Expect(field.PolicyExplicitlySet).To(BeFalse())
			}
		}
		Expect(emptyReport.VMIs[0].ResolvedOptions.ExperimentalMigrationOptions).ToNot(BeNil())

		By("the full resolved options equal the real applyMigrationPolicySpec result")
		expectedResolved := applyMigrationPolicySpec(base, &policy.Spec)
		Expect(report.VMIs[0].ResolvedOptions).To(Equal(expectedResolved))
	})

	It("compares every resolved leaf field-by-field against the real functions", func() {
		vmiLabels := map[string]string{"app": "web", "tier": "cache"}
		namespaceLabels := map[string]string{"env": "prod"}
		target := ExplainMigrationTarget{
			VMI:       newExplainVMI(vmiName, nsName, vmiLabels),
			Namespace: newExplainNamespace(nsName, namespaceLabels),
		}
		policy := newExplainPolicy("p", map[string]string{"app": "web"}, map[string]string{"env": "prod"})
		policy.Spec.AllowAutoConverge = pointer.P(false)
		policy.Spec.ExperimentalMigrationOptions = &v1.ExperimentalMigrationOptions{
			StallDetector:  &v1.StallDetectorOptions{SwitchoverTimeout: pointer.P(int64(33))},
			DowntimeTuning: &v1.DowntimeTuningOptions{InitialMs: pointer.P(int64(120))},
			Compression:    pointer.P(v1.MigrationCompressionZstd),
		}
		policies := explainPolicyList(policy)

		report, err := ExplainMigrationPolicies(ExplainMigrationPoliciesInput{
			Targets:         []ExplainMigrationTarget{target},
			Policies:        policies,
			ClusterDefaults: base,
		})
		Expect(err).ToNot(HaveOccurred())

		realSelected := matchPolicy(policies, target.VMI, target.Namespace)
		Expect(realSelected).ToNot(BeNil())
		expectedResolved := applyMigrationPolicySpec(base, &realSelected.Spec)
		gotResolved := report.VMIs[0].ResolvedOptions

		Expect(gotResolved).To(Equal(expectedResolved))
		for _, leaf := range migrationPolicyFieldLeaves {
			Expect(leaf.optionsValue(gotResolved)).To(Equal(leaf.optionsValue(expectedResolved)), "field %s", leaf.path)
		}
		Expect(report.VMIs[0].Fields).To(HaveLen(len(migrationPolicyFieldLeaves)))
	})

	It("does not mutate base configuration, policies or target objects", func() {
		target := ExplainMigrationTarget{
			VMI:       newExplainVMI(vmiName, nsName, map[string]string{"app": "web"}),
			Namespace: newExplainNamespace(nsName, map[string]string{"env": "prod"}),
		}
		policy := newExplainPolicy("p", map[string]string{"app": "web"}, map[string]string{"env": "prod"})
		policy.Spec.AllowPostCopy = pointer.P(true)
		policy.Spec.ExperimentalMigrationOptions = &v1.ExperimentalMigrationOptions{
			StallDetector: &v1.StallDetectorOptions{StallMargin: pointer.P(int64(8))},
		}
		policies := explainPolicyList(policy)
		baselinePolicies := explainPolicyList(policy.DeepCopy())

		snapshotVMI := target.VMI.DeepCopy()
		snapshotNamespace := target.Namespace.DeepCopy()
		snapshotPolicies := policies.DeepCopy()
		snapshotBaseline := baselinePolicies.DeepCopy()
		snapshotBase := base.DeepCopy()

		_, err := ExplainMigrationPolicies(ExplainMigrationPoliciesInput{
			Targets:          []ExplainMigrationTarget{target},
			Policies:         policies,
			BaselinePolicies: baselinePolicies,
			ClusterDefaults:  base,
		})
		Expect(err).ToNot(HaveOccurred())

		Expect(target.VMI).To(Equal(snapshotVMI))
		Expect(target.Namespace).To(Equal(snapshotNamespace))
		Expect(policies).To(Equal(snapshotPolicies))
		Expect(baselinePolicies).To(Equal(snapshotBaseline))
		Expect(base).To(Equal(snapshotBase))
	})

	It("compares baseline and candidate policy snapshots on the bounded VMI set", func() {
		target := ExplainMigrationTarget{
			VMI:       newExplainVMI(vmiName, nsName, map[string]string{"app": "web", "tier": "cache"}),
			Namespace: newExplainNamespace(nsName, nil),
		}

		baselinePolicy := newExplainPolicy("p1", map[string]string{"app": "web"}, nil)
		baselinePolicy.Spec.AllowAutoConverge = pointer.P(true)
		baselinePolicies := explainPolicyList(baselinePolicy)

		candidatePolicy := baselinePolicy.DeepCopy()
		moreSpecific := newExplainPolicy("p0", map[string]string{"app": "web", "tier": "cache"}, nil)
		// The override lives on the newly selected policy so the resolved
		// value actually changes between the two snapshots.
		moreSpecific.Spec.AllowAutoConverge = pointer.P(false)
		candidatePolicies := explainPolicyList(candidatePolicy, moreSpecific)

		report, err := ExplainMigrationPolicies(ExplainMigrationPoliciesInput{
			Targets:          []ExplainMigrationTarget{target},
			Policies:         candidatePolicies,
			BaselinePolicies: baselinePolicies,
			ClusterDefaults:  base,
		})
		Expect(err).ToNot(HaveOccurred())
		Expect(report.Comparison).ToNot(BeNil())
		Expect(report.Comparison.VMIs).To(HaveLen(1))

		diff := report.Comparison.VMIs[0]
		Expect(diff.BaselineSelectedPolicy).To(Equal("p1"))
		Expect(diff.CandidateSelectedPolicy).To(Equal("p0"))
		Expect(diff.SelectedPolicyChanged).To(BeTrue())

		p0Change := findOutcomeChange(diff.PolicyOutcomeChanges, "p0")
		Expect(p0Change.Baseline.Present).To(BeFalse())
		Expect(p0Change.Baseline.Outcome).To(Equal(MatchOutcomeNotPresent))
		Expect(p0Change.Candidate.Present).To(BeTrue())
		Expect(p0Change.Candidate.Outcome).To(Equal(MatchOutcomeSelected))

		autoConvergeChange := findFieldChange(diff.FieldChanges, "allowAutoConverge")
		Expect(autoConvergeChange.BaselineValue).To(BeTrue())
		Expect(autoConvergeChange.CandidateValue).To(BeFalse())

		By("identical snapshots produce no changes")
		identicalReport, err := ExplainMigrationPolicies(ExplainMigrationPoliciesInput{
			Targets:          []ExplainMigrationTarget{target},
			Policies:         baselinePolicies.DeepCopy(),
			BaselinePolicies: baselinePolicies,
			ClusterDefaults:  base,
		})
		Expect(err).ToNot(HaveOccurred())
		identicalDiff := identicalReport.Comparison.VMIs[0]
		Expect(identicalDiff.SelectedPolicyChanged).To(BeFalse())
		Expect(identicalDiff.PolicyOutcomeChanges).To(BeEmpty())
		Expect(identicalDiff.FieldChanges).To(BeEmpty())
	})

	It("keeps nil selector/label and empty map semantics identical to the real functions", func() {
		// A namespace-only selector; note the real countMatchingLabels gates
		// namespace evaluation on the VMI label map being non-nil. The
		// explanation must reproduce that behavior rather than "fix" it.
		policy := newExplainPolicy("p", nil, map[string]string{"env": "prod"})
		policies := explainPolicyList(policy)

		entries := []struct {
			name            string
			vmiLabels       map[string]string
			namespaceLabels map[string]string
		}{
			{name: "nil VMI and namespace labels", vmiLabels: nil, namespaceLabels: nil},
			{name: "empty VMI labels, nil namespace labels", vmiLabels: map[string]string{}, namespaceLabels: nil},
			{name: "nil VMI labels, matching namespace labels", vmiLabels: nil, namespaceLabels: map[string]string{"env": "prod"}},
			{name: "empty VMI labels, matching namespace labels", vmiLabels: map[string]string{}, namespaceLabels: map[string]string{"env": "prod"}},
		}
		for _, entry := range entries {
			By(entry.name)
			vmiLabels := entry.vmiLabels
			namespaceLabels := entry.namespaceLabels

			vmi := newExplainVMI(vmiName, nsName, vmiLabels)
			namespace := newExplainNamespace(nsName, namespaceLabels)

			report, err := ExplainMigrationPolicies(ExplainMigrationPoliciesInput{
				Targets:         []ExplainMigrationTarget{{VMI: vmi, Namespace: namespace}},
				Policies:        policies,
				ClusterDefaults: base,
			})
			Expect(err).ToNot(HaveOccurred())

			realSelected := matchPolicy(policies, vmi, namespace)
			Expect(report.VMIs[0].SelectedPolicyName).To(Equal(selectedPolicyName(realSelected)))

			realMatch, realScore := countMatchingLabels(policy, vmiLabels, namespaceLabels)
			parityEntry := findPolicyExplanation(report.VMIs[0].Policies, "p")
			Expect(parityEntry.Matched).To(Equal(realMatch))
			Expect(parityEntry.Score.MatchingVMILabels).To(Equal(realScore.matchingVMILabels))
			Expect(parityEntry.Score.MatchingNamespaceLabels).To(Equal(realScore.matchingNSLabels))
		}
	})

	It("sorts VMIs stably and tolerates a nil namespace target", func() {
		first := ExplainMigrationTarget{
			VMI:       newExplainVMI("vmi-b", "ns-b", map[string]string{"app": "web"}),
			Namespace: newExplainNamespace("ns-b", nil),
		}
		second := ExplainMigrationTarget{
			// Non-nil, non-matching labels make this VMI genuinely unmatched;
			// the namespace is nil on purpose to cover nil-namespace handling.
			VMI: newExplainVMI("vmi-a", "ns-a", map[string]string{"other": "x"}),
		}
		policy := newExplainPolicy("p", map[string]string{"app": "web"}, nil)

		report, err := ExplainMigrationPolicies(ExplainMigrationPoliciesInput{
			Targets:         []ExplainMigrationTarget{first, second},
			Policies:        explainPolicyList(policy),
			ClusterDefaults: base,
		})
		Expect(err).ToNot(HaveOccurred())
		Expect([]string{report.VMIs[0].Namespace, report.VMIs[0].Name}).To(Equal([]string{"ns-a", "vmi-a"}))
		Expect([]string{report.VMIs[1].Namespace, report.VMIs[1].Name}).To(Equal([]string{"ns-b", "vmi-b"}))
		Expect(report.VMIs[0].SelectedPolicyName).To(BeEmpty())
		Expect(report.VMIs[1].SelectedPolicyName).To(Equal("p"))
	})

	It("covers every leaf reachable by applyMigrationPolicySpec in the field table", func() {
		Expect(migrationPolicyFieldLeaves).To(HaveLen(19))
		paths := make(map[string]bool)
		for _, leaf := range migrationPolicyFieldLeaves {
			Expect(paths[leaf.path]).To(BeFalse(), "duplicate field path %s", leaf.path)
			paths[leaf.path] = true
		}
		expectedPaths := []string{
			"allowAutoConverge", "bandwidthPerMigration", "completionTimeoutPerGiB",
			"maxDowntimeMs", "allowPostCopy", "allowWorkloadDisruption",
			"experimental.compression",
			"experimental.stallDetector.stallMargin",
			"experimental.stallDetector.ewmaAlpha",
			"experimental.stallDetector.stallProgressTimeout",
			"experimental.stallDetector.switchoverTimeout",
			"experimental.stallDetector.precopyPossibleFactor",
			"experimental.stallDetector.patienceWindowDecayFactor",
			"experimental.stallDetector.searchLocalMinima",
			"experimental.stallDetector.completionTimeoutFactor",
			"experimental.downtimeTuning.initialMs",
			"experimental.downtimeTuning.steps",
			"experimental.downtimeTuning.startAfterIteration",
			"experimental.downtimeTuning.cooldownSeconds",
		}
		for _, path := range expectedPaths {
			Expect(paths[path]).To(BeTrue(), "missing field path %s", path)
		}
	})
})

func newExplainVMI(name, namespace string, labels map[string]string) *v1.VirtualMachineInstance {
	return &v1.VirtualMachineInstance{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, Labels: labels},
	}
}

func newExplainNamespace(name string, labels map[string]string) *k8sv1.Namespace {
	return &k8sv1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels}}
}

func newExplainPolicy(name string, vmiSelector, namespaceSelector map[string]string) *migrationsv1.MigrationPolicy {
	return &migrationsv1.MigrationPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: migrationsv1.MigrationPolicySpec{
			Selectors: &migrationsv1.Selectors{
				VirtualMachineInstanceSelector: vmiSelector,
				NamespaceSelector:              namespaceSelector,
			},
		},
	}
}

func explainPolicyList(policies ...*migrationsv1.MigrationPolicy) *migrationsv1.MigrationPolicyList {
	items := make([]migrationsv1.MigrationPolicy, 0, len(policies))
	for _, policy := range policies {
		items = append(items, *policy)
	}
	return &migrationsv1.MigrationPolicyList{Items: items}
}

func findFieldExplanation(fields []MigrationPolicyFieldExplanation, path string) MigrationPolicyFieldExplanation {
	for _, field := range fields {
		if field.FieldPath == path {
			return field
		}
	}
	Fail("missing field explanation: " + path)
	return MigrationPolicyFieldExplanation{}
}

func findPolicyExplanation(entries []MigrationPolicyMatchExplanation, name string) MigrationPolicyMatchExplanation {
	for _, entry := range entries {
		if entry.PolicyName == name {
			return entry
		}
	}
	Fail("missing policy explanation: " + name)
	return MigrationPolicyMatchExplanation{}
}

func findOutcomeChange(changes []MigrationPolicyOutcomeChange, name string) MigrationPolicyOutcomeChange {
	for _, change := range changes {
		if change.PolicyName == name {
			return change
		}
	}
	Fail("missing outcome change: " + name)
	return MigrationPolicyOutcomeChange{}
}

func findFieldChange(changes []MigrationPolicyFieldChange, path string) MigrationPolicyFieldChange {
	for _, change := range changes {
		if change.FieldPath == path {
			return change
		}
	}
	Fail("missing field change: " + path)
	return MigrationPolicyFieldChange{}
}

func selectedPolicyName(policy *migrationsv1.MigrationPolicy) string {
	if policy == nil {
		return ""
	}
	return policy.Name
}
