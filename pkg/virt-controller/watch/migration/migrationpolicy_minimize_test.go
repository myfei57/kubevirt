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
	"encoding/json"
	"math/rand"
	"reflect"
	"sort"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	k8sv1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	v1 "kubevirt.io/api/core/v1"
	migrationsv1 "kubevirt.io/api/migrations/v1alpha1"
	"kubevirt.io/client-go/kubecli"

	"kubevirt.io/kubevirt/pkg/pointer"
)

const (
	randomMinimizeSeeds  = 40
	baseRandomPolicyCount = 4
	baseRandomVMICount    = 3
	randomChoiceCount     = 4
	binaryChoiceCount     = 2
	timeoutChoiceCount    = 3
	timeoutBaseValue      = 100
	timeoutStepValue      = 50
	tightNodeBudget       = 2
	shortTimeoutValue      = 150
	shortDowntimeValue     = 100
	longDowntimeValue      = 200
	changedDefaultsTimeout = 42
)

var _ = Describe("MinimizeMigrationPolicyBasis", func() {
	var defaults *v1.VMIMConfigurationOptions

	BeforeEach(func() {
		defaults = &v1.VMIMConfigurationOptions{}
	})

	It("keeps shadowed policies that become winners once the current winner is deleted", func() {
		// p-high wins v1 on the VMI-label dimension; p-low only wins v1 after
		// p-high is deleted (interaction shadowing) and is the sole winner of v2.
		policies := []migrationsv1.MigrationPolicy{
			minimizeTestPolicy("p-high",
				map[string]string{"app": "x"}, nil,
				func(spec *migrationsv1.MigrationPolicySpec) { spec.AllowAutoConverge = pointer.P(true) }),
			minimizeTestPolicy("p-low",
				nil, map[string]string{"tier": "gold"},
				func(spec *migrationsv1.MigrationPolicySpec) { spec.AllowAutoConverge = pointer.P(false) }),
		}
		inventory := []MinimizeMigrationPolicyVMI{
			minimizeTestVMI("ns1", "v1", map[string]string{"app": "x"}, map[string]string{"tier": "gold"}),
			// Non-nil VMI labels without app=x make p-high fail its selector;
			// nil labels would make matchPolicy bypass the selector entirely.
			minimizeTestVMI("ns2", "v2", map[string]string{"unused": "z"}, map[string]string{"tier": "gold"}),
		}

		report, err := MinimizeMigrationPolicyBasis(minimizeInput(policies, inventory, defaults))
		Expect(err).ToNot(HaveOccurred())
		Expect(report.Status).To(Equal(MinimizeStatusMinimum))
		Expect(report.LowerBound).To(Equal(2))
		Expect(report.UpperBound).To(Equal(2))
		Expect(report.BestKnown.PolicyNames).To(ConsistOf("p-high", "p-low"))

		By("each retained policy has a replay-backed deletion witness")
		Expect(report.DeletionWitnesses).To(HaveLen(2))
		highWitness := findWitness(report, "p-high")
		Expect(highWitness.Removable).To(BeFalse())
		Expect(highWitness.VMIKey).To(Equal("ns1/v1"))
		Expect(highWitness.BaselinePolicy).To(Equal("p-high"))
		Expect(highWitness.AfterRemovalPolicy).To(Equal("p-low"))
		Expect(highWitness.ChangedFields).To(ContainElement("AllowAutoConverge"))

		lowWitness := findWitness(report, "p-low")
		Expect(lowWitness.Removable).To(BeFalse())
		Expect(lowWitness.VMIKey).To(Equal("ns2/v2"))
		Expect(lowWitness.AfterRemovalPolicy).To(BeEmpty())
		Expect(lowWitness.ChangedFields).To(ContainElement("AllowAutoConverge"))

		expectBruteForceMinimum(report, policies, inventory, defaults)
	})

	It("accepts a different winner when the effective options stay identical", func() {
		// Both policies overlay the very same value; the winner name may change
		// while the effective options must not.
		policies := []migrationsv1.MigrationPolicy{
			minimizeTestPolicy("p1", map[string]string{"app": "x"}, nil,
				func(spec *migrationsv1.MigrationPolicySpec) { spec.AllowAutoConverge = pointer.P(true) }),
			minimizeTestPolicy("p2", nil, map[string]string{"tier": "gold"},
				func(spec *migrationsv1.MigrationPolicySpec) { spec.AllowAutoConverge = pointer.P(true) }),
		}
		inventory := []MinimizeMigrationPolicyVMI{
			minimizeTestVMI("ns1", "v1", map[string]string{"app": "x"}, map[string]string{"tier": "gold"}),
		}

		report, err := MinimizeMigrationPolicyBasis(minimizeInput(policies, inventory, defaults))
		Expect(err).ToNot(HaveOccurred())
		Expect(report.Status).To(Equal(MinimizeStatusMinimum))
		Expect(report.UpperBound).To(Equal(1))
		Expect(report.LowerBound).To(Equal(report.UpperBound))
		Expect(report.BestKnown.PolicyNames).To(HaveLen(1))
		Expect(report.BestKnown.PolicyNames[0]).To(BeElementOf("p1", "p2"))

		By("the size-one subset is replay verified even though the winner name differs from baseline")
		Expect(report.BestKnown.ReplayVerified).To(BeTrue())
		Expect(report.BestKnown.Observations).To(HaveLen(1))
		Expect(report.BestKnown.Observations[0].EffectiveEqualsBaseline).To(BeTrue())

		By("a name-only comparison would wrongly keep both policies")
		Expect(report.BestKnown.Observations[0].MatchedPolicy).ToNot(Equal("p1"))

		expectBruteForceMinimum(report, policies, inventory, defaults)
	})

	It("distinguishes explicit false from nil inheritance", func() {
		policies := []migrationsv1.MigrationPolicy{
			minimizeTestPolicy("p1", map[string]string{"app": "z"}, nil,
				func(spec *migrationsv1.MigrationPolicySpec) { spec.AllowPostCopy = pointer.P(false) }),
			// p2 matches with lower precedence but inherits nil for AllowPostCopy.
			minimizeTestPolicy("p2", nil, map[string]string{"tier": "silver"}, nil),
		}
		inventory := []MinimizeMigrationPolicyVMI{
			minimizeTestVMI("ns1", "v1", map[string]string{"app": "z"}, map[string]string{"tier": "silver"}),
		}

		report, err := MinimizeMigrationPolicyBasis(minimizeInput(policies, inventory, defaults))
		Expect(err).ToNot(HaveOccurred())
		Expect(report.Status).To(Equal(MinimizeStatusMinimum))
		Expect(report.BestKnown.PolicyNames).To(Equal([]string{"p1"}))

		witness := findWitness(report, "p1")
		Expect(witness.Removable).To(BeFalse())
		Expect(witness.ChangedFields).To(ContainElement("AllowPostCopy"))
		// The witness replays the minimum subset minus p1: p2 is not retained
		// in that subset, so v1 falls back to no winner and bare defaults.
		Expect(witness.AfterRemovalPolicy).To(BeEmpty())

		expectBruteForceMinimum(report, policies, inventory, defaults)
	})

	It("treats equal explicit values across winners as the same equivalence class", func() {
		// Both winners carry AllowPostCopy=false: switching winner keeps the
		// non-nil false value, so one policy suffices.
		policies := []migrationsv1.MigrationPolicy{
			minimizeTestPolicy("p1", map[string]string{"app": "z"}, nil,
				func(spec *migrationsv1.MigrationPolicySpec) { spec.AllowPostCopy = pointer.P(false) }),
			minimizeTestPolicy("p2", nil, map[string]string{"tier": "silver"},
				func(spec *migrationsv1.MigrationPolicySpec) { spec.AllowPostCopy = pointer.P(false) }),
		}
		inventory := []MinimizeMigrationPolicyVMI{
			minimizeTestVMI("ns1", "v1", map[string]string{"app": "z"}, map[string]string{"tier": "silver"}),
		}

		report, err := MinimizeMigrationPolicyBasis(minimizeInput(policies, inventory, defaults))
		Expect(err).ToNot(HaveOccurred())
		Expect(report.Status).To(Equal(MinimizeStatusMinimum))
		Expect(report.UpperBound).To(Equal(1))
		expectBruteForceMinimum(report, policies, inventory, defaults)
	})

	It("respects the VMI-label tie-break over namespace-label score and witnesses the exposed policy", func() {
		// Equal total score (2 labels each); the VMI-label policy wins and the
		// namespace-label policy only surfaces after its deletion.
		policies := []migrationsv1.MigrationPolicy{
			minimizeTestPolicy("p-vmi",
				map[string]string{"a": "1", "b": "2"}, nil,
				func(spec *migrationsv1.MigrationPolicySpec) {
					spec.MaxDowntimeMs = pointer.P(uint64(shortDowntimeValue))
				}),
			minimizeTestPolicy("p-ns",
				nil, map[string]string{"n": "1", "m": "2"},
				func(spec *migrationsv1.MigrationPolicySpec) {
					spec.MaxDowntimeMs = pointer.P(uint64(longDowntimeValue))
				}),
		}
		inventory := []MinimizeMigrationPolicyVMI{
			minimizeTestVMI("ns1", "v1",
				map[string]string{"a": "1", "b": "2"},
				map[string]string{"n": "1", "m": "2"}),
		}

		report, err := MinimizeMigrationPolicyBasis(minimizeInput(policies, inventory, defaults))
		Expect(err).ToNot(HaveOccurred())
		Expect(report.BestKnown.PolicyNames).To(Equal([]string{"p-vmi"}))
		Expect(report.BestKnown.Observations[0].MatchedPolicy).To(Equal("p-vmi"))

		// p-ns is not part of the minimum subset: removing p-vmi leaves the VMI
		// without any winner, yet its effective options still change.
		witness := findWitness(report, "p-vmi")
		Expect(witness.AfterRemovalPolicy).To(BeEmpty())
		Expect(witness.ChangedFields).To(ContainElement("MaxDowntimeMs"))

		expectBruteForceMinimum(report, policies, inventory, defaults)
	})

	It("keeps an undecided good policy that precedes a kept bad fallback in the preference chain", func() {
		// nsb matches all four policies. Its chain is d (winner), a, b, c;
		// only d reproduces the baseline, while b is a bad fallback that becomes
		// winner once d and a are removed. nsc is solely protected by b.
		policies := []migrationsv1.MigrationPolicy{
			minimizeTestPolicy("a", map[string]string{"v2": "v2-value"},
				map[string]string{"n0": "n0-value", "n1": "n1-value"},
				func(spec *migrationsv1.MigrationPolicySpec) { spec.AllowAutoConverge = pointer.P(true) }),
			minimizeTestPolicy("b", map[string]string{"v2": "v2-value"},
				map[string]string{"n0": "n0-value"},
				func(spec *migrationsv1.MigrationPolicySpec) {
					spec.CompletionTimeoutPerGiB = pointer.P(int64(shortTimeoutValue))
				}),
			minimizeTestPolicy("c", map[string]string{"v0": "v0-value"},
				map[string]string{"n0": "n0-value"},
				func(spec *migrationsv1.MigrationPolicySpec) { spec.AllowAutoConverge = pointer.P(true) }),
			minimizeTestPolicy("d", map[string]string{"v1": "v1-value", "v2": "v2-value"},
				map[string]string{"n1": "n1-value"},
				func(spec *migrationsv1.MigrationPolicySpec) { spec.AllowPostCopy = pointer.P(true) }),
		}
		inventory := []MinimizeMigrationPolicyVMI{
			minimizeTestVMI("nsa", "vmi",
				map[string]string{"v0": "v0-value", "v1": "v1-value"}, map[string]string{}),
			minimizeTestVMI("nsb", "vmi",
				map[string]string{"v0": "v0-value", "v1": "v1-value", "v2": "v2-value"},
				map[string]string{"n0": "n0-value", "n1": "n1-value"}),
			minimizeTestVMI("nsc", "vmi",
				map[string]string{"v2": "v2-value"}, map[string]string{"n0": "n0-value"}),
		}

		report, err := MinimizeMigrationPolicyBasis(minimizeInput(policies, inventory, defaults))
		Expect(err).ToNot(HaveOccurred())
		expectBruteForceMinimum(report, policies, inventory, defaults)
		Expect(report.BestKnown.PolicyNames).To(ConsistOf("b", "d"))

		dWitness := findWitness(report, "d")
		Expect(dWitness.VMIKey).To(Equal("nsb/vmi"))
		Expect(dWitness.ChangedFields).To(ContainElement("AllowPostCopy"))
		bWitness := findWitness(report, "b")
		Expect(bWitness.VMIKey).To(Equal("nsc/vmi"))
	})

	It("returns the empty subset when policies do not change the cluster defaults", func() {
		// The matched policy overlays nothing, so bare defaults equal baseline.
		policies := []migrationsv1.MigrationPolicy{
			minimizeTestPolicy("p-noop", map[string]string{"app": "x"}, nil, nil),
		}
		inventory := []MinimizeMigrationPolicyVMI{
			minimizeTestVMI("ns1", "v1", map[string]string{"app": "x"}, nil),
		}

		report, err := MinimizeMigrationPolicyBasis(minimizeInput(policies, inventory, defaults))
		Expect(err).ToNot(HaveOccurred())
		Expect(report.Status).To(Equal(MinimizeStatusMinimum))
		Expect(report.LowerBound).To(BeZero())
		Expect(report.UpperBound).To(BeZero())
		Expect(report.BestKnown.PolicyNames).To(BeEmpty())
		Expect(report.DeletionWitnesses).To(BeEmpty())
		expectBruteForceMinimum(report, policies, inventory, defaults)
	})

	It("returns the empty subset for an empty inventory", func() {
		policies := []migrationsv1.MigrationPolicy{
			minimizeTestPolicy("p1", map[string]string{"app": "x"}, nil,
				func(spec *migrationsv1.MigrationPolicySpec) { spec.AllowAutoConverge = pointer.P(true) }),
		}
		report, err := MinimizeMigrationPolicyBasis(minimizeInput(policies, nil, defaults))
		Expect(err).ToNot(HaveOccurred())
		Expect(report.Status).To(Equal(MinimizeStatusMinimum))
		Expect(report.UpperBound).To(BeZero())
		Expect(report.BestKnown.PolicyNames).To(BeEmpty())
	})

	It("marks the report Incomplete with an admissible bound when the node budget is exhausted", func() {
		policies := []migrationsv1.MigrationPolicy{
			minimizeTestPolicy("p1", map[string]string{"app": "x"}, nil,
				func(spec *migrationsv1.MigrationPolicySpec) { spec.AllowAutoConverge = pointer.P(true) }),
			minimizeTestPolicy("p2", nil, map[string]string{"tier": "gold"},
				func(spec *migrationsv1.MigrationPolicySpec) { spec.AllowAutoConverge = pointer.P(true) }),
			minimizeTestPolicy("p3", map[string]string{"app": "x"}, map[string]string{"tier": "gold"},
				func(spec *migrationsv1.MigrationPolicySpec) { spec.AllowAutoConverge = pointer.P(false) }),
		}
		inventory := []MinimizeMigrationPolicyVMI{
			minimizeTestVMI("ns1", "v1", map[string]string{"app": "x"}, map[string]string{"tier": "gold"}),
		}

		input := minimizeInput(policies, inventory, defaults)
		input.Limits.MaxSearchNodes = tightNodeBudget
		report, err := MinimizeMigrationPolicyBasis(input)
		Expect(err).ToNot(HaveOccurred())
		Expect(report.BudgetExhausted).To(BeTrue())
		Expect(report.Status).To(Equal(MinimizeStatusIncomplete))
		Expect(report.BestKnown).ToNot(BeNil())
		Expect(report.LowerBound).To(BeNumerically("<=", report.UpperBound))
		Expect(report.OptimalityProof).To(ContainSubstring("budget"))
		for _, candidate := range report.Candidates {
			Expect(candidate.ReplayVerified).To(BeTrue())
			for _, observation := range candidate.Observations {
				Expect(observation.EffectiveEqualsBaseline).To(BeTrue())
			}
		}

		By("the same instance without budget pressure reaches the certified minimum")
		fullReport, err := MinimizeMigrationPolicyBasis(minimizeInput(policies, inventory, defaults))
		Expect(err).ToNot(HaveOccurred())
		expectBruteForceMinimum(fullReport, policies, inventory, defaults)
	})

	It("never mutates the input objects", func() {
		policies := []migrationsv1.MigrationPolicy{
			minimizeTestPolicy("p1", map[string]string{"app": "x"}, nil,
				func(spec *migrationsv1.MigrationPolicySpec) { spec.AllowAutoConverge = pointer.P(true) }),
			minimizeTestPolicy("p2", nil, map[string]string{"tier": "gold"},
				func(spec *migrationsv1.MigrationPolicySpec) { spec.AllowAutoConverge = pointer.P(false) }),
		}
		inventory := []MinimizeMigrationPolicyVMI{
			minimizeTestVMI("ns1", "v1", map[string]string{"app": "x"}, map[string]string{"tier": "gold"}),
			minimizeTestVMI("ns2", "v2", map[string]string{"unused": "z"}, map[string]string{"tier": "gold"}),
		}
		input := minimizeInput(policies, inventory, defaults)

		before := snapshotMinimizeInput(input)
		_, err := MinimizeMigrationPolicyBasis(input)
		Expect(err).ToNot(HaveOccurred())
		Expect(snapshotMinimizeInput(input)).To(Equal(before))
	})

	It("pins identities and invalidates the digest on any inventory or config change", func() {
		policies := []migrationsv1.MigrationPolicy{
			minimizeTestPolicy("p1", map[string]string{"app": "x"}, nil,
				func(spec *migrationsv1.MigrationPolicySpec) { spec.AllowAutoConverge = pointer.P(true) }),
		}
		policies[0].UID = types.UID("policy-uid-1")
		policies[0].Generation = 7
		inventory := []MinimizeMigrationPolicyVMI{
			minimizeTestVMI("ns1", "v1", map[string]string{"app": "x"}, nil),
		}

		input := minimizeInput(policies, inventory, defaults)
		input.SourceDigest = "caller-digest"
		report, err := MinimizeMigrationPolicyBasis(input)
		Expect(err).ToNot(HaveOccurred())
		Expect(report.SourceDigest).To(Equal("caller-digest"))
		Expect(report.PolicyIdentity).To(ContainElement(Equal(PolicyIdentity{
			Name: "p1", UID: types.UID("policy-uid-1"), Generation: 7,
		})))
		Expect(report.VMIIdentity).To(ContainElement(Equal(VMIIdentity{
			Namespace: "ns1", Name: "v1", UID: types.UID("uid-ns1-v1"),
		})))
		Expect(report.ScopeWarning).ToNot(BeEmpty())

		rerun, err := MinimizeMigrationPolicyBasis(minimizeInput(policies, inventory, defaults))
		Expect(err).ToNot(HaveOccurred())
		Expect(rerun.ComputedDigest).To(Equal(report.ComputedDigest))

		By("changing a VMI label changes the digest")
		relabeledInventory := []MinimizeMigrationPolicyVMI{
			minimizeTestVMI("ns1", "v1", map[string]string{"app": "y"}, nil),
		}
		relabeledReport, err := MinimizeMigrationPolicyBasis(minimizeInput(policies, relabeledInventory, defaults))
		Expect(err).ToNot(HaveOccurred())
		Expect(relabeledReport.ComputedDigest).ToNot(Equal(report.ComputedDigest))

		By("changing a policy spec changes the digest")
		changedPolicies := []migrationsv1.MigrationPolicy{
			minimizeTestPolicy("p1", map[string]string{"app": "x"}, nil,
				func(spec *migrationsv1.MigrationPolicySpec) { spec.AllowAutoConverge = pointer.P(false) }),
		}
		changedPolicyReport, err := MinimizeMigrationPolicyBasis(minimizeInput(changedPolicies, inventory, defaults))
		Expect(err).ToNot(HaveOccurred())
		Expect(changedPolicyReport.ComputedDigest).ToNot(Equal(report.ComputedDigest))

		By("changing a policy UID changes the digest")
		uidPolicies := []migrationsv1.MigrationPolicy{*policies[0].DeepCopy()}
		uidPolicies[0].UID = types.UID("policy-uid-2")
		uidReport, err := MinimizeMigrationPolicyBasis(minimizeInput(uidPolicies, inventory, defaults))
		Expect(err).ToNot(HaveOccurred())
		Expect(uidReport.ComputedDigest).ToNot(Equal(report.ComputedDigest))

		By("changing the cluster defaults changes the digest")
		otherDefaults := defaults.DeepCopy()
		otherDefaults.CompletionTimeoutPerGiB = pointer.P(int64(changedDefaultsTimeout))
		defaultsReport, err := MinimizeMigrationPolicyBasis(minimizeInput(policies, inventory, otherDefaults))
		Expect(err).ToNot(HaveOccurred())
		Expect(defaultsReport.ComputedDigest).ToNot(Equal(report.ComputedDigest))
	})

	It("rejects invalid inputs", func() {
		validPolicy := minimizeTestPolicy("p1", map[string]string{"app": "x"}, nil, nil)
		validInventory := []MinimizeMigrationPolicyVMI{
			minimizeTestVMI("ns1", "v1", map[string]string{"app": "x"}, nil),
		}

		By("duplicate policy names")
		_, err := MinimizeMigrationPolicyBasis(minimizeInput(
			[]migrationsv1.MigrationPolicy{validPolicy, validPolicy}, validInventory, defaults))
		Expect(err).To(HaveOccurred())

		By("nil cluster defaults")
		_, err = MinimizeMigrationPolicyBasis(MinimizeMigrationPolicyBasisInput{
			Policies: []migrationsv1.MigrationPolicy{validPolicy}, Inventory: validInventory,
		})
		Expect(err).To(HaveOccurred())

		By("nil VMI or namespace")
		_, err = MinimizeMigrationPolicyBasis(MinimizeMigrationPolicyBasisInput{
			Policies:        []migrationsv1.MigrationPolicy{validPolicy},
			ClusterDefaults: defaults,
			Inventory:       []MinimizeMigrationPolicyVMI{{VMI: nil, Namespace: nil}},
		})
		Expect(err).To(HaveOccurred())

		By("duplicate inventory entries")
		_, err = MinimizeMigrationPolicyBasis(minimizeInput(
			[]migrationsv1.MigrationPolicy{validPolicy},
			[]MinimizeMigrationPolicyVMI{validInventory[0], validInventory[0]}, defaults))
		Expect(err).To(HaveOccurred())

		By("zero-valued limits are replaced by defaults")
		_, err = MinimizeMigrationPolicyBasis(minimizeInput([]migrationsv1.MigrationPolicy{validPolicy}, validInventory, defaults))
		Expect(err).ToNot(HaveOccurred())

		By("policy count over the explicit limit")
		overLimit := minimizeInput(
			[]migrationsv1.MigrationPolicy{validPolicy, minimizeTestPolicy("p2", nil, nil, nil)},
			validInventory, defaults)
		overLimit.Limits.MaxPolicies = 1
		_, err = MinimizeMigrationPolicyBasis(overLimit)
		Expect(err).To(HaveOccurred())

		By("VMI count over the explicit limit")
		twoVMIs := append([]MinimizeMigrationPolicyVMI{}, validInventory...)
		twoVMIs = append(twoVMIs, minimizeTestVMI("ns2", "v2", map[string]string{"app": "x"}, nil))
		overVMIs := minimizeInput([]migrationsv1.MigrationPolicy{validPolicy}, twoVMIs, defaults)
		overVMIs.Limits.MaxVMIs = 1
		_, err = MinimizeMigrationPolicyBasis(overVMIs)
		Expect(err).To(HaveOccurred())
	})

	It("matches an exhaustive all-subset oracle across randomized small fixtures", func() {
		for seed := int64(1); seed <= randomMinimizeSeeds; seed++ {
			// Up to 5 policies (32 subsets) and 4 VMIs, including fixtures with
			// nil label maps and all-nil policy specs.
			policyCount := baseRandomPolicyCount + int(seed%binaryChoiceCount)
			vmiCount := baseRandomVMICount + int(seed%binaryChoiceCount)
			fixture := newRandomMinimizeFixture(seed, policyCount, vmiCount)
			report, err := MinimizeMigrationPolicyBasis(minimizeInput(fixture.policies, fixture.inventory, fixture.defaults))
			Expect(err).ToNot(HaveOccurred())

			oracle := bruteForceCrossCheck(fixture.policies, fixture.inventory, fixture.defaults)
			Expect(report.Status).To(Equal(oracle.Status), "seed %d", seed)
			Expect(report.LowerBound).To(Equal(report.UpperBound), "seed %d", seed)
			Expect(report.UpperBound).To(Equal(oracle.UpperBound), "seed %d", seed)
			Expect(report.BestKnown.Size).To(Equal(oracle.UpperBound), "seed %d", seed)

			By("every incumbent is independently replayed and uses stable matchPolicy tie-breaking")
			for _, candidate := range report.Candidates {
				Expect(candidate.ReplayVerified).To(BeTrue(), "seed %d", seed)
				Expect(candidate.Size).To(BeNumerically(">=", report.UpperBound), "seed %d", seed)
				for _, observation := range candidate.Observations {
					Expect(observation.EffectiveEqualsBaseline).To(BeTrue(), "seed %d", seed)
					item := fixture.inventoryEntry(observation.VMIKey)
					Expect(item).ToNot(BeNil(), "seed %d", seed)
					list := kubecli.NewMinimalMigrationPolicyList(fixture.subsetPolicies(candidate.PolicyNames)...)
					winner := matchPolicy(list, item.VMI, item.Namespace)
					expectedName := ""
					if winner != nil {
						expectedName = winner.Name
					}
					Expect(observation.MatchedPolicy).To(Equal(expectedName), "seed %d", seed)
				}
			}

			By("every retained policy of the minimum subset has a local deletion witness")
			Expect(report.DeletionWitnesses).To(HaveLen(report.BestKnown.Size), "seed %d", seed)
			for _, name := range report.BestKnown.PolicyNames {
				witness := findWitness(report, name)
				Expect(witness.Removable).To(BeFalse(), "seed %d policy %s", seed, name)
				Expect(witness.VMIKey).ToNot(BeEmpty(), "seed %d policy %s", seed, name)
				Expect(witness.ChangedFields).ToNot(BeEmpty(), "seed %d policy %s", seed, name)
			}
		}
	})
})

func minimizeInput(policies []migrationsv1.MigrationPolicy, inventory []MinimizeMigrationPolicyVMI,
	defaults *v1.VMIMConfigurationOptions) MinimizeMigrationPolicyBasisInput {
	return MinimizeMigrationPolicyBasisInput{
		Policies:        policies,
		ClusterDefaults: defaults,
		Inventory:       inventory,
	}
}

func minimizeTestPolicy(name string, vmiSelector, namespaceSelector map[string]string,
	customize func(spec *migrationsv1.MigrationPolicySpec)) migrationsv1.MigrationPolicy {
	policy := kubecli.NewMinimalMigrationPolicy(name)
	policy.UID = types.UID("uid-" + name)
	policy.Generation = 1
	policy.Spec.Selectors = &migrationsv1.Selectors{
		VirtualMachineInstanceSelector: cloneStringMap(vmiSelector),
		NamespaceSelector:              cloneStringMap(namespaceSelector),
	}
	if customize != nil {
		customize(&policy.Spec)
	}
	return *policy
}

func minimizeTestVMI(namespace, name string, vmiLabels, namespaceLabels map[string]string) MinimizeMigrationPolicyVMI {
	return MinimizeMigrationPolicyVMI{
		VMI: &v1.VirtualMachineInstance{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: namespace,
				Name:      name,
				UID:       types.UID("uid-" + namespace + "-" + name),
				Labels:    cloneStringMap(vmiLabels),
			},
		},
		Namespace: &k8sv1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name:   namespace,
				Labels: cloneStringMap(namespaceLabels),
			},
		},
	}
}

func cloneStringMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func expectBruteForceMinimum(report *MinimizeMigrationPolicyBasisReport,
	policies []migrationsv1.MigrationPolicy, inventory []MinimizeMigrationPolicyVMI,
	defaults *v1.VMIMConfigurationOptions) {
	oracle := bruteForceCrossCheck(policies, inventory, defaults)
	Expect(report.Status).To(Equal(MinimizeStatusMinimum))
	Expect(report.LowerBound).To(Equal(report.UpperBound))
	Expect(report.UpperBound).To(Equal(oracle.UpperBound))
	Expect(report.BestKnown.Size).To(Equal(oracle.UpperBound))
}

func findWitness(report *MinimizeMigrationPolicyBasisReport, policyName string) MinimizeDeletionWitness {
	for _, witness := range report.DeletionWitnesses {
		if witness.RemovedPolicy == policyName {
			return witness
		}
	}
	Fail("missing deletion witness for policy " + policyName)
	return MinimizeDeletionWitness{}
}

func snapshotMinimizeInput(input MinimizeMigrationPolicyBasisInput) string {
	payload, err := json.Marshal(struct {
		Policies  []migrationsv1.MigrationPolicy
		Defaults  *v1.VMIMConfigurationOptions
		Inventory []MinimizeMigrationPolicyVMI
	}{
		Policies:  input.Policies,
		Defaults:  input.ClusterDefaults,
		Inventory: input.Inventory,
	})
	Expect(err).ToNot(HaveOccurred())
	return string(payload)
}

// bruteForceCrossCheck enumerates every keep/delete subset of the existing
// policies (test-only, small sets) and replays each subset through the
// original functions to derive the true global minimum.
func bruteForceCrossCheck(policies []migrationsv1.MigrationPolicy, inventory []MinimizeMigrationPolicyVMI,
	defaults *v1.VMIMConfigurationOptions) *MinimizeMigrationPolicyBasisReport {
	baseline := make([]*v1.VMIMConfigurationOptions, len(inventory))
	fullList := kubecli.NewMinimalMigrationPolicyList(policies...)
	for i, item := range inventory {
		winner := matchPolicy(fullList, item.VMI, item.Namespace)
		baseline[i] = defaults.DeepCopy()
		if winner != nil {
			baseline[i] = applyMigrationPolicySpec(defaults, &winner.Spec)
		}
	}

	minimumSize := len(policies) + 1
	for mask := 0; mask < (1 << len(policies)); mask++ {
		subset := make([]migrationsv1.MigrationPolicy, 0, len(policies))
		for i := range policies {
			if mask&(1<<i) != 0 {
				subset = append(subset, policies[i])
			}
		}
		list := kubecli.NewMinimalMigrationPolicyList(subset...)
		feasible := true
		for i, item := range inventory {
			winner := matchPolicy(list, item.VMI, item.Namespace)
			effective := defaults.DeepCopy()
			if winner != nil {
				effective = applyMigrationPolicySpec(defaults, &winner.Spec)
			}
			if !reflect.DeepEqual(effective, baseline[i]) {
				feasible = false
				break
			}
		}
		if feasible && len(subset) < minimumSize {
			minimumSize = len(subset)
		}
	}
	return &MinimizeMigrationPolicyBasisReport{
		Status:     MinimizeStatusMinimum,
		LowerBound: minimumSize,
		UpperBound: minimumSize,
	}
}

type randomMinimizeFixture struct {
	policies  []migrationsv1.MigrationPolicy
	inventory []MinimizeMigrationPolicyVMI
	defaults  *v1.VMIMConfigurationOptions
}

func newRandomMinimizeFixture(seed int64, policyCount, vmiCount int) randomMinimizeFixture {
	rng := rand.New(rand.NewSource(seed))
	vmiLabelKeys := []string{"v0", "v1", "v2"}
	nsLabelKeys := []string{"n0", "n1"}

	randomLabels := func(keys []string) map[string]string {
		labels := map[string]string{}
		for _, key := range keys {
			if rng.Intn(binaryChoiceCount) == 0 {
				labels[key] = key + "-value"
			}
		}
		if len(labels) == 0 && rng.Intn(binaryChoiceCount) == 0 {
			return nil
		}
		return labels
	}

	policies := make([]migrationsv1.MigrationPolicy, 0, policyCount)
	for i := 0; i < policyCount; i++ {
		name := string(rune('a' + i))
		policy := minimizeTestPolicy(name, randomLabels(vmiLabelKeys), randomLabels(nsLabelKeys),
			func(spec *migrationsv1.MigrationPolicySpec) {
				switch rng.Intn(randomChoiceCount) {
				case 0:
					spec.AllowAutoConverge = pointer.P(rng.Intn(binaryChoiceCount) == 0)
				case 1:
					spec.AllowPostCopy = pointer.P(rng.Intn(binaryChoiceCount) == 0)
				case 2:
					spec.CompletionTimeoutPerGiB = pointer.P(
						int64(timeoutBaseValue + rng.Intn(timeoutChoiceCount)*timeoutStepValue))
				default:
					// All-nil spec: the policy overlays nothing and the
					// effective options stay equal to the cluster defaults.
				}
			})
		policies = append(policies, policy)
	}

	inventory := make([]MinimizeMigrationPolicyVMI, 0, vmiCount)
	for i := 0; i < vmiCount; i++ {
		nsName := "ns" + string(rune('a'+i))
		inventory = append(inventory, minimizeTestVMI(nsName, "vmi", randomLabels(vmiLabelKeys),
			randomLabels(nsLabelKeys)))
	}

	return randomMinimizeFixture{
		policies:  policies,
		inventory: inventory,
		defaults:  &v1.VMIMConfigurationOptions{},
	}
}

func (f randomMinimizeFixture) inventoryEntry(key string) MinimizeMigrationPolicyVMI {
	for _, item := range f.inventory {
		if vmiKey(item.VMI) == key {
			return item
		}
	}
	return MinimizeMigrationPolicyVMI{}
}

func (f randomMinimizeFixture) subsetPolicies(names []string) []migrationsv1.MigrationPolicy {
	wanted := map[string]struct{}{}
	for _, name := range names {
		wanted[name] = struct{}{}
	}
	subset := make([]migrationsv1.MigrationPolicy, 0, len(names))
	for _, policy := range f.policies {
		if _, ok := wanted[policy.Name]; ok {
			subset = append(subset, policy)
		}
	}
	sort.Slice(subset, func(i, j int) bool { return subset[i].Name < subset[j].Name })
	return subset
}
