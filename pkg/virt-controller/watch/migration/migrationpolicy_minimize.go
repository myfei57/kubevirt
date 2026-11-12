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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"

	k8sv1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/types"

	k6tv1 "kubevirt.io/api/core/v1"
	"kubevirt.io/api/migrations/v1alpha1"
)

// MinimizeMigrationPolicyBasisStatus describes whether the returned subset is
// provably minimum or only the best known subset within the configured budget.
type MinimizeMigrationPolicyBasisStatus string

const (
	// MinimizeStatusMinimum means a provable lower bound equals the upper bound
	// (the size of the returned subset), i.e. no smaller equivalent subset exists
	// for the given, finite inventory.
	MinimizeStatusMinimum MinimizeMigrationPolicyBasisStatus = "Minimum"
	// MinimizeStatusIncomplete means the search budget was exhausted before a
	// provable optimum could be established. The report still carries the best
	// verified feasible subset and an admissible lower bound.
	MinimizeStatusIncomplete MinimizeMigrationPolicyBasisStatus = "Incomplete"
)

const (
	defaultMinimizeMaxPolicies          = 64
	defaultMinimizeMaxVMIs              = 500
	defaultMinimizeMaxSearchNodes       = 20000
	defaultMinimizeMaxVMIReplays        = 50000
	maxStoredMinimizeCandidates         = 100
	minimizeOptimalityProofExhaustive = "exhaustive branch-and-bound: every branch was either replayed with " +
		"matchPolicy/applyMigrationPolicySpec or pruned by an admissible lower bound"
	minimizeOptimalityProofBudgetCutoff = "search stopped after the evaluation budget was exhausted: the " +
		"decision tree was not fully explored and the lower bound remains admissible but not tight"
)

// MinimizeMigrationPolicyBasisLimits bounds the analysis. The zero value of
// every field is replaced by a conservative default. The limits exist because
// the result is only valid for the explicit, finite inventory handed in and
// must never turn into an unbounded cluster-wide scan.
type MinimizeMigrationPolicyBasisLimits struct {
	// MaxPolicies bounds the number of candidate MigrationPolicies.
	MaxPolicies int
	// MaxVMIs bounds the number of VMI/namespace pairs in the inventory.
	MaxVMIs int
	// MaxSearchNodes bounds the number of branch-and-bound decision nodes.
	MaxSearchNodes int
	// MaxVMIReplays bounds the number of per-VMI winner/effective resolutions,
	// i.e. matchPolicy evaluations plus the resulting applyMigrationPolicySpec
	// calls performed through the original production functions.
	MaxVMIReplays int
}

// MinimizeMigrationPolicyVMI pairs a VMI with the namespace object used for
// namespace-label matching. Both objects are read only.
type MinimizeMigrationPolicyVMI struct {
	VMI       *k6tv1.VirtualMachineInstance
	Namespace *k8sv1.Namespace
}

// MinimizeMigrationPolicyBasisInput is the immutable input of the analyzer.
// Nothing in this structure (nor any referenced object) is mutated.
type MinimizeMigrationPolicyBasisInput struct {
	// Policies is the fixed candidate set. The search domain is strictly the
	// keep/delete decision over these policies: no selectors are generated and
	// no policies are renamed or reordered.
	Policies []v1alpha1.MigrationPolicy
	// ClusterDefaults are the cluster-wide migration options (as produced by
	// migrationsutil.ToVMIMConfigurationOptions of the KubeVirt CR) that every
	// VMI inherits before a matched policy overlays its non-nil fields.
	ClusterDefaults *k6tv1.VMIMConfigurationOptions
	// Inventory is the explicit, finite set of VMIs covered by the analysis.
	Inventory []MinimizeMigrationPolicyVMI
	// Limits optionally overrides the built-in resource limits.
	Limits MinimizeMigrationPolicyBasisLimits
	// SourceDigest is an optional caller-supplied digest of the serialized
	// sources. It is echoed verbatim; the analyzer additionally computes its
	// own digest over the deep-copied inputs.
	SourceDigest string
}

// PolicyIdentity pins the exact policy revision a report was computed against.
type PolicyIdentity struct {
	Name       string
	UID        types.UID
	Generation int64
}

// VMIIdentity pins the exact VMI revision covered by a report.
type VMIIdentity struct {
	Namespace  string
	Name       string
	UID        types.UID
	Generation int64
}

// MinimizeVMIObservation records, for one VMI and one candidate subset, which
// policy wins through the original matchPolicy function and whether the
// resulting effective options are identical to the baseline.
type MinimizeVMIObservation struct {
	VMIKey string
	// MatchedPolicy is the winning policy name, or empty when no policy matches.
	MatchedPolicy string
	// EffectiveEqualsBaseline compares the fully resolved options, not names.
	EffectiveEqualsBaseline bool
}

// MinimizeMigrationPolicySubset describes one feasible, replay-verified subset.
type MinimizeMigrationPolicySubset struct {
	PolicyNames []string
	Size        int
	// ReplayVerified is always true for subsets emitted by the analyzer: the
	// subset was replayed for every inventory VMI through the original
	// matchPolicy and applyMigrationPolicySpec functions.
	ReplayVerified bool
	Observations   []MinimizeVMIObservation
}

// MinimizeDeletionWitness is the per-retained-policy counterexample showing
// that deleting the policy out of the reported subset changes the effective
// options of at least one VMI. A witness is a local necessity argument only;
// it cannot by itself prove global minimality.
type MinimizeDeletionWitness struct {
	RemovedPolicy string
	// VMIKey identifies the VMI whose effective options change.
	VMIKey string
	// BaselinePolicy is the winner within the reported subset.
	BaselinePolicy string
	// AfterRemovalPolicy is the winner after the deletion, or empty when no
	// policy matches anymore. This is precisely the "another policy exposed by
	// removing the current winner" case.
	AfterRemovalPolicy string
	// ChangedFields lists the effective-option field paths that differ.
	ChangedFields []string
	// Removable is true when no VMI changes upon deletion, i.e. the local
	// necessity argument does not hold for this policy.
	Removable bool
}

// MinimizeMigrationPolicyBasisReport is the analyzer result. It never mutates
// cluster state; it is an offline artifact bound to the pinned inputs.
type MinimizeMigrationPolicyBasisReport struct {
	Status MinimizeMigrationPolicyBasisStatus
	Reason string
	Limits MinimizeMigrationPolicyBasisLimits

	// Staleness protection: any change of policies, cluster defaults or the
	// inventory changes ComputedDigest and therefore invalidates the artifact.
	SourceDigest   string
	ComputedDigest string
	PolicyIdentity []PolicyIdentity
	VMIIdentity    []VMIIdentity
	PolicyCount    int
	VMICount       int

	// LowerBound is an admissible lower bound on the number of retained
	// policies. UpperBound is the size of BestKnown. The result is certified
	// Minimum only when LowerBound == UpperBound after an exhaustive search.
	LowerBound        int
	UpperBound        int
	PackingLowerBound int
	OptimalityProof   string
	BestKnown         *MinimizeMigrationPolicySubset
	Candidates        []MinimizeMigrationPolicySubset
	DeletionWitnesses []MinimizeDeletionWitness

	SearchNodes       int
	ReplayEvaluations int
	VMIReplays        int
	BudgetExhausted   bool

	// ScopeWarning reminds callers that the proof is relative to the finite
	// inventory and must not be read as a safety argument for future VMIs.
	ScopeWarning string
}

type minimizeDecision uint8

const (
	minimizeUndecided minimizeDecision = iota
	minimizeKeep
	minimizeRemove
)

// minimizeVMI holds, for one inventory VMI, its preference chain (the ordered
// list of matching policies produced by repeatedly calling matchPolicy) and
// the effective-config equivalence classes over that chain.
type minimizeVMI struct {
	key string
	vmi *k6tv1.VirtualMachineInstance
	ns  *k8sv1.Namespace

	baselineEffective *k6tv1.VMIMConfigurationOptions
	baselineWinner    string

	// chain contains policy indices in matchPolicy precedence order: the first
	// entry is the winner of the full set, the second is the winner once the
	// first is deleted, and so on.
	chain []int
	// good marks chain policies whose overlay yields options equal to baseline.
	good map[int]bool
	// noPolicyGood is true when the plain cluster defaults equal baseline.
	noPolicyGood bool
}

func (v *minimizeVMI) hasAnyUndecided(decisions []minimizeDecision) bool {
	for _, policyIdx := range v.chain {
		if decisions[policyIdx] == minimizeUndecided {
			return true
		}
	}
	return false
}

type migrationPolicyMinimizer struct {
	policies []v1alpha1.MigrationPolicy
	defaults *k6tv1.VMIMConfigurationOptions
	vmis     []*minimizeVMI
	limits   MinimizeMigrationPolicyBasisLimits

	decisions []minimizeDecision

	upperBound    int
	bestKnown     []int
	bestObs       []MinimizeVMIObservation
	candidates    []MinimizeMigrationPolicySubset
	seenCandidate map[string]bool

	searchNodes       int
	replayEvaluations int
	vmiReplays        int
	budgetExhausted   bool
	stopReason        string
	packingLowerBound int
}

// MinimizeMigrationPolicyBasis searches the minimum subset of the given
// MigrationPolicies that leaves every inventory VMI's final effective
// migration options exactly unchanged. The analysis is read-only, reuses
// matchPolicy and applyMigrationPolicySpec verbatim for every feasibility
// verdict, and only decides between keeping and deleting existing policies.
func MinimizeMigrationPolicyBasis(input MinimizeMigrationPolicyBasisInput) (*MinimizeMigrationPolicyBasisReport, error) {
	limits := normalizeMinimizeLimits(input.Limits)

	if len(input.Policies) > limits.MaxPolicies {
		return nil, fmt.Errorf("migration policy count %d exceeds limit %d", len(input.Policies), limits.MaxPolicies)
	}
	if len(input.Inventory) > limits.MaxVMIs {
		return nil, fmt.Errorf("VMI inventory count %d exceeds limit %d", len(input.Inventory), limits.MaxVMIs)
	}
	if input.ClusterDefaults == nil {
		return nil, fmt.Errorf("cluster defaults must not be nil")
	}

	policies := make([]v1alpha1.MigrationPolicy, 0, len(input.Policies))
	names := make(map[string]struct{}, len(input.Policies))
	for _, policy := range input.Policies {
		if policy.Name == "" {
			return nil, fmt.Errorf("every migration policy must have a name")
		}
		if _, exists := names[policy.Name]; exists {
			return nil, fmt.Errorf("duplicate migration policy name %q: names drive the matchPolicy tie-break", policy.Name)
		}
		names[policy.Name] = struct{}{}
		policies = append(policies, *policy.DeepCopy())
	}

	defaults := input.ClusterDefaults.DeepCopy()

	vmis := make([]*minimizeVMI, 0, len(input.Inventory))
	for _, item := range input.Inventory {
		if item.VMI == nil || item.Namespace == nil {
			return nil, fmt.Errorf("inventory entries must contain both a VMI and its namespace")
		}
		key := vmiKey(item.VMI)
		for _, existing := range vmis {
			if existing.key == key {
				return nil, fmt.Errorf("duplicate inventory entry %q", key)
			}
		}
		vmis = append(vmis, &minimizeVMI{
			key: key,
			vmi: item.VMI.DeepCopy(),
			ns:  item.Namespace.DeepCopy(),
		})
	}

	digest, err := computeMinimizeDigest(defaults, policies, vmis)
	if err != nil {
		return nil, err
	}

	m := &migrationPolicyMinimizer{
		policies:      policies,
		defaults:      defaults,
		vmis:          vmis,
		limits:        limits,
		decisions:     make([]minimizeDecision, len(policies)),
		upperBound:    len(policies),
		seenCandidate: make(map[string]bool),
	}

	if err := m.buildBaselinesAndChains(); err != nil {
		return nil, err
	}

	if len(vmis) == 0 {
		// With no VMI to protect, every policy is removable.
		m.bestKnown = nil
		m.bestObs = nil
		m.recordCandidate(nil, nil)
		return m.buildReport(input.SourceDigest, digest), nil
	}

	// The full set is feasible by definition and was verified while building
	// the baselines.
	fullSet := make([]int, len(policies))
	for idx := range policies {
		fullSet[idx] = idx
	}
	m.bestKnown = fullSet
	m.bestObs = m.observeBaseline()
	m.recordCandidate(fullSet, m.bestObs)
	m.packingLowerBound = m.disjointNeedsPacking(m.openNeeds())

	m.dfs()

	return m.buildReport(input.SourceDigest, digest), nil
}

func normalizeMinimizeLimits(limits MinimizeMigrationPolicyBasisLimits) MinimizeMigrationPolicyBasisLimits {
	if limits.MaxPolicies <= 0 {
		limits.MaxPolicies = defaultMinimizeMaxPolicies
	}
	if limits.MaxVMIs <= 0 {
		limits.MaxVMIs = defaultMinimizeMaxVMIs
	}
	if limits.MaxSearchNodes <= 0 {
		limits.MaxSearchNodes = defaultMinimizeMaxSearchNodes
	}
	if limits.MaxVMIReplays <= 0 {
		limits.MaxVMIReplays = defaultMinimizeMaxVMIReplays
	}
	return limits
}

// buildBaselinesAndChains resolves, per VMI, the baseline effective options and
// the matchPolicy preference chain, and partitions the chain into effective
// config equivalence classes (good vs. bad relative to baseline).
func (m *migrationPolicyMinimizer) buildBaselinesAndChains() error {
	for _, vmiModel := range m.vmis {
		baselineList := &v1alpha1.MigrationPolicyList{Items: m.policies}
		baselineWinner := matchPolicy(baselineList, vmiModel.vmi, vmiModel.ns)
		m.vmiReplays++

		vmiModel.baselineEffective = m.defaults.DeepCopy()
		if baselineWinner != nil {
			vmiModel.baselineWinner = baselineWinner.Name
			vmiModel.baselineEffective = applyMigrationPolicySpec(m.defaults, &baselineWinner.Spec)
		}

		// Repeatedly ask matchPolicy for the winner of the remaining policies.
		// Deleting the previous winner is the only way to expose the next
		// precedence level, which also captures the shadowing semantics
		// exactly: policies that never win on the full set may still win after
		// a deletion.
		excluded := make([]bool, len(m.policies))
		for {
			remaining := make([]v1alpha1.MigrationPolicy, 0, len(m.policies))
			for idx, policy := range m.policies {
				if !excluded[idx] {
					remaining = append(remaining, policy)
				}
			}
			winner := matchPolicy(&v1alpha1.MigrationPolicyList{Items: remaining}, vmiModel.vmi, vmiModel.ns)
			m.vmiReplays++
			if winner == nil {
				break
			}
			winnerIdx, ok := m.policyIndex(winner.Name)
			if !ok {
				return fmt.Errorf("internal error: matchPolicy returned unknown policy %q", winner.Name)
			}
			vmiModel.chain = append(vmiModel.chain, winnerIdx)
			excluded[winnerIdx] = true
		}

		vmiModel.good = make(map[int]bool, len(vmiModel.chain))
		for _, policyIdx := range vmiModel.chain {
			policy := m.policies[policyIdx]
			effective := applyMigrationPolicySpec(m.defaults, &policy.Spec)
			vmiModel.good[policyIdx] = equality.Semantic.DeepEqual(effective, vmiModel.baselineEffective)
		}
		vmiModel.noPolicyGood = equality.Semantic.DeepEqual(m.defaults, vmiModel.baselineEffective)
	}
	return m.checkReplayBudget()
}

// replay evaluates a subset through the original production functions for
// every inventory VMI. It is the sole feasibility authority for incumbents
// and deletion witnesses.
func (m *migrationPolicyMinimizer) replay(keptIndices []int) ([]MinimizeVMIObservation, bool, error) {
	if err := m.checkReplayBudgetFor(len(m.vmis)); err != nil {
		return nil, false, err
	}
	m.replayEvaluations++

	items := make([]v1alpha1.MigrationPolicy, 0, len(keptIndices))
	for _, idx := range keptIndices {
		items = append(items, m.policies[idx])
	}
	list := &v1alpha1.MigrationPolicyList{Items: items}

	observations := make([]MinimizeVMIObservation, 0, len(m.vmis))
	allEqual := true
	for _, vmiModel := range m.vmis {
		m.vmiReplays++
		matched := matchPolicy(list, vmiModel.vmi, vmiModel.ns)
		effective := m.defaults
		matchedName := ""
		if matched != nil {
			matchedName = matched.Name
			effective = applyMigrationPolicySpec(m.defaults, &matched.Spec)
		}
		equalsBaseline := equality.Semantic.DeepEqual(effective, vmiModel.baselineEffective)
		if !equalsBaseline {
			allEqual = false
		}
		observations = append(observations, MinimizeVMIObservation{
			VMIKey:                  vmiModel.key,
			MatchedPolicy:           matchedName,
			EffectiveEqualsBaseline: equalsBaseline,
		})
	}
	return observations, allEqual, nil
}

func (m *migrationPolicyMinimizer) observeBaseline() []MinimizeVMIObservation {
	observations := make([]MinimizeVMIObservation, 0, len(m.vmis))
	for _, vmiModel := range m.vmis {
		observations = append(observations, MinimizeVMIObservation{
			VMIKey:                  vmiModel.key,
			MatchedPolicy:           vmiModel.baselineWinner,
			EffectiveEqualsBaseline: true,
		})
	}
	return observations
}

// dfs is the branch-and-bound search over one keep/remove decision per policy.
// Label selectors are never enumerated: the per-VMI preference chain already
// encodes every reachable winner, so the decision tree has at most 2^n nodes
// over n existing policies and is pruned by an admissible lower bound.
func (m *migrationPolicyMinimizer) dfs() {
	if m.budgetExhausted {
		return
	}
	m.searchNodes++
	if m.searchNodes > m.limits.MaxSearchNodes {
		m.budgetExhausted = true
		m.stopReason = fmt.Sprintf("search node limit %d reached", m.limits.MaxSearchNodes)
		return
	}

	keptCount := 0
	for _, decision := range m.decisions {
		if decision == minimizeKeep {
			keptCount++
		}
	}

	openNeeds := make(map[int][]int)
	for vmiIdx, vmiModel := range m.vmis {
		violated, needPolicies := m.classifyVMI(vmiModel)
		if violated {
			return
		}
		if len(needPolicies) > 0 {
			openNeeds[vmiIdx] = needPolicies
		}
	}

	if len(openNeeds) == 0 {
		// Every VMI is satisfied by the fixed decisions. Policies still
		// undecided cannot help any VMI and are therefore removed.
		subset := make([]int, 0, keptCount)
		for idx, decision := range m.decisions {
			if decision == minimizeKeep {
				subset = append(subset, idx)
			}
		}
		observations, feasible, err := m.replay(subset)
		if err != nil {
			m.budgetExhausted = true
			m.stopReason = err.Error()
			return
		}
		if feasible {
			m.recordCandidate(subset, observations)
			if len(subset) < m.upperBound {
				m.upperBound = len(subset)
				m.bestKnown = append([]int(nil), subset...)
				m.bestObs = observations
			}
		}
		return
	}

	lowerBound := keptCount + m.disjointNeedsPacking(openNeeds)
	if lowerBound >= m.upperBound {
		// Even an admissible, optimistic count cannot beat the incumbent.
		return
	}

	branch := m.selectBranchVariable(openNeeds)
	// Remove first drives straight toward small subsets; the keep branch
	// preserves feasibility for VMIs that depend on this policy.
	m.decisions[branch] = minimizeRemove
	m.dfs()
	m.decisions[branch] = minimizeUndecided
	if m.budgetExhausted {
		return
	}
	m.decisions[branch] = minimizeKeep
	m.dfs()
	m.decisions[branch] = minimizeUndecided
}

// classifyVMI evaluates one VMI under the current partial decisions. It
// returns violated=true when no extension can keep the VMI on its baseline,
// and needPolicies with the undecided good policies that must still be
// decided when at least one additional keep is required. A nil/empty
// needPolicies result means the VMI is already satisfiable with the fixed
// decisions and remaining removals.
func (m *migrationPolicyMinimizer) classifyVMI(vmiModel *minimizeVMI) (violated bool, needPolicies []int) {
	// Policies before the first kept one can still win while undecided, so a
	// kept policy is the fixed winner only when every earlier policy is
	// removed. Track the undecided prefix separately.
	var undecidedGood []int
	fixedKeepIdx := 0
	hasFixedKeep := false
	for _, policyIdx := range vmiModel.chain {
		switch m.decisions[policyIdx] {
		case minimizeKeep:
			fixedKeepIdx = policyIdx
			hasFixedKeep = true
		case minimizeRemove:
			continue
		default:
			if !hasFixedKeep && vmiModel.good[policyIdx] {
				undecidedGood = append(undecidedGood, policyIdx)
			}
		}
		if hasFixedKeep {
			break
		}
	}

	if !hasFixedKeep {
		// No kept policy participates in this chain.
		if len(undecidedGood) == 0 && !vmiModel.hasAnyUndecided(m.decisions) && !vmiModel.noPolicyGood {
			// Every matching policy is removed and bare defaults differ.
			return true, nil
		}
		if len(undecidedGood) == 0 && !vmiModel.noPolicyGood {
			// Only undecided bad policies remain and bare defaults differ from
			// baseline, so no extension can restore the options.
			return true, nil
		}
		// When bare defaults already equal the baseline, the VMI needs no
		// retained policy at all and must not inflate the lower bound.
		if len(undecidedGood) > 0 && !vmiModel.noPolicyGood {
			return false, undecidedGood
		}
		return false, nil
	}

	// A kept policy exists but undecided policies precede it in precedence.
	if len(undecidedGood) == 0 && !vmiModel.good[fixedKeepIdx] {
		// Neither the undecided prefix nor the kept fallback can reproduce the
		// baseline: every extension is infeasible for this VMI.
		return true, nil
	}
	if vmiModel.good[fixedKeepIdx] {
		// Removing every undecided prefix policy already yields a good outcome,
		// so no additional kept policy is required.
		return false, nil
	}
	// The kept fallback is bad: at least one undecided good prefix policy must
	// be kept to win ahead of it.
	return false, undecidedGood
}

// openNeeds at the root (all decisions undecided) seeds the certified lower
// bound reported even when the budget is exhausted.
func (m *migrationPolicyMinimizer) openNeeds() map[int][]int {
	needs := make(map[int][]int)
	for vmiIdx, vmiModel := range m.vmis {
		if vmiModel.noPolicyGood {
			continue
		}
		good := make([]int, 0, len(vmiModel.chain))
		for _, policyIdx := range vmiModel.chain {
			if vmiModel.good[policyIdx] {
				good = append(good, policyIdx)
			}
		}
		if len(good) > 0 {
			needs[vmiIdx] = good
		}
	}
	return needs
}

// disjointNeedsPacking returns a greedy maximal packing of pairwise disjoint
// need sets. Each packed VMI requires a distinct retained policy, hence the
// packing size is an admissible lower bound. Greedy smallest-set-first is
// deterministic and never overestimates the maximum packing.
func (m *migrationPolicyMinimizer) disjointNeedsPacking(needs map[int][]int) int {
	vmis := make([]int, 0, len(needs))
	for vmiIdx := range needs {
		vmis = append(vmis, vmiIdx)
	}
	sort.Slice(vmis, func(i, j int) bool {
		if len(needs[vmis[i]]) != len(needs[vmis[j]]) {
			return len(needs[vmis[i]]) < len(needs[vmis[j]])
		}
		return vmis[i] < vmis[j]
	})

	usedPolicies := make(map[int]struct{})
	packing := 0
	for _, vmiIdx := range vmis {
		disjoint := true
		for _, policyIdx := range needs[vmiIdx] {
			if _, used := usedPolicies[policyIdx]; used {
				disjoint = false
				break
			}
		}
		if !disjoint {
			continue
		}
		packing++
		for _, policyIdx := range needs[vmiIdx] {
			usedPolicies[policyIdx] = struct{}{}
		}
	}
	return packing
}

// selectBranchVariable picks the undecided policy that covers the most open
// VMIs, which yields the strongest pruning. Ties break on the stable policy
// index so runs are deterministic.
func (m *migrationPolicyMinimizer) selectBranchVariable(needs map[int][]int) int {
	frequency := make([]int, len(m.policies))
	for _, goodPolicies := range needs {
		for _, policyIdx := range goodPolicies {
			frequency[policyIdx]++
		}
	}
	chosen, hasChoice := 0, false
	for idx := range m.policies {
		if m.decisions[idx] != minimizeUndecided || frequency[idx] == 0 {
			continue
		}
		if !hasChoice || frequency[idx] > frequency[chosen] ||
			(frequency[idx] == frequency[chosen] && idx < chosen) {
			chosen = idx
			hasChoice = true
		}
	}
	if hasChoice {
		return chosen
	}
	// Defensive fallback: any undecided policy keeps the tree moving.
	for idx, decision := range m.decisions {
		if decision == minimizeUndecided {
			return idx
		}
	}
	return chosen
}

func (m *migrationPolicyMinimizer) recordCandidate(subset []int, observations []MinimizeVMIObservation) {
	names := m.subsetNames(subset)
	key := strings.Join(names, "|")
	if m.seenCandidate[key] {
		return
	}
	m.seenCandidate[key] = true
	if len(m.candidates) >= maxStoredMinimizeCandidates {
		return
	}
	m.candidates = append(m.candidates, MinimizeMigrationPolicySubset{
		PolicyNames:    names,
		Size:           len(names),
		ReplayVerified: true,
		Observations:   append([]MinimizeVMIObservation(nil), observations...),
	})
}

func (m *migrationPolicyMinimizer) buildDeletionWitnesses() []MinimizeDeletionWitness {
	witnesses := make([]MinimizeDeletionWitness, 0, len(m.bestKnown))
	for _, removedIdx := range m.bestKnown {
		reduced := make([]int, 0, len(m.bestKnown)-1)
		for _, idx := range m.bestKnown {
			if idx != removedIdx {
				reduced = append(reduced, idx)
			}
		}
		observations, _, err := m.replay(reduced)
		witness := MinimizeDeletionWitness{
			RemovedPolicy: m.policies[removedIdx].Name,
			Removable:     true,
		}
		if err != nil {
			// Budget ran out during witness generation: report the policy as
			// not witnessed rather than fabricating a counterexample.
			m.budgetExhausted = true
			if m.stopReason == "" {
				m.stopReason = err.Error()
			}
			witnesses = append(witnesses, witness)
			continue
		}
		for _, observation := range observations {
			if observation.EffectiveEqualsBaseline {
				continue
			}
			vmiModel := m.vmiByName(observation.VMIKey)
			changed := diffEffectiveOptions(m.effectiveOptionsFor(m.bestKnown, vmiModel),
				m.effectiveOptionsFor(reduced, vmiModel))
			witness = MinimizeDeletionWitness{
				RemovedPolicy:      m.policies[removedIdx].Name,
				VMIKey:             observation.VMIKey,
				BaselinePolicy:     m.winnerInBestKnown(observation.VMIKey),
				AfterRemovalPolicy: observation.MatchedPolicy,
				ChangedFields:      changed,
			}
			break
		}
		witnesses = append(witnesses, witness)
	}
	return witnesses
}

func (m *migrationPolicyMinimizer) winnerInBestKnown(key string) string {
	for _, observation := range m.bestObs {
		if observation.VMIKey == key {
			return observation.MatchedPolicy
		}
	}
	return ""
}

func (m *migrationPolicyMinimizer) vmiByName(key string) *minimizeVMI {
	for _, vmiModel := range m.vmis {
		if vmiModel.key == key {
			return vmiModel
		}
	}
	return nil
}

// effectiveOptionsFor resolves one VMI's options under an arbitrary subset via
// the original functions. It is used only to describe witness field changes,
// after a full replay already established that the VMI changes.
func (m *migrationPolicyMinimizer) effectiveOptionsFor(keptIndices []int, vmiModel *minimizeVMI) *k6tv1.VMIMConfigurationOptions {
	m.vmiReplays++
	items := make([]v1alpha1.MigrationPolicy, 0, len(keptIndices))
	for _, idx := range keptIndices {
		items = append(items, m.policies[idx])
	}
	matched := matchPolicy(&v1alpha1.MigrationPolicyList{Items: items}, vmiModel.vmi, vmiModel.ns)
	if matched == nil {
		return m.defaults.DeepCopy()
	}
	return applyMigrationPolicySpec(m.defaults, &matched.Spec)
}

func (m *migrationPolicyMinimizer) buildReport(sourceDigest, computedDigest string) *MinimizeMigrationPolicyBasisReport {
	witnesses := m.buildDeletionWitnesses()

	bestSubset := &MinimizeMigrationPolicySubset{
		PolicyNames:    m.subsetNames(m.bestKnown),
		Size:           len(m.bestKnown),
		ReplayVerified: true,
		Observations:   append([]MinimizeVMIObservation(nil), m.bestObs...),
	}

	lowerBound := m.packingLowerBound
	status := MinimizeStatusMinimum
	proof := minimizeOptimalityProofExhaustive
	reason := ""
	if m.budgetExhausted {
		status = MinimizeStatusIncomplete
		proof = minimizeOptimalityProofBudgetCutoff
		reason = m.stopReason
	} else {
		// An exhaustive, correctly pruned search certifies the incumbent size.
		lowerBound = len(m.bestKnown)
	}
	if lowerBound > len(m.bestKnown) {
		// Defensive invariant: an admissible bound can never exceed the
		// verified feasible incumbent size.
		lowerBound = len(m.bestKnown)
	}

	return &MinimizeMigrationPolicyBasisReport{
		Status:            status,
		Reason:            reason,
		Limits:            m.limits,
		SourceDigest:      sourceDigest,
		ComputedDigest:    computedDigest,
		PolicyIdentity:    buildPolicyIdentities(m.policies),
		VMIIdentity:       buildVMIIdentities(m.vmis),
		PolicyCount:       len(m.policies),
		VMICount:          len(m.vmis),
		LowerBound:        lowerBound,
		UpperBound:        len(m.bestKnown),
		PackingLowerBound: m.packingLowerBound,
		OptimalityProof:   proof,
		BestKnown:         bestSubset,
		Candidates:        append([]MinimizeMigrationPolicySubset(nil), m.candidates...),
		DeletionWitnesses: witnesses,
		SearchNodes:       m.searchNodes,
		ReplayEvaluations: m.replayEvaluations,
		VMIReplays:        m.vmiReplays,
		BudgetExhausted:   m.budgetExhausted,
		ScopeWarning: "the minimum is proven only for the explicit VMI/namespace inventory and fixed policy set; " +
			"new VMIs, changed labels, policy revisions or cluster config changes invalidate this artifact and " +
			"must not be assumed safe to delete against",
	}
}

func (m *migrationPolicyMinimizer) policyIndex(name string) (int, bool) {
	for idx, policy := range m.policies {
		if policy.Name == name {
			return idx, true
		}
	}
	return 0, false
}

func (m *migrationPolicyMinimizer) subsetNames(indices []int) []string {
	names := make([]string, 0, len(indices))
	for _, idx := range indices {
		names = append(names, m.policies[idx].Name)
	}
	sort.Strings(names)
	return names
}

func (m *migrationPolicyMinimizer) checkReplayBudget() error {
	if m.vmiReplays > m.limits.MaxVMIReplays {
		m.budgetExhausted = true
		m.stopReason = fmt.Sprintf("VMI replay limit %d reached", m.limits.MaxVMIReplays)
		return fmt.Errorf("%s", m.stopReason)
	}
	return nil
}

func (m *migrationPolicyMinimizer) checkReplayBudgetFor(additional int) error {
	if m.vmiReplays+additional > m.limits.MaxVMIReplays {
		m.budgetExhausted = true
		m.stopReason = fmt.Sprintf("VMI replay limit %d reached", m.limits.MaxVMIReplays)
		return fmt.Errorf("%s", m.stopReason)
	}
	return nil
}

func vmiKey(vmi *k6tv1.VirtualMachineInstance) string {
	return fmt.Sprintf("%s/%s", vmi.Namespace, vmi.Name)
}

func buildPolicyIdentities(policies []v1alpha1.MigrationPolicy) []PolicyIdentity {
	identities := make([]PolicyIdentity, 0, len(policies))
	for _, policy := range policies {
		identities = append(identities, PolicyIdentity{
			Name:       policy.Name,
			UID:        policy.UID,
			Generation: policy.Generation,
		})
	}
	sort.Slice(identities, func(i, j int) bool { return identities[i].Name < identities[j].Name })
	return identities
}

func buildVMIIdentities(vmis []*minimizeVMI) []VMIIdentity {
	identities := make([]VMIIdentity, 0, len(vmis))
	for _, vmiModel := range vmis {
		identities = append(identities, VMIIdentity{
			Namespace:  vmiModel.vmi.Namespace,
			Name:       vmiModel.vmi.Name,
			UID:        vmiModel.vmi.UID,
			Generation: vmiModel.vmi.Generation,
		})
	}
	sort.Slice(identities, func(i, j int) bool {
		if identities[i].Namespace != identities[j].Namespace {
			return identities[i].Namespace < identities[j].Namespace
		}
		return identities[i].Name < identities[j].Name
	})
	return identities
}

// digestDocument is the canonical serialization covering every input that can
// influence matching or effective options.
type digestDocument struct {
	ClusterDefaults *k6tv1.VMIMConfigurationOptions
	Policies        []v1alpha1.MigrationPolicy
	Inventory       []digestInventoryEntry
}

type digestInventoryEntry struct {
	Namespace       string
	Name            string
	UID             types.UID
	Generation      int64
	VMILabels       map[string]string
	NamespaceLabels map[string]string
}

func computeMinimizeDigest(defaults *k6tv1.VMIMConfigurationOptions, policies []v1alpha1.MigrationPolicy,
	vmis []*minimizeVMI) (string, error) {
	sortedPolicies := append([]v1alpha1.MigrationPolicy(nil), policies...)
	sort.Slice(sortedPolicies, func(i, j int) bool { return sortedPolicies[i].Name < sortedPolicies[j].Name })

	inventory := make([]digestInventoryEntry, 0, len(vmis))
	for _, vmiModel := range vmis {
		inventory = append(inventory, digestInventoryEntry{
			Namespace:       vmiModel.vmi.Namespace,
			Name:            vmiModel.vmi.Name,
			UID:             vmiModel.vmi.UID,
			Generation:      vmiModel.vmi.Generation,
			VMILabels:       vmiModel.vmi.Labels,
			NamespaceLabels: vmiModel.ns.Labels,
		})
	}
	sort.Slice(inventory, func(i, j int) bool {
		if inventory[i].Namespace != inventory[j].Namespace {
			return inventory[i].Namespace < inventory[j].Namespace
		}
		return inventory[i].Name < inventory[j].Name
	})

	payload, err := json.Marshal(digestDocument{
		ClusterDefaults: defaults,
		Policies:        sortedPolicies,
		Inventory:       inventory,
	})
	if err != nil {
		return "", fmt.Errorf("failed to canonicalize minimize input: %w", err)
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:]), nil
}

// diffEffectiveOptions lists the field paths whose effective values differ.
// Pointer fields compare nil-ness and dereferenced values; nested option
// structs are reported with dotted paths.
func diffEffectiveOptions(a, b *k6tv1.VMIMConfigurationOptions) []string {
	var changed []string
	va := reflect.ValueOf(a).Elem()
	vb := reflect.ValueOf(b).Elem()
	ta := va.Type()
	for i := 0; i < ta.NumField(); i++ {
		fieldName := ta.Field(i).Name
		fa, fb := va.Field(i), vb.Field(i)
		if fa.Kind() != reflect.Ptr {
			if !reflect.DeepEqual(fa.Interface(), fb.Interface()) {
				changed = append(changed, fieldName)
			}
			continue
		}
		switch {
		case fa.IsNil() || fb.IsNil():
			if fa.IsNil() != fb.IsNil() {
				changed = append(changed, fieldName)
			}
		case fa.Elem().Kind() == reflect.Struct:
			changed = append(changed, diffPointerStructs(fieldName, fa, fb)...)
		default:
			if !reflect.DeepEqual(fa.Interface(), fb.Interface()) {
				changed = append(changed, fieldName)
			}
		}
	}
	sort.Strings(changed)
	return changed
}

func diffPointerStructs(prefix string, a, b reflect.Value) []string {
	var changed []string
	ea, eb := a.Elem(), b.Elem()
	ta := ea.Type()
	for i := 0; i < ta.NumField(); i++ {
		path := prefix + "." + ta.Field(i).Name
		fa, fb := ea.Field(i), eb.Field(i)
		if fa.Kind() == reflect.Ptr {
			if fa.IsNil() || fb.IsNil() {
				if fa.IsNil() != fb.IsNil() {
					changed = append(changed, path)
				}
				continue
			}
			if fa.Elem().Kind() == reflect.Struct {
				changed = append(changed, diffPointerStructs(path, fa, fb)...)
				continue
			}
		}
		if !reflect.DeepEqual(fa.Interface(), fb.Interface()) {
			changed = append(changed, path)
		}
	}
	sort.Strings(changed)
	return changed
}
