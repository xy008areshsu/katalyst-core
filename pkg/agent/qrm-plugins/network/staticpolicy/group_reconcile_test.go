/*
Copyright 2022 The Katalyst Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package staticpolicy

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	apiconsts "github.com/kubewharf/katalyst-api/pkg/consts"

	"github.com/kubewharf/katalyst-core/pkg/agent/qrm-plugins/commonstate"
	"github.com/kubewharf/katalyst-core/pkg/agent/qrm-plugins/network/state"
	"github.com/kubewharf/katalyst-core/pkg/agent/qrm-plugins/network/staticpolicy/nic"
	"github.com/kubewharf/katalyst-core/pkg/config/agent/qrm"
	metricconsts "github.com/kubewharf/katalyst-core/pkg/consts"
	"github.com/kubewharf/katalyst-core/pkg/metaserver"
	metaserveragent "github.com/kubewharf/katalyst-core/pkg/metaserver/agent"
	"github.com/kubewharf/katalyst-core/pkg/metaserver/agent/metric"
	"github.com/kubewharf/katalyst-core/pkg/metrics"
	"github.com/kubewharf/katalyst-core/pkg/util/machine"
	utilmetric "github.com/kubewharf/katalyst-core/pkg/util/metric"
	qrmgeneral "github.com/kubewharf/katalyst-core/pkg/util/qrm"
)

// ---- fakeState: a minimal state.State that just returns a fixed NICMap ----

type fakeState struct {
	state.State
	machineState state.NICMap
}

func (f *fakeState) GetMachineState() state.NICMap { return f.machineState }

// ---- helpers to build a policy wired for generateGroups ----

func newReconcileTestConf() *qrm.NetworkQRMPluginConfig {
	return &qrm.NetworkQRMPluginConfig{
		EnableDynamicEDTReconcile: true,
		BEGroupFloor:              5000,
		OnlineGroupFloor:          5000,
		OnlineGroupCeil:           40000,
		ReconcileInterval:         10 * time.Second,
		BMQReservedPerPod:         15000,
		BMQSelector:               "bmq",
	}
}

const reconcileNICName = "eth0"

func newReconcileNICs() []machine.InterfaceInfo {
	v4 := net.ParseIP("1.1.1.1")
	return []machine.InterfaceInfo{
		{
			Name: reconcileNICName,
			Addr: &machine.IfaceAddr{IPV4: []*net.IP{&v4}},
		},
	}
}

// noIPNICs returns a NIC with no resolvable IP (used to exercise the skip path).
func noIPNICs() []machine.InterfaceInfo {
	return []machine.InterfaceInfo{
		{Name: reconcileNICName, Addr: &machine.IfaceAddr{}},
	}
}

func bmqAI(podUID, ctr, classID string) *state.AllocationInfo {
	return &state.AllocationInfo{
		AllocationMeta: commonstate.AllocationMeta{
			PodUid:        podUID,
			ContainerName: ctr,
			QoSLevel:      apiconsts.PodAnnotationQoSLevelSharedCores,
			Annotations:   map[string]string{apiconsts.PodAnnotationCPUEnhancementCPUSet: "bmq"},
		},
		NetClassID: classID,
	}
}

func onlineAI(classID string) *state.AllocationInfo {
	return &state.AllocationInfo{
		AllocationMeta: commonstate.AllocationMeta{
			QoSLevel:    apiconsts.PodAnnotationQoSLevelSharedCores,
			Annotations: map[string]string{},
		},
		NetClassID: classID,
	}
}

func beAI(classID string) *state.AllocationInfo {
	return &state.AllocationInfo{
		AllocationMeta: commonstate.AllocationMeta{
			QoSLevel:    apiconsts.PodAnnotationQoSLevelReclaimedCores,
			Annotations: map[string]string{},
		},
		NetClassID: classID,
	}
}

// makeReconcilePolicy builds a StaticPolicy wired for generateGroups: a fakeState holding the given
// NICMap, a metaServer backed by a FakeMetricsFetcher, and an applyNetworkGroupsFunc that records
// the last applied groups so tests can assert on what reached the data plane.
func makeReconcilePolicy(t *testing.T, netConf *qrm.NetworkQRMPluginConfig, nics []machine.InterfaceInfo,
	machineState state.NICMap,
) (*StaticPolicy, *metric.FakeMetricsFetcher, *[]map[string]*qrmgeneral.NetworkGroup) {
	conf := &qrm.QRMPluginsConfiguration{NetworkQRMPluginConfig: netConf}
	emitter := metrics.DummyMetrics{}
	fetcher := metric.NewFakeMetricsFetcher(emitter).(*metric.FakeMetricsFetcher)

	metaServer := &metaserver.MetaServer{
		MetaAgent: &metaserveragent.MetaAgent{
			KatalystMachineInfo: &machine.KatalystMachineInfo{
				ExtraNetworkInfo: &machine.ExtraNetworkInfo{Interface: nics},
			},
			MetricsFetcher: fetcher,
		},
	}

	applied := &[]map[string]*qrmgeneral.NetworkGroup{}

	p := &StaticPolicy{
		qrmConfig:  conf,
		emitter:    emitter,
		metaServer: metaServer,
		state:      &fakeState{machineState: machineState},
		nicManager: &fakeNICManager{nics: nics},
		applyNetworkGroupsFunc: func(g map[string]*qrmgeneral.NetworkGroup) error {
			*applied = append(*applied, g)
			return nil
		},
	}
	return p, fetcher, applied
}

// fakeNICManager returns a fixed set of healthy NICs.
type fakeNICManager struct {
	nics []machine.InterfaceInfo
}

func (f *fakeNICManager) GetNICs() nic.NICs {
	return nic.NICs{HealthyNICs: f.nics}
}
func (f *fakeNICManager) Run(_ context.Context) {}

// set per-container egress BPS (bytes/sec) for a BMQ container.
func setBMQRuntime(fetcher *metric.FakeMetricsFetcher, podUID, ctr string, mbps float64) {
	bps := mbps * 1e6 / 8 // Mbps → bytes/sec
	fetcher.SetContainerMetric(podUID, ctr, metricconsts.MetricNetTcpSendBPSContainer,
		utilmetric.MetricData{Value: bps})
}

func nicStateWith(capacity uint32, entries state.PodEntries) *state.NICState {
	return &state.NICState{
		EgressState: state.BandwidthInfo{Capacity: capacity, Allocatable: capacity},
		PodEntries:  entries,
	}
}

// ============================ tests ============================

func TestTierOf(t *testing.T) {
	t.Parallel()
	assert.Equal(t, TierBMQ, tierOf(bmqAI("p", "c", "1"), "bmq"))
	assert.Equal(t, TierBE, tierOf(beAI("2"), "bmq"))
	assert.Equal(t, TierOnline, tierOf(onlineAI("3"), "bmq"))
	// BMQ pod takes precedence even if it were reclaimed-labeled.
	bmqReclaimed := beAI("4")
	bmqReclaimed.Annotations = map[string]string{apiconsts.PodAnnotationCPUEnhancementCPUSet: "bmq"}
	bmqReclaimed.QoSLevel = apiconsts.PodAnnotationQoSLevelReclaimedCores
	// reclaimed_cores' specified pool is "reclaim", so a bmq cpuset on reclaimed will NOT match the
	// selector via GetSpecifiedPoolName; it stays BE. This documents the selector's reliance on
	// shared_cores cpuset_pool. (See TODO in tierOf.)
	assert.Equal(t, TierBE, tierOf(bmqReclaimed, "bmq"))
	// empty selector never matches BMQ.
	assert.Equal(t, TierOnline, tierOf(onlineAI("5"), ""))
	assert.Equal(t, TierOnline, tierOf(nil, "bmq"))
}

func TestClampHelpers(t *testing.T) {
	t.Parallel()
	assert.Equal(t, uint32(0), subClampZero(5, 5))
	assert.Equal(t, uint32(0), subClampZero(3, 10))
	assert.Equal(t, uint32(7), subClampZero(10, 3))
	assert.Equal(t, uint32(5000), clampLow(100, 5000))
	assert.Equal(t, uint32(8000), clampLow(8000, 5000))
}

// no BMQ pressure: budget large, Online at ceiling, BE gets the surplus, both > floor.
func TestGenerateGroups_NoPressure(t *testing.T) {
	t.Parallel()
	conf := newReconcileTestConf()
	entries := state.PodEntries{
		"online1": {"c": onlineAI("100")},
		"be1":     {"c": beAI("200")},
	}
	p, _, _ := makeReconcilePolicy(t, conf, newReconcileNICs(),
		state.NICMap{reconcileNICName: nicStateWith(100000, entries)})

	groups, err := p.generateGroups()
	assert.NoError(t, err)

	online := groups[getGroupName(reconcileNICName, OnlineGroupNameSuffix)]
	be := groups[getGroupName(reconcileNICName, LowPriorityGroupNameSuffix)]
	assert.NotNil(t, online)
	assert.NotNil(t, be)
	// budget = 100000 (no BMQ). Online at ceiling 40000, BE = 100000-40000 = 60000.
	assert.Equal(t, uint32(40000), online.Egress)
	assert.Equal(t, uint32(60000), be.Egress)
}

// BE squeezed FIRST: under moderate pressure Online stays at ceiling, BE drops but stays >= floor.
func TestGenerateGroups_BESqueezedFirst(t *testing.T) {
	t.Parallel()
	conf := newReconcileTestConf()
	entries := state.PodEntries{
		"online1": {"c": onlineAI("100")},
		"be1":     {"c": beAI("200")},
		"bmq1":    {"c": bmqAI("bmq1", "c", "300")},
	}
	p, fetcher, _ := makeReconcilePolicy(t, conf, newReconcileNICs(),
		state.NICMap{reconcileNICName: nicStateWith(100000, entries)})
	// 1 BMQ pod, runtime 50000 Mbps > reservation 15000 → reserve 50000. budget=50000.
	setBMQRuntime(fetcher, "bmq1", "c", 50000)

	groups, err := p.generateGroups()
	assert.NoError(t, err)
	online := groups[getGroupName(reconcileNICName, OnlineGroupNameSuffix)]
	be := groups[getGroupName(reconcileNICName, LowPriorityGroupNameSuffix)]
	// budget-ceil = 50000-40000 = 10000 >= BEfloor(5000) → Online at ceiling, BE = 10000.
	assert.Equal(t, uint32(40000), online.Egress)
	assert.Equal(t, uint32(10000), be.Egress)
	assert.True(t, be.Egress >= conf.BEGroupFloor)
}

// Heavy pressure: BE pinned at floor, Online drops toward its floor; both still >= floor (never 0).
func TestGenerateGroups_BothAtFloorUnderPressure(t *testing.T) {
	t.Parallel()
	conf := newReconcileTestConf()
	entries := state.PodEntries{
		"online1": {"c": onlineAI("100")},
		"be1":     {"c": beAI("200")},
		"bmq1":    {"c": bmqAI("bmq1", "c", "300")},
	}
	p, fetcher, _ := makeReconcilePolicy(t, conf, newReconcileNICs(),
		state.NICMap{reconcileNICName: nicStateWith(100000, entries)})
	// runtime 92000 → budget = 8000. budget-ceil underflow→0 < BEfloor → BE=5000,
	// Online = clampLow(8000-5000=3000, 5000) = 5000.
	setBMQRuntime(fetcher, "bmq1", "c", 92000)

	groups, err := p.generateGroups()
	assert.NoError(t, err)
	online := groups[getGroupName(reconcileNICName, OnlineGroupNameSuffix)]
	be := groups[getGroupName(reconcileNICName, LowPriorityGroupNameSuffix)]
	assert.Equal(t, uint32(5000), be.Egress)
	assert.Equal(t, uint32(5000), online.Egress)
	assert.True(t, be.Egress >= conf.BEGroupFloor && be.Egress > 0)
	assert.True(t, online.Egress >= conf.OnlineGroupFloor && online.Egress > 0)
}

// the prior zero-rate / permanent-0 bug: even when BMQ is fully within its reservation (no live
// traffic), Online must be at ceiling and BE > floor — never 0.
func TestGenerateGroups_BMQWithinReservation_NeverZero(t *testing.T) {
	t.Parallel()
	conf := newReconcileTestConf()
	entries := state.PodEntries{
		"online1": {"c": onlineAI("100")},
		"be1":     {"c": beAI("200")},
		"bmq1":    {"c": bmqAI("bmq1", "c", "300")},
	}
	p, _, _ := makeReconcilePolicy(t, conf, newReconcileNICs(),
		state.NICMap{reconcileNICName: nicStateWith(100000, entries)})
	// no runtime metric set → bmqRuntime=0, reserve=max(0, 1*15000)=15000. budget=85000.
	groups, err := p.generateGroups()
	assert.NoError(t, err)
	online := groups[getGroupName(reconcileNICName, OnlineGroupNameSuffix)]
	be := groups[getGroupName(reconcileNICName, LowPriorityGroupNameSuffix)]
	assert.Equal(t, uint32(40000), online.Egress)
	assert.Equal(t, uint32(45000), be.Egress) // 85000 - 40000
	assert.True(t, online.Egress > 0 && be.Egress > 0)
}

// the prior ratchet bug: Online recovers toward ceiling once pressure eases (stateless recompute).
func TestGenerateGroups_OnlineRecovers(t *testing.T) {
	t.Parallel()
	conf := newReconcileTestConf()
	entries := state.PodEntries{
		"online1": {"c": onlineAI("100")},
		"be1":     {"c": beAI("200")},
		"bmq1":    {"c": bmqAI("bmq1", "c", "300")},
	}
	p, fetcher, _ := makeReconcilePolicy(t, conf, newReconcileNICs(),
		state.NICMap{reconcileNICName: nicStateWith(100000, entries)})

	// heavy pressure first: Online squeezed to floor.
	setBMQRuntime(fetcher, "bmq1", "c", 92000)
	g1, _ := p.generateGroups()
	assert.Equal(t, uint32(5000), g1[getGroupName(reconcileNICName, OnlineGroupNameSuffix)].Egress)

	// pressure eases: Online must climb back to ceiling, not stay ratcheted at floor.
	setBMQRuntime(fetcher, "bmq1", "c", 1000)
	g2, _ := p.generateGroups()
	assert.Equal(t, uint32(40000), g2[getGroupName(reconcileNICName, OnlineGroupNameSuffix)].Egress)
}

// EVERY emitted group must have Egress>0 AND non-empty IPs (catch the batch-poison bug). Swept over
// a wide range of BMQ runtime so no allocation point produces an invalid group.
func TestGenerateGroups_EveryGroupValid(t *testing.T) {
	t.Parallel()
	conf := newReconcileTestConf()
	entries := state.PodEntries{
		"online1": {"c": onlineAI("100")},
		"be1":     {"c": beAI("200")},
		"bmq1":    {"c": bmqAI("bmq1", "c", "300")},
	}
	for _, rt := range []float64{0, 1000, 40000, 60000, 85000, 95000, 200000} {
		p, fetcher, _ := makeReconcilePolicy(t, conf, newReconcileNICs(),
			state.NICMap{reconcileNICName: nicStateWith(100000, entries)})
		setBMQRuntime(fetcher, "bmq1", "c", rt)
		groups, err := p.generateGroups()
		assert.NoError(t, err)
		assert.NotEmpty(t, groups)
		for name, g := range groups {
			assert.True(t, g.Egress > 0, "group %s has zero egress at runtime %v", name, rt)
			assert.True(t, g.MergedIPv4 != "" || g.MergedIPv6 != "",
				"group %s has empty IPs at runtime %v", name, rt)
			assert.NotEmpty(t, g.NetClassIDs, "group %s has empty NetClassIDs", name)
		}
	}
}

// underflow guard: BMQ reserve exceeding capacity must not underflow; both rates pinned at floor.
func TestGenerateGroups_UnderflowGuard(t *testing.T) {
	t.Parallel()
	conf := newReconcileTestConf()
	entries := state.PodEntries{
		"online1": {"c": onlineAI("100")},
		"be1":     {"c": beAI("200")},
		"bmq1":    {"c": bmqAI("bmq1", "c", "300")},
	}
	p, fetcher, _ := makeReconcilePolicy(t, conf, newReconcileNICs(),
		state.NICMap{reconcileNICName: nicStateWith(10000, entries)})
	setBMQRuntime(fetcher, "bmq1", "c", 999999) // far exceeds 10000 capacity
	groups, err := p.generateGroups()
	assert.NoError(t, err)
	be := groups[getGroupName(reconcileNICName, LowPriorityGroupNameSuffix)]
	online := groups[getGroupName(reconcileNICName, OnlineGroupNameSuffix)]
	assert.Equal(t, uint32(5000), be.Egress)
	assert.Equal(t, uint32(5000), online.Egress)
}

// NIC without a resolvable IP must be skipped, not emitted as an invalid group.
func TestGenerateGroups_SkipNICWithoutIP(t *testing.T) {
	t.Parallel()
	conf := newReconcileTestConf()
	entries := state.PodEntries{"online1": {"c": onlineAI("100")}}
	p, _, _ := makeReconcilePolicy(t, conf, noIPNICs(),
		state.NICMap{reconcileNICName: nicStateWith(100000, entries)})
	groups, err := p.generateGroups()
	assert.NoError(t, err)
	assert.Empty(t, groups)
}

// BMQ containers are never placed into any emitted group (never throttled).
func TestGenerateGroups_BMQNeverGrouped(t *testing.T) {
	t.Parallel()
	conf := newReconcileTestConf()
	entries := state.PodEntries{
		"bmq1": {"c": bmqAI("bmq1", "c", "300")},
	}
	p, _, _ := makeReconcilePolicy(t, conf, newReconcileNICs(),
		state.NICMap{reconcileNICName: nicStateWith(100000, entries)})
	groups, err := p.generateGroups()
	assert.NoError(t, err)
	// only BMQ present → no BE, no Online group emitted, and class id 300 appears nowhere.
	assert.Empty(t, groups)
}

// a tier with no members is not emitted.
func TestGenerateGroups_EmptyTierNotEmitted(t *testing.T) {
	t.Parallel()
	conf := newReconcileTestConf()
	entries := state.PodEntries{"online1": {"c": onlineAI("100")}}
	p, _, _ := makeReconcilePolicy(t, conf, newReconcileNICs(),
		state.NICMap{reconcileNICName: nicStateWith(100000, entries)})
	groups, err := p.generateGroups()
	assert.NoError(t, err)
	assert.Nil(t, groups[getGroupName(reconcileNICName, LowPriorityGroupNameSuffix)])
	assert.NotNil(t, groups[getGroupName(reconcileNICName, OnlineGroupNameSuffix)])
}

// idempotency: reconcileGroups applies once, then skips the data-plane write when unchanged.
func TestReconcileGroups_IdempotentNoOp(t *testing.T) {
	t.Parallel()
	conf := newReconcileTestConf()
	entries := state.PodEntries{
		"online1": {"c": onlineAI("100")},
		"be1":     {"c": beAI("200")},
	}
	p, _, applied := makeReconcilePolicy(t, conf, newReconcileNICs(),
		state.NICMap{reconcileNICName: nicStateWith(100000, entries)})

	assert.NoError(t, p.reconcileGroups())
	assert.Len(t, *applied, 1) // first run applies

	assert.NoError(t, p.reconcileGroups())
	assert.Len(t, *applied, 1) // unchanged → no second apply
}

func TestGroupsEqual(t *testing.T) {
	t.Parallel()
	a := map[string]*qrmgeneral.NetworkGroup{
		"g": {NetClassIDs: []string{"1", "2"}, Egress: 100, MergedIPv4: "1.1.1.1"},
	}
	b := map[string]*qrmgeneral.NetworkGroup{
		"g": {NetClassIDs: []string{"2", "1"}, Egress: 100, MergedIPv4: "1.1.1.1"},
	}
	assert.True(t, groupsEqual(a, b)) // order-independent in NetClassIDs

	c := map[string]*qrmgeneral.NetworkGroup{
		"g": {NetClassIDs: []string{"1", "2"}, Egress: 200, MergedIPv4: "1.1.1.1"},
	}
	assert.False(t, groupsEqual(a, c))
	assert.False(t, groupsEqual(a, nil))
}

// feature OFF: generateAndApplyGroups must take the single low-priority path (today's behaviour),
// not the reconcile path. Online group is never emitted; the applied set is the lowPriorityGroups.
func TestFeatureOff_SingleGroupPath(t *testing.T) {
	t.Parallel()
	conf := &qrm.NetworkQRMPluginConfig{EnableDynamicEDTReconcile: false}
	entries := state.PodEntries{
		"online1": {"c": onlineAI("100")},
		"be1":     {"c": beAI("200")},
	}
	p, _, applied := makeReconcilePolicy(t, conf, newReconcileNICs(),
		state.NICMap{reconcileNICName: nicStateWith(100000, entries)})

	assert.NoError(t, p.generateAndApplyGroups())
	// exactly one apply, and it must be the low-priority groups map (no online group, networkGroups untouched).
	assert.Len(t, *applied, 1)
	got := (*applied)[0]
	assert.Nil(t, got[getGroupName(reconcileNICName, OnlineGroupNameSuffix)])
	assert.NotNil(t, got[getGroupName(reconcileNICName, LowPriorityGroupNameSuffix)])
	assert.Nil(t, p.networkGroups) // reconcile path never touched
}
