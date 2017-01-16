package policy

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"reflect"
	"strings"
	"syscall"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/mitchellh/hashstructure"
	"github.com/pkg/errors"
	"github.com/rancher/go-rancher-metadata/metadata"
)

// TODO: Fill in the comments for all the needed ones

const (
	// TODO: Having contention with hostports iptables rules logic
	// Discuss with @ibuildthecloud
	//hookChain = "CATTLE_FORWARD"
	hookChain                    = "FORWARD"
	cattleNetworkPolicyChainName = "CATTLE_NETWORK_POLICY"
)

type watcher struct {
	c                  metadata.Client
	lastApplied        time.Time
	shutdownInProgress bool
	signalCh           chan os.Signal
	exitCh             chan int
	defaultNetwork     *metadata.Network
	stacks             []metadata.Stack
	services           []metadata.Service
	appliedIPsets      map[string]map[string]bool
	appliedRules       map[int]map[string]Rule
	ipsets             map[string]map[string]bool
	rules              map[int]map[string]Rule
	selfHost           *metadata.Host
	appliednp          *NetworkPolicy
	np                 *NetworkPolicy
}

// Rule ...
type Rule struct {
	dst      string
	src      string
	ports    []string
	stateful bool
	action   string
	system   bool
}

func (rule *Rule) iptables(defPolicyAction string) []byte {
	buf := &bytes.Buffer{}
	buf.WriteString(fmt.Sprintf("-A %v ", cattleNetworkPolicyChainName))
	if rule.dst != "" {
		buf.WriteString(fmt.Sprintf("-m set --match-set %v dst ", rule.dst))
	}

	if rule.src != "" {
		buf.WriteString(fmt.Sprintf("-m set --match-set %v src ", rule.src))
	}

	// TODO: Check for ports/ stateful etc

	var ruleTarget string
	if rule.action == ActionAllow {
		ruleTarget = "RETURN"
	} else {
		ruleTarget = "DROP"
	}

	buf.WriteString(fmt.Sprintf("-j %v\n", ruleTarget))

	// Add the defaultPolicy
	if rule.dst != "" {
		buf.WriteString(fmt.Sprintf("-A %v ", cattleNetworkPolicyChainName))
		buf.WriteString(fmt.Sprintf("-m set --match-set %v dst ", rule.dst))
		var ruleTarget string
		if defPolicyAction == ActionAllow {
			ruleTarget = "RETURN"
		} else {
			ruleTarget = "DROP"
		}

		if rule.system {
			ruleTarget = "RETURN"
		}

		buf.WriteString(fmt.Sprintf("-j %v\n", ruleTarget))
	}

	return buf.Bytes()
}

// Watch is used to monitor metadata for changes
func Watch(c metadata.Client, exitCh chan int) error {
	sCh := make(chan os.Signal, 2)
	signal.Notify(sCh, os.Interrupt, syscall.SIGTERM)

	w := &watcher{
		c:                  c,
		shutdownInProgress: false,
		exitCh:             exitCh,
		signalCh:           sCh,
	}

	go w.shutdown()
	go c.OnChange(5, w.onChangeNoError)
	return nil
}

func (w *watcher) shutdown() {
	<-w.signalCh
	logrus.Infof("Got shutdown signal")

	w.shutdownInProgress = true

	// This is probably a good place to add clean up logic
	w.cleanup()

	w.exitCh <- 0
}

func (w *watcher) onChangeNoError(version string) {
	logrus.Debugf("onChangeNoError version: %v", version)
	if w.shutdownInProgress {
		logrus.Infof("Shutdown in progress, no more processing")
		return
	}

	if err := w.onChange(version); err != nil {
		logrus.Errorf("Failed to apply network policy: %v", err)
	}
}

func (w *watcher) getDefaultNetwork() (*metadata.Network, error) {
	networks, err := w.c.GetNetworks()
	if err != nil {
		return nil, err
	}

	for _, n := range networks {
		if n.Default {
			return &n, nil
		}
	}

	return nil, fmt.Errorf("Couldn't find default network")
}

// This function returns IP addresses of local and all containers of the stack
// on the default network
func (w *watcher) getInfoFromStack(stack metadata.Stack) (map[string]bool, map[string]bool) {
	local := make(map[string]bool)
	all := make(map[string]bool)
	for _, service := range stack.Services {
		for _, c := range service.Containers {
			if c.NetworkUUID == w.defaultNetwork.UUID {
				if c.HostUUID == w.selfHost.UUID {
					local[c.PrimaryIp] = true
				}
				all[c.PrimaryIp] = true
			}
		}
	}

	//logrus.Debugf("For stack: %v\nlocal: %v\nall: %v", stack.Name, local, all)
	return local, all
}

func (w *watcher) generateHash(s string) (string, error) {
	hash, err := hashstructure.Hash(s, nil)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%v", hash), nil
}

func (w *watcher) defaultPolicyAction(action string) (map[string]Rule, error) {
	defPolicyActionMap := make(map[string]Rule)

	r := Rule{dst: "", src: "", action: action}
	defPolicyActionMap["default.policy.action"] = r

	logrus.Debugf("defPolicyActionMap: %v", defPolicyActionMap)
	return defPolicyActionMap, nil
}

func (w *watcher) defaultSystemPolicies() (map[string]Rule, error) {
	defSysRulesMap := make(map[string]Rule)
	for _, stack := range w.stacks {
		var err error
		var dstSetName, srcSetName string

		if !stack.System {
			continue
		}

		_, all := w.getInfoFromStack(stack)

		srcSet := fmt.Sprintf("src.within.%v", stack.Name)
		srcSetName, err = w.generateHash(srcSet)
		if err != nil {
			logrus.Errorf("coudln't generate hash: %v", err)
			return nil, err
		}

		//TODO:
		//srcSetName = "CATTLE-" + srcSetName
		srcSetName = "CATTLE-" + srcSet

		logrus.Debugf("%v dstSetName: %v srcSetName: %v", stack.Name, dstSetName, srcSetName)

		if existingSet, exists := w.ipsets[srcSetName]; exists {
			if !reflect.DeepEqual(existingSet, all) {
				logrus.Errorf("mismatch existingSet: %v all:%v", existingSet, all)
			}
		} else {
			w.ipsets[srcSetName] = all
		}

		r := Rule{dst: "", src: srcSetName, action: ActionAllow}

		//logrus.Debugf("r: %v", r)
		defSysRulesMap["from."+stack.Name] = r
	}

	logrus.Debugf("defSysRulesMap: %v", defSysRulesMap)
	return defSysRulesMap, nil
}

func (w *watcher) withinStackHandler(p Policy) (map[string]Rule, error) {
	logrus.Debugf("withinStackHandler")
	withinRulesMap := make(map[string]Rule)
	for _, stack := range w.stacks {
		var err error
		var dstSetName, srcSetName string
		local, all := w.getInfoFromStack(stack)
		if len(local) > 0 {
			dstSet := fmt.Sprintf("dst.within.%v", stack.Name)
			dstSetName, err = w.generateHash(dstSet)
			if err != nil {
				logrus.Errorf("coudln't generate hash: %v", err)
				return nil, err
			}

			srcSet := fmt.Sprintf("src.within.%v", stack.Name)
			srcSetName, err = w.generateHash(srcSet)
			if err != nil {
				logrus.Errorf("coudln't generate hash: %v", err)
				return nil, err
			}

			//TODO:
			dstSetName = dstSet
			srcSetName = srcSet

			logrus.Debugf("%v dstSetName: %v srcSetName: %v", stack.Name, dstSetName, srcSetName)

			if existingSet, exists := w.ipsets[dstSetName]; exists {
				if !reflect.DeepEqual(existingSet, local) {
					return nil, fmt.Errorf("mismatch existingSet: %v local:%v", existingSet, local)
				}
			} else {
				w.ipsets[dstSetName] = local
			}

			if existingSet, exists := w.ipsets[srcSetName]; exists {
				if !reflect.DeepEqual(existingSet, all) {
					logrus.Errorf("mismatch existingSet: %v all:%v", existingSet, all)
				}
			} else {
				w.ipsets[srcSetName] = all
			}

		} else {
			logrus.Debugf("stack: %v doesn't have any local containers, skipping", stack.Name)
			continue
		}
		r := Rule{dst: dstSetName, src: srcSetName, action: p.Action}

		// TODO: Revisit later and check if this is needed here or do it earlier
		// within system stacks action is always allowed
		if stack.System {
			r.action = ActionAllow
			r.system = true
		}

		//logrus.Debugf("r: %v", r)
		withinRulesMap["within."+stack.Name] = r
	}

	logrus.Debugf("withinRulesMap: %v", withinRulesMap)
	return withinRulesMap, nil
}

func (w *watcher) withinServiceHandler(p Policy) (map[string]Rule, error) {
	logrus.Debugf("withinServiceHandler")

	return nil, nil
}

func (w *watcher) withinLinkHandler(p Policy) (map[string]Rule, error) {
	logrus.Debugf("withinLinkHandler")

	return nil, nil
}

func (w *watcher) withinPolicyHandler(p Policy) (map[string]Rule, error) {
	logrus.Debugf("withinPolicyHandler")
	if p.Within == StrStack {
		return w.withinStackHandler(p)
	} else if p.Within == StrService {
		return w.withinServiceHandler(p)
	} else if p.Within == StrLink {
		w.withinLinkHandler(p)
	}

	return nil, fmt.Errorf("invalid option for within")
}

func (w *watcher) betweenPolicyHandler(p Policy) {

}

func (w *watcher) translatePolicy(np *NetworkPolicy) {

	// TODO: release these once done
	w.ipsets = make(map[string]map[string]bool)
	w.rules = make(map[int]map[string]Rule)

	index := 0

	if len(np.Policies) > 0 {

		r, err := w.defaultSystemPolicies()
		if err != nil {
			logrus.Errorf("error translating default system policies: %v", err)
			// TODO: What to do?
		}
		w.rules[index] = r
		index++

		for _, p := range np.Policies {
			logrus.Debugf("Working on: p:%#v", p)

			// within Handler
			if p.Within != "" {
				r, err := w.withinPolicyHandler(p)
				if err != nil {
					logrus.Errorf("error: %v", err)
				} else {
					w.rules[index] = r
				}
				index++
				continue
			}

		}
	}

	//r, err = w.defaultPolicyAction(np.DefaultPolicyAction)
	//if err != nil {
	//	logrus.Errorf("error translating default policy action: %v", err)
	//	// TODO: What to do?
	//}
	//w.rules[index] = r
	//index++

	logrus.Debugf("w.rules: %#v", w.rules)
	logrus.Debugf("w.ipsets: %#v", w.ipsets)
}

func (w *watcher) fetchInfoFromMetadata() error {
	stacks, err := w.c.GetStacks()
	if err != nil {
		logrus.Errorf("Error getting stacks from metadata: %v", err)
		return err
	}

	selfHost, err := w.c.GetSelfHost()
	if err != nil {
		logrus.Errorf("Couldn't get containers from metadata: %v", err)
		return err
	}

	defaultNetwork, err := w.getDefaultNetwork()
	if err != nil {
		logrus.Errorf("Error while finding default network: %v", err)
		return err
	}
	logrus.Debugf("defaultNetwork: %v", defaultNetwork)

	w.defaultNetwork = defaultNetwork
	w.selfHost = &selfHost
	w.stacks = stacks

	return nil
}

func (w *watcher) onChange(version string) error {
	logrus.Debugf("onChange version: %v", version)
	var err error

	err = w.fetchInfoFromMetadata()
	if err != nil {
		logrus.Errorf("error fetching information from metadata: %v", err)
		return err
	}

	actualNP := w.defaultNetwork.NetworkPolicy
	logrus.Infof("actualNP: %#v", actualNP)

	// TODO: Replace this with the metadata call
	np, err := ParseNetworkPolicy(actualNP)

	if err != nil {
		logrus.Errorf("error parsing network policy: %v", err)
		return err
	}
	w.np = np

	// TODO: Handle error
	w.translatePolicy(np)

	// Need to process ipsets first as we reference
	// the set names later in the iptables rules.

	if !reflect.DeepEqual(w.appliedIPsets, w.ipsets) {
		logrus.Infof("Applying new ipsets")

		// TODO: check for errors
		w.refreshIpsets()

	} else {
		logrus.Infof("No change in ipsets")
	}

	if !reflect.DeepEqual(w.appliedRules, w.rules) {
		logrus.Infof("Applying new rules")

		// TODO: Check for error
		w.applyIptablesRules(w.rules)

		w.appliedRules = w.rules
	} else {
		logrus.Infof("No change in applied rules")
	}

	// TODO:
	// Cleanup ipsets only after the iptables are refreshed
	//  - clean up ipsets with ref = 0
	if !reflect.DeepEqual(w.appliedIPsets, w.ipsets) {
		if err := w.cleanupIpsets(); err != nil {
			logrus.Errorf("Error cleaning ipsets: %v", err)
		}
		w.appliedIPsets = w.ipsets
	}

	// TODO: Fix this
	w.appliednp = w.np

	return nil
}

// TODO: See if we can take buffer approach
func (w *watcher) refreshIpsets() error {
	logrus.Debugf("refreshing ipsets")

	for ipsetName, ipset := range w.ipsets {
		oldipset := w.appliedIPsets[ipsetName]
		if !reflect.DeepEqual(ipset, oldipset) {
			logrus.Debugf("refreshing ipset: %v", ipsetName)
			tmpIPSetName := "TMP-" + ipsetName
			createIPSet(tmpIPSetName, ipset)
			if existsIPSet(ipsetName) {
				swapCmdStr := fmt.Sprintf("ipset swap %s %s", tmpIPSetName, ipsetName)
				executeCommand(swapCmdStr)

				deleteCmdStr := fmt.Sprintf("ipset destroy %s", tmpIPSetName)
				executeCommand(deleteCmdStr)
			} else {
				renameCmdStr := fmt.Sprintf("ipset rename %s %s", tmpIPSetName, ipsetName)
				executeCommand(renameCmdStr)
			}

		}
	}

	return nil
}

func (w *watcher) cleanupIpsets() error {
	logrus.Debugf("ipsets cleanup")

	for ipsetName := range w.appliedIPsets {
		_, existsInNew := w.appliedIPsets[ipsetName]
		if !existsInNew {
			logrus.Debugf("ipset: %v doesn't exist in new map, hence deleting ", ipsetName)
			deleteCmdStr := fmt.Sprintf("ipset destroy %s", ipsetName)
			executeCommand(deleteCmdStr)
		}
	}

	return nil
}

func (w *watcher) applyIptablesRules(rulesMap map[int]map[string]Rule) error {
	buf := &bytes.Buffer{}
	buf.WriteString("*filter\n")
	buf.WriteString(fmt.Sprintf(":%s -\n", cattleNetworkPolicyChainName))

	// TODO: For all rules, build iptables rules
	for i := 0; i < len(rulesMap); i++ {
		rules, ok := rulesMap[i]
		if !ok {
			logrus.Errorf("not expecting error here for i: %v", i)
			continue
		}

		for ruleName, rule := range rules {
			logrus.Debugf("ruleName: %v, rule: %v", ruleName, rule)
			buf.Write(rule.iptables(w.np.DefaultPolicyAction))
		}
	}

	buf.WriteString("\nCOMMIT\n")

	if logrus.GetLevel() == logrus.DebugLevel {
		fmt.Printf("Applying rules\n%s", buf)
	}

	cmd := exec.Command("iptables-restore", "-n")
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	cmd.Stdin = buf
	if err := cmd.Run(); err != nil {
		logrus.Errorf("Failed to apply rules\n%s", buf)
		return err
	}

	if err := w.insertBaseRules(); err != nil {
		return errors.Wrap(err, "Applying base iptables rules")
	}

	return nil
}

func (w *watcher) run(args ...string) error {
	logrus.Debugf("Running %s", strings.Join(args, " "))
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func (w *watcher) insertBaseRules() error {
	if w.run("iptables", "-w", "-C", hookChain, "-j", cattleNetworkPolicyChainName) != nil {
		return w.run("iptables", "-w", "-I", hookChain, "-j", cattleNetworkPolicyChainName)
	}
	return nil
}

func (w *watcher) deleteBaseRules() error {
	if w.run("iptables", "-w", "-C", hookChain, "-j", cattleNetworkPolicyChainName) == nil {
		return w.run("iptables", "-w", "-D", hookChain, "-j", cattleNetworkPolicyChainName)
	}
	return nil
}

func (w *watcher) flushAndDeleteChain() error {
	if err := w.run("iptables", "-w", "-F", cattleNetworkPolicyChainName); err != nil {
		logrus.Errorf("Error flushing the chain: %v", cattleNetworkPolicyChainName)
		return err
	}

	if err := w.run("iptables", "-X", cattleNetworkPolicyChainName); err != nil {
		logrus.Errorf("Error deleting the chain: %v", cattleNetworkPolicyChainName)
		return err
	}

	return nil
}

func (w *watcher) cleanup() error {
	logrus.Debugf("Doing cleanup")
	// TODO: Add error handling
	// delete the base Rule
	w.deleteBaseRules()

	// Flush and delete the chain
	w.flushAndDeleteChain()

	// remove the ipsets

	return nil
}

func existsIPSet(name string) bool {
	checkCmdStr := fmt.Sprintf("ipset list %s -name", name)
	err := executeCommand(checkCmdStr)

	return err == nil
}

func createIPSet(name string, ips map[string]bool) {

	//ipset -N %s iphash
	// TODO: Remove counters???
	createStr := fmt.Sprintf("ipset create %s iphash counters", name)
	executeCommand(createStr)

	for ip := range ips {
		addIPStr := fmt.Sprintf("ipset add %s %s", name, ip)
		executeCommand(addIPStr)
	}
}
