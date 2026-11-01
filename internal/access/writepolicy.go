package access

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/GalaxyGorilla/bacnet-shield/internal/bacnet"
)

// Action is a write-policy rule action.
type Action string

const (
	ActionAllow Action = "allow"
	ActionDeny  Action = "deny"
)

// Rule is one write-policy entry. Spec names an object, an instance and a
// property, each of which may be "*":
//
//	"*"                              every write to every object
//	"analog-value:*:present-value"   the setpoint of every analog value
//	"analog-value:5:*"               everything on one object
//	"device:1001:description"        a single property
//
// A two-part spec ("analog-value:5") means every property of that object.
type Rule struct {
	Spec   string
	Action Action
}

// WritePolicy decides which writes a client may perform.
//
// The semantics are the ones the other Shield proxies use, because they are
// the ones an operator can reason about:
//
//   - deny overrides: one matching deny rule rejects the whole request, so a
//     multi-property write can never straddle a forbidden object;
//   - allow must cover: an allow rule authorizes the request only if it
//     matches EVERY object/property the request touches;
//   - otherwise the configured default applies (deny unless configured).
//
// A write whose payload cannot be decoded is denied: an unparseable write
// cannot be authorized, and forwarding it "because we could not tell" is
// exactly the bypass the policy exists to prevent.
type WritePolicy struct {
	readOnly     bool
	defaultAllow bool
	rules        []rule
}

type rule struct {
	action Action

	anyType     bool
	objectType  bacnet.ObjectType
	anyInstance bool
	instance    uint32
	anyProperty bool
	property    bacnet.PropertyID
}

// NewWritePolicy compiles a policy. readOnly and a default/rules are
// mutually exclusive: read_only is the clearer way to say "deny everything",
// and accepting both invites a config that looks restrictive and is not.
func NewWritePolicy(readOnly bool, def Action, rules []Rule) (*WritePolicy, error) {
	if readOnly {
		if def != "" || len(rules) > 0 {
			return nil, fmt.Errorf("access: read_only cannot be combined with a write_policy")
		}
		return &WritePolicy{readOnly: true}, nil
	}
	p := &WritePolicy{}
	switch def {
	case ActionAllow:
		p.defaultAllow = true
	case ActionDeny:
		p.defaultAllow = false
	default:
		return nil, fmt.Errorf("access: write_policy default must be %q or %q", ActionAllow, ActionDeny)
	}
	for _, r := range rules {
		c, err := compileRule(r)
		if err != nil {
			return nil, err
		}
		p.rules = append(p.rules, c)
	}
	return p, nil
}

func compileRule(r Rule) (rule, error) {
	var c rule
	switch r.Action {
	case ActionAllow, ActionDeny:
		c.action = r.Action
	default:
		return rule{}, fmt.Errorf("access: rule %q: action must be %q or %q", r.Spec, ActionAllow, ActionDeny)
	}

	spec := strings.TrimSpace(r.Spec)
	if spec == "" {
		return rule{}, fmt.Errorf("access: empty write rule")
	}
	if spec == "*" {
		c.anyType, c.anyInstance, c.anyProperty = true, true, true
		return c, nil
	}
	parts := strings.Split(spec, ":")
	if len(parts) > 3 {
		return rule{}, fmt.Errorf("access: rule %q: want <type>[:<instance>[:<property>]]", spec)
	}
	// Object type.
	if parts[0] == "*" {
		c.anyType = true
	} else {
		t, err := bacnet.ParseObjectType(parts[0])
		if err != nil {
			return rule{}, fmt.Errorf("access: rule %q: %w", spec, err)
		}
		c.objectType = t
	}
	// Instance.
	if len(parts) < 2 || parts[1] == "*" {
		c.anyInstance = true
	} else {
		n, err := strconv.ParseUint(strings.TrimSpace(parts[1]), 10, 32)
		if err != nil || n > 1<<22-1 {
			return rule{}, fmt.Errorf("access: rule %q: bad instance %q", spec, parts[1])
		}
		c.instance = uint32(n)
	}
	// Property.
	if len(parts) < 3 || parts[2] == "*" {
		c.anyProperty = true
	} else {
		prop, err := bacnet.ParsePropertyID(parts[2])
		if err != nil {
			return rule{}, fmt.Errorf("access: rule %q: %w", spec, err)
		}
		c.property = prop
	}
	return c, nil
}

func (r rule) matches(t bacnet.WriteTarget) bool {
	if !r.anyType && r.objectType != t.Object.Type {
		return false
	}
	if !r.anyInstance && r.instance != t.Object.Instance {
		return false
	}
	if !r.anyProperty && r.property != t.Property {
		return false
	}
	return true
}

// Allowed decides one APDU.
func (p *WritePolicy) Allowed(a bacnet.APDU) bool {
	if p == nil {
		return true
	}
	if !a.IsWrite() {
		return true
	}
	if p.readOnly {
		return false
	}
	// A segmented write is denied before decoding. The policy would only see
	// the first segment, so a client could put an allowed target in segment
	// one and a forbidden one in a later segment and the policy would never
	// inspect the second. Denying the whole class is fail-closed and costs
	// only the rare large segmented write.
	if a.Segmented {
		return false
	}
	targets, isWrite, err := bacnet.WriteTargets(a)
	if !isWrite {
		return true
	}
	if err != nil {
		return false
	}
	if len(targets) == 0 {
		// A service-level write (CreateObject, ReinitializeDevice, ...) has
		// no object to match a rule against, so only the default can
		// authorize it. This is why a default-deny policy also blocks those
		// services even when object rules exist.
		return p.defaultAllow
	}

	for _, r := range p.rules {
		if r.action != ActionDeny {
			continue
		}
		for _, t := range targets {
			if r.matches(t) {
				return false
			}
		}
	}
	for _, r := range p.rules {
		if r.action != ActionAllow {
			continue
		}
		covered := true
		for _, t := range targets {
			if !r.matches(t) {
				covered = false
				break
			}
		}
		if covered {
			return true
		}
	}
	return p.defaultAllow
}
