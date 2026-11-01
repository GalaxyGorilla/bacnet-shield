package bacnet

import (
	"fmt"
	"strconv"
	"strings"
)

// PropertyID is a BACnet property identifier.
type PropertyID uint32

// Common property identifiers (ASHRAE 135 clause 12.11). A policy may use a
// name or the number; the numbers here are the wire values.
const (
	PropertyNotificationClass PropertyID = 17
	PropertyCovIncrement      PropertyID = 22
	PropertyDescription       PropertyID = 28
	PropertyDeviceType        PropertyID = 31
	PropertyEventState        PropertyID = 36
	PropertyFirmwareRevision  PropertyID = 44
	PropertyLocalDate         PropertyID = 56
	PropertyLocalTime         PropertyID = 57
	PropertyLocation          PropertyID = 58
	PropertyMaxAPDULength     PropertyID = 62
	PropertyModelName         PropertyID = 70
	PropertyNumberOfStates    PropertyID = 74
	PropertyObjectIdentifier  PropertyID = 75
	PropertyObjectList        PropertyID = 76
	PropertyObjectName        PropertyID = 77
	PropertyObjectType        PropertyID = 79
	PropertyOutOfService      PropertyID = 81
	PropertyOutputUnits       PropertyID = 82
	PropertyPolarity          PropertyID = 84
	PropertyPresentValue      PropertyID = 85
	PropertyPriority          PropertyID = 86
	PropertyPriorityArray     PropertyID = 87
	PropertyReliability       PropertyID = 103
	PropertyRelinquishDefault PropertyID = 104
	PropertySegmentation      PropertyID = 107
	PropertyStateText         PropertyID = 110
	PropertyStatusFlags       PropertyID = 111
	PropertyUnits             PropertyID = 117
	PropertyVendorIdentifier  PropertyID = 120
	PropertyVendorName        PropertyID = 121
)

var propertyNames = map[PropertyID]string{
	PropertyNotificationClass: "notification-class",
	PropertyCovIncrement:      "cov-increment",
	PropertyDescription:       "description",
	PropertyDeviceType:        "device-type",
	PropertyEventState:        "event-state",
	PropertyFirmwareRevision:  "firmware-revision",
	PropertyLocalDate:         "local-date",
	PropertyLocalTime:         "local-time",
	PropertyLocation:          "location",
	PropertyMaxAPDULength:     "max-apdu-length-accepted",
	PropertyModelName:         "model-name",
	PropertyNumberOfStates:    "number-of-states",
	PropertyObjectIdentifier:  "object-identifier",
	PropertyObjectList:        "object-list",
	PropertyObjectName:        "object-name",
	PropertyObjectType:        "object-type",
	PropertyOutOfService:      "out-of-service",
	PropertyOutputUnits:       "output-units",
	PropertyPolarity:          "polarity",
	PropertyPresentValue:      "present-value",
	PropertyPriority:          "priority",
	PropertyPriorityArray:     "priority-array",
	PropertyReliability:       "reliability",
	PropertyRelinquishDefault: "relinquish-default",
	PropertySegmentation:      "segmentation-supported",
	PropertyStateText:         "state-text",
	PropertyStatusFlags:       "status-flags",
	PropertyUnits:             "units",
	PropertyVendorIdentifier:  "vendor-identifier",
	PropertyVendorName:        "vendor-name",
}

func (p PropertyID) String() string {
	if n, ok := propertyNames[p]; ok {
		return n
	}
	return strconv.FormatUint(uint64(p), 10)
}

// ParsePropertyID accepts a name ("present-value"), the underscore spelling,
// or a number ("85").
func ParsePropertyID(s string) (PropertyID, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return 0, fmt.Errorf("bacnet: empty property id")
	}
	if n, err := strconv.ParseUint(s, 10, 32); err == nil {
		return PropertyID(n), nil
	}
	norm := strings.ReplaceAll(s, "-", "_")
	for id, name := range propertyNames {
		if strings.ReplaceAll(name, "-", "_") == norm {
			return id, nil
		}
	}
	return 0, fmt.Errorf("bacnet: unknown property %q", s)
}

// WriteTarget is one object/property a write service would modify.
type WriteTarget struct {
	Object     ObjectID
	Property   PropertyID
	ArrayIndex *uint32
}

func (t WriteTarget) String() string {
	s := t.Object.String() + ":" + t.Property.String()
	if t.ArrayIndex != nil {
		s += "[" + strconv.FormatUint(uint64(*t.ArrayIndex), 10) + "]"
	}
	return s
}

// WriteTargets extracts what a confirmed write would modify.
//
// isWrite is false for every non-write APDU. For a write service that has no
// per-object target (CreateObject, DeleteObject, ReinitializeDevice, ...)
// targets is nil and isWrite is true: the policy must decide on the service
// itself, because there is no object to match a rule against.
//
// An undecodable write returns an error. The caller must deny it: a write
// that cannot be parsed cannot be authorized, and forwarding it "because we
// could not tell" is exactly the bypass the policy exists to prevent.
func WriteTargets(a APDU) (targets []WriteTarget, isWrite bool, err error) {
	if !a.IsWrite() {
		return nil, false, nil
	}
	switch a.Service {
	case ServiceWriteProperty:
		t, err := parseWriteProperty(a.Payload)
		if err != nil {
			return nil, true, err
		}
		return []WriteTarget{t}, true, nil
	case ServiceWritePropertyMultiple:
		ts, err := parseWritePropertyMultiple(a.Payload)
		if err != nil {
			return nil, true, err
		}
		return ts, true, nil
	default:
		return nil, true, nil
	}
}

// parseWriteProperty decodes:
//
//	[0] object-identifier, [1] property-identifier,
//	[2] array-index OPTIONAL, [3] value
func parseWriteProperty(payload []byte) (WriteTarget, error) {
	r := &tagReader{b: payload}
	obj, err := readObjectIDTag(r, 0)
	if err != nil {
		return WriteTarget{}, fmt.Errorf("bacnet: write-property: %w", err)
	}
	prop, err := readPropertyTag(r, 1)
	if err != nil {
		return WriteTarget{}, fmt.Errorf("bacnet: write-property: %w", err)
	}
	var index *uint32
	t, err := r.next()
	if err != nil {
		return WriteTarget{}, fmt.Errorf("bacnet: write-property: %w", err)
	}
	if t.Context && t.Number == 2 {
		v, err := t.uint()
		if err != nil {
			return WriteTarget{}, fmt.Errorf("bacnet: write-property: array index: %w", err)
		}
		index = &v
		if t, err = r.next(); err != nil {
			return WriteTarget{}, fmt.Errorf("bacnet: write-property: %w", err)
		}
	}
	if !t.Context || t.Number != 3 {
		return WriteTarget{}, fmt.Errorf("bacnet: write-property: value tag %d, want context 3", t.Number)
	}
	return WriteTarget{Object: obj, Property: prop, ArrayIndex: index}, nil
}

// parseWritePropertyMultiple decodes:
//
//	[0] { { [0] object-identifier,
//	        [1] { { [0] property-identifier, [1] array-index OPTIONAL,
//	                [2] value, [3] priority OPTIONAL } } } }
func parseWritePropertyMultiple(payload []byte) ([]WriteTarget, error) {
	r := &tagReader{b: payload}
	open, err := r.next()
	if err != nil {
		return nil, fmt.Errorf("bacnet: write-property-multiple: %w", err)
	}
	if !open.Opening || open.Number != 0 {
		return nil, fmt.Errorf("bacnet: write-property-multiple: want opening tag 0, got %+v", open)
	}
	var out []WriteTarget
	for {
		t, err := r.next()
		if err != nil {
			return nil, fmt.Errorf("bacnet: write-property-multiple: %w", err)
		}
		if t.Closing {
			if t.Number != 0 {
				return nil, fmt.Errorf("bacnet: write-property-multiple: closing tag %d, want 0", t.Number)
			}
			if len(out) == 0 {
				return nil, fmt.Errorf("bacnet: write-property-multiple: empty write list")
			}
			return out, nil
		}
		if !t.Context || t.Number != 0 || len(t.Data) != 4 {
			return nil, fmt.Errorf("bacnet: write-property-multiple: want object id, got tag %d", t.Number)
		}
		obj, err := ParseObjectID(t.Data)
		if err != nil {
			return nil, fmt.Errorf("bacnet: write-property-multiple: %w", err)
		}
		spec, err := r.next()
		if err != nil {
			return nil, fmt.Errorf("bacnet: write-property-multiple: %w", err)
		}
		if !spec.Opening || spec.Number != 1 {
			return nil, fmt.Errorf("bacnet: write-property-multiple: want property list, got tag %d", spec.Number)
		}
		var held *Tag
		for {
			var t Tag
			if held != nil {
				t = *held
				held = nil
			} else {
				var err error
				t, err = r.next()
				if err != nil {
					return nil, fmt.Errorf("bacnet: write-property-multiple: %w", err)
				}
			}
			if t.Closing {
				if t.Number != 1 {
					return nil, fmt.Errorf("bacnet: write-property-multiple: closing tag %d, want 1", t.Number)
				}
				break
			}
			prop, err := readPropertyID(t, 0)
			if err != nil {
				return nil, fmt.Errorf("bacnet: write-property-multiple: %w", err)
			}
			var index *uint32
			t, err = r.next()
			if err != nil {
				return nil, fmt.Errorf("bacnet: write-property-multiple: %w", err)
			}
			if t.Context && t.Number == 1 {
				v, err := t.uint()
				if err != nil {
					return nil, fmt.Errorf("bacnet: write-property-multiple: array index: %w", err)
				}
				index = &v
				if t, err = r.next(); err != nil {
					return nil, fmt.Errorf("bacnet: write-property-multiple: %w", err)
				}
			}
			if !t.Context || t.Number != 2 {
				return nil, fmt.Errorf("bacnet: write-property-multiple: value tag %d, want 2", t.Number)
			}
			if t.Opening {
				if err := r.skipValue(t.Number); err != nil {
					return nil, fmt.Errorf("bacnet: write-property-multiple: %w", err)
				}
			}
			// The priority is an optional context tag 3 after the value. It
			// has no effect on the policy target, but it must be consumed or
			// the next iteration would read it as a property identifier.
			t, err = r.next()
			if err != nil {
				return nil, fmt.Errorf("bacnet: write-property-multiple: %w", err)
			}
			if t.Context && t.Number == 3 {
				if _, err := t.uint(); err != nil {
					return nil, fmt.Errorf("bacnet: write-property-multiple: priority: %w", err)
				}
				t, err = r.next()
				if err != nil {
					return nil, fmt.Errorf("bacnet: write-property-multiple: %w", err)
				}
			}
			held = &t
			out = append(out, WriteTarget{Object: obj, Property: prop, ArrayIndex: index})
		}
	}
}

func readObjectIDTag(r *tagReader, want uint8) (ObjectID, error) {
	t, err := r.next()
	if err != nil {
		return ObjectID{}, err
	}
	if !t.Context || t.Number != want || len(t.Data) != 4 {
		return ObjectID{}, fmt.Errorf("want context tag %d with a 4-byte object id, got tag %d", want, t.Number)
	}
	return ParseObjectID(t.Data)
}

func readPropertyTag(r *tagReader, want uint8) (PropertyID, error) {
	t, err := r.next()
	if err != nil {
		return 0, err
	}
	return readPropertyID(t, want)
}

// readPropertyID decodes a context tag that carries a property identifier.
// WriteProperty puts it in tag 1; WritePropertyMultiple's property list puts
// it in tag 0.
func readPropertyID(t Tag, want uint8) (PropertyID, error) {
	if !t.Context || t.Number != want {
		return 0, fmt.Errorf("want context tag %d with a property id, got tag %d", want, t.Number)
	}
	v, err := t.uint()
	if err != nil {
		return 0, fmt.Errorf("property id: %w", err)
	}
	return PropertyID(v), nil
}

// COVSubscriptionObject returns the monitored object of a SubscribeCOV or
// SubscribeCOVProperty request. Both carry it as context tag 1 (the optional
// subscriber-process-identifier is tag 0), which is also why a proxy can
// follow the subscription without decoding the rest.
func COVSubscriptionObject(a APDU) (ObjectID, bool) {
	if a.Type != PDUConfirmedRequest || !a.HasService {
		return ObjectID{}, false
	}
	if a.Service != ServiceSubscribeCOV && a.Service != ServiceSubscribeCOVProperty {
		return ObjectID{}, false
	}
	return objectTag(a.Payload, 1)
}

// COVNotificationObject returns the monitored object of a COV notification.
// Notifications carry it as context tag 2: tag 0 is the subscriber process
// identifier and tag 1 the initiating device identifier.
func COVNotificationObject(a APDU) (ObjectID, bool) {
	notification := (a.Type == PDUUnconfirmedRequest && a.Service == ServiceUnconfirmedCOVNotification) ||
		(a.Type == PDUConfirmedRequest && a.Service == ServiceConfirmedCOVNotification)
	if !notification {
		return ObjectID{}, false
	}
	return objectTag(a.Payload, 2)
}

// objectTag scans the top-level tags for a context tag with a 4-byte object
// identifier. Top-level means it does not descend into constructed values,
// which is all the COV structures need: the identifier is always a sibling
// of the opening tags, never inside one.
func objectTag(payload []byte, want uint8) (ObjectID, bool) {
	r := &tagReader{b: payload}
	for {
		t, err := r.next()
		if err != nil {
			return ObjectID{}, false
		}
		if t.Context && t.Number == want && len(t.Data) == 4 {
			oid, err := ParseObjectID(t.Data)
			if err != nil {
				return ObjectID{}, false
			}
			return oid, true
		}
		if t.Opening {
			if err := r.skipValue(t.Number); err != nil {
				return ObjectID{}, false
			}
		}
	}
}

// COVSubscription decodes the fields the proxy needs from a SubscribeCOV or
// SubscribeCOVProperty request: the monitored object (tag 1), the subscriber
// process identifier (tag 0), and the optional lifetime (tag 3).
//
// hasLifetime is false for a cancellation: a SubscribeCOV with the process id
// and object but no lifetime removes the subscription. A lifetime of 0 means
// "no expiry"; a positive value is a relative expiry in seconds.
func COVSubscription(a APDU) (obj ObjectID, procID uint32, lifetime uint32, hasLifetime bool, ok bool) {
	if a.Type != PDUConfirmedRequest || !a.HasService {
		return ObjectID{}, 0, 0, false, false
	}
	if a.Service != ServiceSubscribeCOV && a.Service != ServiceSubscribeCOVProperty {
		return ObjectID{}, 0, 0, false, false
	}
	var haveObj, haveProc bool
	r := &tagReader{b: a.Payload}
	for r.i < len(r.b) {
		t, err := r.next()
		if err != nil {
			return ObjectID{}, 0, 0, false, false
		}
		if t.Opening {
			if err := r.skipValue(t.Number); err != nil {
				return ObjectID{}, 0, 0, false, false
			}
			continue
		}
		if !t.Context {
			continue
		}
		switch t.Number {
		case 0:
			v, err := t.uint()
			if err != nil {
				return ObjectID{}, 0, 0, false, false
			}
			procID, haveProc = v, true
		case 1:
			if len(t.Data) != 4 {
				return ObjectID{}, 0, 0, false, false
			}
			o, err := ParseObjectID(t.Data)
			if err != nil {
				return ObjectID{}, 0, 0, false, false
			}
			obj, haveObj = o, true
		case 3:
			v, err := t.uint()
			if err != nil {
				return ObjectID{}, 0, 0, false, false
			}
			lifetime, hasLifetime = v, true
		}
	}
	if !haveObj || !haveProc {
		return ObjectID{}, 0, 0, false, false
	}
	return obj, procID, lifetime, hasLifetime, true
}

// COVNotificationProcessID returns the subscriber process identifier of a COV
// notification (context tag 0). It is the same identifier the subscription
// carried, which is what lets the proxy pair a notification with its
// subscriber.
func COVNotificationProcessID(a APDU) (uint32, bool) {
	notification := (a.Type == PDUUnconfirmedRequest && a.Service == ServiceUnconfirmedCOVNotification) ||
		(a.Type == PDUConfirmedRequest && a.Service == ServiceConfirmedCOVNotification)
	if !notification {
		return 0, false
	}
	return topLevelUint(a.Payload, 0)
}

// IAmDeviceID returns the device object identifier of an I-Am (context tag 0).
func IAmDeviceID(a APDU) (ObjectID, bool) {
	if a.Type != PDUUnconfirmedRequest || !a.HasService || a.Service != ServiceIAm {
		return ObjectID{}, false
	}
	return objectTag(a.Payload, 0)
}

func topLevelUint(payload []byte, want uint8) (uint32, bool) {
	r := &tagReader{b: payload}
	for r.i < len(r.b) {
		t, err := r.next()
		if err != nil {
			return 0, false
		}
		if t.Opening {
			if err := r.skipValue(t.Number); err != nil {
				return 0, false
			}
			continue
		}
		if t.Context && t.Number == want {
			v, err := t.uint()
			if err != nil {
				return 0, false
			}
			return v, true
		}
	}
	return 0, false
}
