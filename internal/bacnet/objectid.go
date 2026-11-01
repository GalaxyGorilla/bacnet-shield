package bacnet

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

// ObjectType is the 10-bit BACnet object type.
type ObjectType uint16

// Object types from ASHRAE 135 clause 12 (and the addenda that added the
// later ones). Only the ones a proxy is likely to name in a policy are
// spelled out here; numeric types are accepted everywhere a name is.
const (
	ObjectAnalogInput           ObjectType = 0
	ObjectAnalogOutput          ObjectType = 1
	ObjectAnalogValue           ObjectType = 2
	ObjectBinaryInput           ObjectType = 3
	ObjectBinaryOutput          ObjectType = 4
	ObjectBinaryValue           ObjectType = 5
	ObjectCalendar              ObjectType = 6
	ObjectCommand               ObjectType = 7
	ObjectDevice                ObjectType = 8
	ObjectEventEnrollment       ObjectType = 9
	ObjectFile                  ObjectType = 10
	ObjectGroup                 ObjectType = 11
	ObjectLoop                  ObjectType = 12
	ObjectMultiStateInput       ObjectType = 13
	ObjectMultiStateOutput      ObjectType = 14
	ObjectNotificationClass     ObjectType = 15
	ObjectProgram               ObjectType = 16
	ObjectSchedule              ObjectType = 17
	ObjectAveraging             ObjectType = 18
	ObjectMultiStateValue       ObjectType = 19
	ObjectTrendLog              ObjectType = 20
	ObjectLifeSafetyPoint       ObjectType = 21
	ObjectLifeSafetyZone        ObjectType = 22
	ObjectAccumulator           ObjectType = 23
	ObjectPulseConverter        ObjectType = 24
	ObjectEventLog              ObjectType = 25
	ObjectGlobalGroup           ObjectType = 26
	ObjectTrendLogMultiple      ObjectType = 27
	ObjectLoadControl           ObjectType = 28
	ObjectStructuredView        ObjectType = 29
	ObjectAccessDoor            ObjectType = 30
	ObjectTimer                 ObjectType = 31
	ObjectAccessCredential      ObjectType = 32
	ObjectAccessPoint           ObjectType = 33
	ObjectAccessRights          ObjectType = 34
	ObjectAccessUser            ObjectType = 35
	ObjectAccessZone            ObjectType = 36
	ObjectCredentialDataInput   ObjectType = 37
	ObjectNetworkSecurityPolicy ObjectType = 38
	ObjectBitstringValue        ObjectType = 39
	ObjectCharacterStringValue  ObjectType = 40
	ObjectDatePatternValue      ObjectType = 41
	ObjectDateValue             ObjectType = 42
	ObjectDateTimePatternValue  ObjectType = 43
	ObjectDateTimeValue         ObjectType = 44
	ObjectIntegerValue          ObjectType = 45
	ObjectLargeAnalogValue      ObjectType = 46
	ObjectOctetStringValue      ObjectType = 47
	ObjectPositiveIntegerValue  ObjectType = 48
	ObjectTimePatternValue      ObjectType = 49
	ObjectTimeValue             ObjectType = 50
	ObjectNotificationForwarder ObjectType = 51
	ObjectAlertEnrollment       ObjectType = 52
	ObjectChannel               ObjectType = 53
	ObjectLightOutput           ObjectType = 54
	ObjectBinaryLightingOutput  ObjectType = 55
	ObjectNetworkPort           ObjectType = 56
	ObjectElevatorGroup         ObjectType = 57
	ObjectEscalator             ObjectType = 58
	ObjectLift                  ObjectType = 59
	ObjectStaging               ObjectType = 60
	ObjectAuditLog              ObjectType = 61
	ObjectAuditReport           ObjectType = 62
)

var objectTypeNames = map[ObjectType]string{
	ObjectAnalogInput:           "analog-input",
	ObjectAnalogOutput:          "analog-output",
	ObjectAnalogValue:           "analog-value",
	ObjectBinaryInput:           "binary-input",
	ObjectBinaryOutput:          "binary-output",
	ObjectBinaryValue:           "binary-value",
	ObjectCalendar:              "calendar",
	ObjectCommand:               "command",
	ObjectDevice:                "device",
	ObjectEventEnrollment:       "event-enrollment",
	ObjectFile:                  "file",
	ObjectGroup:                 "group",
	ObjectLoop:                  "loop",
	ObjectMultiStateInput:       "multi-state-input",
	ObjectMultiStateOutput:      "multi-state-output",
	ObjectNotificationClass:     "notification-class",
	ObjectProgram:               "program",
	ObjectSchedule:              "schedule",
	ObjectAveraging:             "averaging",
	ObjectMultiStateValue:       "multi-state-value",
	ObjectTrendLog:              "trend-log",
	ObjectLifeSafetyPoint:       "life-safety-point",
	ObjectLifeSafetyZone:        "life-safety-zone",
	ObjectAccumulator:           "accumulator",
	ObjectPulseConverter:        "pulse-converter",
	ObjectEventLog:              "event-log",
	ObjectGlobalGroup:           "global-group",
	ObjectTrendLogMultiple:      "trend-log-multiple",
	ObjectLoadControl:           "load-control",
	ObjectStructuredView:        "structured-view",
	ObjectAccessDoor:            "access-door",
	ObjectTimer:                 "timer",
	ObjectAccessCredential:      "access-credential",
	ObjectAccessPoint:           "access-point",
	ObjectAccessRights:          "access-rights",
	ObjectAccessUser:            "access-user",
	ObjectAccessZone:            "access-zone",
	ObjectCredentialDataInput:   "credential-data-input",
	ObjectNetworkSecurityPolicy: "network-security-policy",
	ObjectBitstringValue:        "bitstring-value",
	ObjectCharacterStringValue:  "characterstring-value",
	ObjectDatePatternValue:      "date-pattern-value",
	ObjectDateValue:             "date-value",
	ObjectDateTimePatternValue:  "datetime-pattern-value",
	ObjectDateTimeValue:         "datetime-value",
	ObjectIntegerValue:          "integer-value",
	ObjectLargeAnalogValue:      "large-analog-value",
	ObjectOctetStringValue:      "octetstring-value",
	ObjectPositiveIntegerValue:  "positive-integer-value",
	ObjectTimePatternValue:      "time-pattern-value",
	ObjectTimeValue:             "time-value",
	ObjectNotificationForwarder: "notification-forwarder",
	ObjectAlertEnrollment:       "alert-enrollment",
	ObjectChannel:               "channel",
	ObjectLightOutput:           "light-output",
	ObjectBinaryLightingOutput:  "binary-lighting-output",
	ObjectNetworkPort:           "network-port",
	ObjectElevatorGroup:         "elevator-group",
	ObjectEscalator:             "escalator",
	ObjectLift:                  "lift",
	ObjectStaging:               "staging",
	ObjectAuditLog:              "audit-log",
	ObjectAuditReport:           "audit-report",
}

func (t ObjectType) String() string {
	if n, ok := objectTypeNames[t]; ok {
		return n
	}
	return strconv.Itoa(int(t))
}

// ParseObjectType accepts a name ("analog-value"), a numeric type ("2"), and
// the underscore spelling ("analog_value") for convenience. Matching is
// case-insensitive; names are compared with hyphens normalized to
// underscores so a policy written either way means the same object type.
func ParseObjectType(s string) (ObjectType, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return 0, fmt.Errorf("bacnet: empty object type")
	}
	if n, err := strconv.ParseUint(s, 10, 16); err == nil {
		if n > 1023 {
			return 0, fmt.Errorf("bacnet: object type %d does not fit in 10 bits", n)
		}
		return ObjectType(n), nil
	}
	norm := strings.ReplaceAll(s, "-", "_")
	for t, name := range objectTypeNames {
		if strings.ReplaceAll(name, "-", "_") == norm {
			return t, nil
		}
	}
	return 0, fmt.Errorf("bacnet: unknown object type %q", s)
}

// ObjectID is a BACnet object identifier: a 10-bit type and a 22-bit
// instance.
type ObjectID struct {
	Type     ObjectType
	Instance uint32
}

const maxObjectInstance = 1<<22 - 1

// ParseObjectID decodes the 4-byte wire form.
func ParseObjectID(b []byte) (ObjectID, error) {
	if len(b) < 4 {
		return ObjectID{}, fmt.Errorf("bacnet: object id: %d bytes, need 4", len(b))
	}
	v := binary.BigEndian.Uint32(b[:4])
	return ObjectID{Type: ObjectType(v >> 22), Instance: v & maxObjectInstance}, nil
}

// AppendTo appends the 4-byte wire form.
func (o ObjectID) AppendTo(dst []byte) []byte {
	v := uint32(o.Type)<<22 | (o.Instance & maxObjectInstance)
	return binary.BigEndian.AppendUint32(dst, v)
}

func (o ObjectID) String() string {
	return fmt.Sprintf("%s,%d", o.Type, o.Instance)
}

// ParseObjectIDString parses "analog-value,5", "analog-value:5" or the
// numeric "2,5" form. The comma spelling is the BACnet convention; the colon
// spelling exists because a policy file reads better with one separator
// between the three parts.
func ParseObjectIDString(s string) (ObjectID, error) {
	sep := ","
	if !strings.Contains(s, ",") && strings.Contains(s, ":") {
		sep = ":"
	}
	parts := strings.Split(s, sep)
	if len(parts) != 2 {
		return ObjectID{}, fmt.Errorf("bacnet: object id %q: want <type>%s<instance>", s, sep)
	}
	t, err := ParseObjectType(parts[0])
	if err != nil {
		return ObjectID{}, err
	}
	n, err := strconv.ParseUint(strings.TrimSpace(parts[1]), 10, 32)
	if err != nil || n > maxObjectInstance {
		return ObjectID{}, fmt.Errorf("bacnet: object id %q: bad instance %q", s, parts[1])
	}
	return ObjectID{Type: t, Instance: uint32(n)}, nil
}
