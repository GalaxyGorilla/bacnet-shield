package bacnet

import (
	"fmt"
	"strconv"
)

// PDUType is the APDU type, the high nibble of the first octet.
type PDUType byte

const (
	PDUConfirmedRequest   PDUType = 0x0
	PDUUnconfirmedRequest PDUType = 0x1
	PDUSimpleACK          PDUType = 0x2
	PDUComplexACK         PDUType = 0x3
	PDUSegmentACK         PDUType = 0x4
	PDUError              PDUType = 0x5
	PDUReject             PDUType = 0x6
	PDUAbort              PDUType = 0x7
)

func (t PDUType) String() string {
	switch t {
	case PDUConfirmedRequest:
		return "confirmed-request"
	case PDUUnconfirmedRequest:
		return "unconfirmed-request"
	case PDUSimpleACK:
		return "simple-ack"
	case PDUComplexACK:
		return "complex-ack"
	case PDUSegmentACK:
		return "segment-ack"
	case PDUError:
		return "error"
	case PDUReject:
		return "reject"
	case PDUAbort:
		return "abort"
	default:
		return fmt.Sprintf("apdu(0x%x)", byte(t))
	}
}

// Service is a confirmed or unconfirmed service choice. The two spaces
// overlap numerically (confirmed 5 is SubscribeCOV, unconfirmed 5 is
// UnconfirmedTextMessage), so the constants are named for their space and
// callers must interpret a Service according to the APDU type.
type Service byte

const (
	// Confirmed services.
	ServiceAcknowledgeAlarm                 Service = 0
	ServiceConfirmedCOVNotification         Service = 1
	ServiceConfirmedEventNotification       Service = 2
	ServiceGetAlarmSummary                  Service = 3
	ServiceGetEnrollmentSummary             Service = 4
	ServiceSubscribeCOV                     Service = 5
	ServiceAtomicReadFile                   Service = 6
	ServiceAtomicWriteFile                  Service = 7
	ServiceAddListElement                   Service = 8
	ServiceRemoveListElement                Service = 9
	ServiceCreateObject                     Service = 10
	ServiceDeleteObject                     Service = 11
	ServiceReadProperty                     Service = 12
	ServiceReadPropertyConditional          Service = 13
	ServiceReadPropertyMultiple             Service = 14
	ServiceWriteProperty                    Service = 15
	ServiceWritePropertyMultiple            Service = 16
	ServiceDeviceCommunicationControl       Service = 17
	ServiceConfirmedPrivateTransfer         Service = 18
	ServiceConfirmedTextMessage             Service = 19
	ServiceReinitializeDevice               Service = 20
	ServiceVTOpen                           Service = 21
	ServiceVTClose                          Service = 22
	ServiceVTData                           Service = 23
	ServiceAuthenticate                     Service = 24
	ServiceRequestKey                       Service = 25
	ServiceReadRange                        Service = 26
	ServiceLifeSafetyOperation              Service = 27
	ServiceSubscribeCOVProperty             Service = 28
	ServiceGetEventInformation              Service = 29
	ServiceSubscribeCOVPropertyMultiple     Service = 30
	ServiceConfirmedCOVNotificationMultiple Service = 31
	ServiceConfirmedAuditNotification       Service = 32
	ServiceAuditLogQuery                    Service = 33
)

// Unconfirmed services. Only the ones with a distinct meaning are listed;
// the numeric values are the wire values.
const (
	ServiceIAm                          Service = 0
	ServiceIHave                        Service = 1
	ServiceUnconfirmedCOVNotification   Service = 2
	ServiceUnconfirmedEventNotification Service = 3
	ServiceUnconfirmedPrivateTransfer   Service = 4
	ServiceUnconfirmedTextMessage       Service = 5
	ServiceTimeSynchronization          Service = 6
	ServiceWhoHas                       Service = 7
	ServiceWhoIs                        Service = 8
	ServiceUTCTimeSynchronization       Service = 9
	ServiceWriteGroup                   Service = 10
)

// APDU is a parsed application PDU.
//
// Payload is the service data after the APDU header (and after the service
// choice where one is present). It is a sub-slice of the parsed datagram;
// the proxy forwards it without copying or re-encoding.
type APDU struct {
	Type    PDUType
	Payload []byte

	// Confirmed-request and complex-ack flags.
	Segmented                 bool
	MoreFollows               bool
	SegmentedResponseAccepted bool
	MaxSegments               byte // confirmed request, 0..7
	MaxAPDU                   byte // confirmed request, 0..5

	InvokeID    byte
	HasInvokeID bool

	SequenceNumber byte
	WindowSize     byte

	NAK    bool // segment-ack
	Server bool // segment-ack / abort

	Service    Service
	HasService bool
}

// ParseAPDU decodes one application PDU.
func ParseAPDU(b []byte) (APDU, error) {
	if len(b) < 1 {
		return APDU{}, fmt.Errorf("bacnet: apdu: empty")
	}
	a := APDU{Type: PDUType(b[0] >> 4)}
	switch a.Type {
	case PDUConfirmedRequest:
		if len(b) < 3 {
			return APDU{}, fmt.Errorf("bacnet: apdu: confirmed request %d bytes, need 3", len(b))
		}
		a.Segmented = b[0]&0x08 != 0
		a.MoreFollows = b[0]&0x04 != 0
		a.SegmentedResponseAccepted = b[0]&0x02 != 0
		a.MaxSegments = (b[1] >> 4) & 0x07
		a.MaxAPDU = b[1] & 0x0F
		a.InvokeID = b[2]
		a.HasInvokeID = true
		i := 3
		if a.Segmented {
			if len(b) < 5 {
				return APDU{}, fmt.Errorf("bacnet: apdu: segmented confirmed request %d bytes, need 5", len(b))
			}
			a.SequenceNumber = b[3]
			a.WindowSize = b[4]
			i = 5
		}
		if len(b) > i {
			a.Service = Service(b[i])
			a.HasService = true
			i++
		}
		a.Payload = b[i:]

	case PDUUnconfirmedRequest:
		if len(b) < 2 {
			return APDU{}, fmt.Errorf("bacnet: apdu: unconfirmed request %d bytes, need 2", len(b))
		}
		a.Service = Service(b[1])
		a.HasService = true
		a.Payload = b[2:]

	case PDUSimpleACK:
		if len(b) < 3 {
			return APDU{}, fmt.Errorf("bacnet: apdu: simple ack %d bytes, need 3", len(b))
		}
		a.InvokeID = b[1]
		a.HasInvokeID = true
		a.Service = Service(b[2])
		a.HasService = true
		a.Payload = b[3:]

	case PDUComplexACK:
		if len(b) < 3 {
			return APDU{}, fmt.Errorf("bacnet: apdu: complex ack %d bytes, need 3", len(b))
		}
		a.Segmented = b[0]&0x08 != 0
		a.MoreFollows = b[0]&0x04 != 0
		a.InvokeID = b[1]
		a.HasInvokeID = true
		i := 2
		if a.Segmented {
			if len(b) < 4 {
				return APDU{}, fmt.Errorf("bacnet: apdu: segmented complex ack %d bytes, need 4", len(b))
			}
			a.SequenceNumber = b[2]
			a.WindowSize = b[3]
			i = 4
		}
		if len(b) > i {
			a.Service = Service(b[i])
			a.HasService = true
			i++
		}
		a.Payload = b[i:]

	case PDUSegmentACK:
		if len(b) < 4 {
			return APDU{}, fmt.Errorf("bacnet: apdu: segment ack %d bytes, need 4", len(b))
		}
		a.NAK = b[0]&0x02 != 0
		a.Server = b[0]&0x01 != 0
		a.InvokeID = b[1]
		a.HasInvokeID = true
		a.SequenceNumber = b[2]
		a.WindowSize = b[3]
		a.Payload = b[4:]

	case PDUError:
		if len(b) < 3 {
			return APDU{}, fmt.Errorf("bacnet: apdu: error %d bytes, need 3", len(b))
		}
		a.InvokeID = b[1]
		a.HasInvokeID = true
		a.Service = Service(b[2])
		a.HasService = true
		a.Payload = b[3:]

	case PDUReject:
		if len(b) < 3 {
			return APDU{}, fmt.Errorf("bacnet: apdu: reject %d bytes, need 3", len(b))
		}
		a.InvokeID = b[1]
		a.HasInvokeID = true
		a.Payload = b[2:]

	case PDUAbort:
		if len(b) < 3 {
			return APDU{}, fmt.Errorf("bacnet: apdu: abort %d bytes, need 3", len(b))
		}
		a.Server = b[0]&0x01 != 0
		a.InvokeID = b[1]
		a.HasInvokeID = true
		a.Payload = b[2:]

	default:
		return APDU{}, fmt.Errorf("bacnet: apdu: invalid pdu type 0x%x", byte(a.Type))
	}
	return a, nil
}

// Marshal encodes the APDU. A parsed APDU round-trips byte for byte as long
// as the fields it carries are the ones on the wire (the parser only sets
// the flags that belong to the type).
func (a APDU) Marshal() []byte {
	switch a.Type {
	case PDUConfirmedRequest:
		b0 := byte(a.Type) << 4
		if a.Segmented {
			b0 |= 0x08
		}
		if a.MoreFollows {
			b0 |= 0x04
		}
		if a.SegmentedResponseAccepted {
			b0 |= 0x02
		}
		out := []byte{b0, (a.MaxSegments&0x07)<<4 | (a.MaxAPDU & 0x0F), a.InvokeID}
		if a.Segmented {
			out = append(out, a.SequenceNumber, a.WindowSize)
		}
		if a.HasService {
			out = append(out, byte(a.Service))
		}
		return append(out, a.Payload...)

	case PDUUnconfirmedRequest:
		out := []byte{byte(a.Type) << 4, byte(a.Service)}
		return append(out, a.Payload...)

	case PDUSimpleACK:
		return append([]byte{byte(a.Type) << 4, a.InvokeID, byte(a.Service)}, a.Payload...)

	case PDUComplexACK:
		b0 := byte(a.Type) << 4
		if a.Segmented {
			b0 |= 0x08
		}
		if a.MoreFollows {
			b0 |= 0x04
		}
		out := []byte{b0, a.InvokeID}
		if a.Segmented {
			out = append(out, a.SequenceNumber, a.WindowSize)
		}
		if a.HasService {
			out = append(out, byte(a.Service))
		}
		return append(out, a.Payload...)

	case PDUSegmentACK:
		b0 := byte(a.Type) << 4
		if a.NAK {
			b0 |= 0x02
		}
		if a.Server {
			b0 |= 0x01
		}
		return append([]byte{b0, a.InvokeID, a.SequenceNumber, a.WindowSize}, a.Payload...)

	case PDUError:
		return append([]byte{byte(a.Type) << 4, a.InvokeID, byte(a.Service)}, a.Payload...)

	case PDUReject:
		return append([]byte{byte(a.Type) << 4, a.InvokeID}, a.Payload...)

	case PDUAbort:
		b0 := byte(a.Type) << 4
		if a.Server {
			b0 |= 0x01
		}
		return append([]byte{b0, a.InvokeID}, a.Payload...)
	}
	return nil
}

// InvokeIDOffset is the index of the invoke-ID octet in the encoded APDU.
// A confirmed request carries two extra octets (flags and max-size) before
// it; every other type has it in the second octet.
func (a APDU) InvokeIDOffset() (int, error) {
	if !a.HasInvokeID {
		return 0, fmt.Errorf("bacnet: apdu: %s has no invoke id", a.Type)
	}
	if a.Type == PDUConfirmedRequest {
		return 2, nil
	}
	return 1, nil
}

// PatchInvokeID rewrites the invoke-ID octet in place. The proxy uses this
// instead of re-encoding: everything else in the client's APDU (and in the
// vendor's answer) stays byte-identical.
func PatchInvokeID(apdu []byte, id byte) error {
	if len(apdu) < 1 {
		return fmt.Errorf("bacnet: apdu: empty")
	}
	t := PDUType(apdu[0] >> 4)
	switch t {
	case PDUConfirmedRequest:
		if len(apdu) < 3 {
			return fmt.Errorf("bacnet: apdu: confirmed request %d bytes", len(apdu))
		}
		apdu[2] = id
	case PDUUnconfirmedRequest:
		return fmt.Errorf("bacnet: apdu: unconfirmed request has no invoke id")
	case PDUSimpleACK, PDUComplexACK, PDUSegmentACK, PDUError, PDUReject, PDUAbort:
		if len(apdu) < 2 {
			return fmt.Errorf("bacnet: apdu: %d bytes", len(apdu))
		}
		apdu[1] = id
	default:
		return fmt.Errorf("bacnet: apdu: invalid pdu type 0x%x", byte(t))
	}
	return nil
}

// IsRequest reports whether the APDU asks a device to do something.
func (a APDU) IsRequest() bool {
	return a.Type == PDUConfirmedRequest || a.Type == PDUUnconfirmedRequest
}

// IsResponse reports whether the APDU answers a confirmed request.
func (a APDU) IsResponse() bool {
	switch a.Type {
	case PDUSimpleACK, PDUComplexACK, PDUError, PDUReject, PDUAbort, PDUSegmentACK:
		return true
	}
	return false
}

// IsWrite reports whether the APDU changes device state. The write policy
// gates these; everything else is a read.
//
// Unconfirmed requests have no invoke ID and no reply, but WriteGroup and
// UnconfirmedPrivateTransfer still change the device. Treating them as
// non-writes would make them a policy bypass that needs no confirmation.
func (a APDU) IsWrite() bool {
	if !a.HasService {
		return false
	}
	if a.Type == PDUUnconfirmedRequest {
		return a.Service == ServiceWriteGroup || a.Service == ServiceUnconfirmedPrivateTransfer
	}
	return a.Type == PDUConfirmedRequest && a.Service.IsWrite()
}

// IsWrite reports whether a confirmed service changes device state.
//
// The list is deliberately the state-changing services, not just
// WriteProperty: a proxy that only inspects WriteProperty leaves
// WritePropertyMultiple, CreateObject, DeleteObject, list edits, file
// writes, and the two "control the device" services as a bypass.
func (s Service) IsWrite() bool {
	switch s {
	case ServiceAcknowledgeAlarm,
		ServiceAtomicWriteFile,
		ServiceAddListElement,
		ServiceRemoveListElement,
		ServiceCreateObject,
		ServiceDeleteObject,
		ServiceWriteProperty,
		ServiceWritePropertyMultiple,
		ServiceDeviceCommunicationControl,
		ServiceConfirmedPrivateTransfer,
		ServiceReinitializeDevice,
		ServiceVTOpen,
		ServiceVTClose,
		ServiceVTData,
		ServiceAuthenticate,
		ServiceRequestKey,
		ServiceLifeSafetyOperation:
		return true
	}
	return false
}

// confirmedServiceNames and unconfirmedServiceNames name the services for the
// audit and log output. The two numeric spaces overlap, so the name is chosen
// by the PDU type; an unnamed service falls back to "service-<n>".
var confirmedServiceNames = map[Service]string{
	ServiceAcknowledgeAlarm:                 "acknowledge-alarm",
	ServiceConfirmedCOVNotification:         "confirmed-cov-notification",
	ServiceConfirmedEventNotification:       "confirmed-event-notification",
	ServiceGetAlarmSummary:                  "get-alarm-summary",
	ServiceGetEnrollmentSummary:             "get-enrollment-summary",
	ServiceSubscribeCOV:                     "subscribe-cov",
	ServiceAtomicReadFile:                   "atomic-read-file",
	ServiceAtomicWriteFile:                  "atomic-write-file",
	ServiceAddListElement:                   "add-list-element",
	ServiceRemoveListElement:                "remove-list-element",
	ServiceCreateObject:                     "create-object",
	ServiceDeleteObject:                     "delete-object",
	ServiceReadProperty:                     "read-property",
	ServiceReadPropertyConditional:          "read-property-conditional",
	ServiceReadPropertyMultiple:             "read-property-multiple",
	ServiceWriteProperty:                    "write-property",
	ServiceWritePropertyMultiple:            "write-property-multiple",
	ServiceDeviceCommunicationControl:       "device-communication-control",
	ServiceConfirmedPrivateTransfer:         "confirmed-private-transfer",
	ServiceConfirmedTextMessage:             "confirmed-text-message",
	ServiceReinitializeDevice:               "reinitialize-device",
	ServiceVTOpen:                           "vt-open",
	ServiceVTClose:                          "vt-close",
	ServiceVTData:                           "vt-data",
	ServiceAuthenticate:                     "authenticate",
	ServiceRequestKey:                       "request-key",
	ServiceReadRange:                        "read-range",
	ServiceLifeSafetyOperation:              "life-safety-operation",
	ServiceSubscribeCOVProperty:             "subscribe-cov-property",
	ServiceGetEventInformation:              "get-event-information",
	ServiceSubscribeCOVPropertyMultiple:     "subscribe-cov-property-multiple",
	ServiceConfirmedCOVNotificationMultiple: "confirmed-cov-notification-multiple",
	ServiceConfirmedAuditNotification:       "confirmed-audit-notification",
	ServiceAuditLogQuery:                    "audit-log-query",
}

var unconfirmedServiceNames = map[Service]string{
	ServiceIAm:                          "i-am",
	ServiceIHave:                        "i-have",
	ServiceUnconfirmedCOVNotification:   "unconfirmed-cov-notification",
	ServiceUnconfirmedEventNotification: "unconfirmed-event-notification",
	ServiceUnconfirmedPrivateTransfer:   "unconfirmed-private-transfer",
	ServiceUnconfirmedTextMessage:       "unconfirmed-text-message",
	ServiceTimeSynchronization:          "time-synchronization",
	ServiceWhoHas:                       "who-has",
	ServiceWhoIs:                        "who-is",
	ServiceUTCTimeSynchronization:       "utc-time-synchronization",
	ServiceWriteGroup:                   "write-group",
}

// ServiceName names the service choice for logging and audit. It returns "" for
// a PDU with no service choice, and "service-<n>" for a number it does not know.
func (a APDU) ServiceName() string {
	if !a.HasService {
		return ""
	}
	var names map[Service]string
	if a.Type == PDUUnconfirmedRequest {
		names = unconfirmedServiceNames
	} else {
		names = confirmedServiceNames
	}
	if n, ok := names[a.Service]; ok {
		return n
	}
	return "service-" + strconv.Itoa(int(a.Service))
}

// ErrorClass is the BACnet error-class octet.
type ErrorClass byte

const (
	ErrorClassDevice        ErrorClass = 0
	ErrorClassObject        ErrorClass = 1
	ErrorClassProperty      ErrorClass = 2
	ErrorClassResources     ErrorClass = 3
	ErrorClassSecurity      ErrorClass = 4
	ErrorClassServices      ErrorClass = 5
	ErrorClassVT            ErrorClass = 6
	ErrorClassCommunication ErrorClass = 7
)

// ErrorCode is the BACnet error-code octet. Only the codes the proxy itself
// generates are named.
type ErrorCode byte

const (
	ErrorCodeOther                ErrorCode = 0
	ErrorCodeInvalidDataType      ErrorCode = 9
	ErrorCodeServiceRequestDenied ErrorCode = 29
	ErrorCodeUnknownObject        ErrorCode = 31
	ErrorCodeUnknownProperty      ErrorCode = 32
	ErrorCodeWriteAccessDenied    ErrorCode = 40
	ErrorCodeUnknownSubscription  ErrorCode = 79
)

// ErrorAPDU builds a locally generated Error PDU answering a confirmed
// request. The invoke ID and service choice must echo the request: a client
// correlates the answer by them, and a mismatch looks like a timeout.
//
// The two parameters are application-tagged ENUMERATEDs (tag 9, one octet) —
// not raw octets. A stack that reads them as tags drops a raw encoding as
// malformed, and the client then waits for a response that already arrived.
func ErrorAPDU(invokeID byte, service Service, class ErrorClass, code ErrorCode) APDU {
	return APDU{
		Type:        PDUError,
		InvokeID:    invokeID,
		HasInvokeID: true,
		Service:     service,
		HasService:  true,
		Payload: []byte{
			tagEnumerated<<4 | 1, byte(class),
			tagEnumerated<<4 | 1, byte(code),
		},
	}
}

// ErrorClassAndCode decodes the error-class and error-code from an Error PDU
// payload. It reports false rather than guessing when the payload is not the
// expected pair of ENUMERATEDs.
func ErrorClassAndCode(payload []byte) (ErrorClass, ErrorCode, bool) {
	r := &tagReader{b: payload}
	classTag, err := r.next()
	if err != nil {
		return 0, 0, false
	}
	class, err := classTag.enumerated()
	if err != nil {
		return 0, 0, false
	}
	codeTag, err := r.next()
	if err != nil {
		return 0, 0, false
	}
	code, err := codeTag.enumerated()
	if err != nil {
		return 0, 0, false
	}
	return ErrorClass(class), ErrorCode(code), true
}

// RejectReason is the reason octet of a Reject PDU.
type RejectReason byte

const (
	RejectReasonOther               RejectReason = 0
	RejectReasonUnrecognizedService RejectReason = 9
)

// RejectAPDU builds a locally generated Reject PDU. It is the correct answer
// when the proxy cannot serve a confirmed request at all (an unsupported
// service), as opposed to an Error PDU, which reports a service-level failure.
func RejectAPDU(invokeID byte, reason RejectReason) APDU {
	return APDU{
		Type:        PDUReject,
		InvokeID:    invokeID,
		HasInvokeID: true,
		Payload:     []byte{byte(reason)},
	}
}
