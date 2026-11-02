package bacnet

import "fmt"

// Multi-object COV transactions: SubscribeCOVPropertyMultiple and the COV
// notification-multiple services. The proxy does not need the monitored
// properties (it routes by object, not by property), so both decoders extract
// only the subscriber process identifier and the monitored object identifiers.
// Everything else is skipped structurally, which keeps the parser tolerant of
// the optional fields a peer may add without turning them into routing state.

// COVMultipleSubscription decodes a SubscribeCOVPropertyMultiple request:
// subscriber-process-identifier (tag 0), optional lifetime (tag 2) and the
// monitored objects from listOfCOVPropertyReferences (tag 4). A cancellation
// has no lifetime and must name the same objects it wants to remove.
func COVMultipleSubscription(a APDU) (objects []ObjectID, procID uint32, lifetime uint32, hasLifetime bool, ok bool) {
	if a.Type != PDUConfirmedRequest || !a.HasService ||
		a.Service != ServiceSubscribeCOVPropertyMultiple {
		return nil, 0, 0, false, false
	}

	var haveProc bool
	r := &tagReader{b: a.Payload}
	for r.i < len(r.b) {
		t, err := r.next()
		if err != nil {
			return nil, 0, 0, false, false
		}
		if t.Opening {
			if err := r.skipValue(t.Number); err != nil {
				return nil, 0, 0, false, false
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
				return nil, 0, 0, false, false
			}
			procID, haveProc = v, true
		case 2:
			v, err := t.uint()
			if err != nil {
				return nil, 0, 0, false, false
			}
			lifetime, hasLifetime = v, true
		}
	}
	if !haveProc {
		return nil, 0, 0, false, false
	}
	objects, err := objectList(a.Payload, 4)
	if err != nil || len(objects) == 0 {
		return nil, 0, 0, false, false
	}
	return objects, procID, lifetime, hasLifetime, true
}

// IsCOVMultipleNotification reports whether a is a COVNotificationMultiple,
// confirmed or unconfirmed. It is separate from COVMultipleNotification so a
// caller can treat a malformed multiple notification as unroutable instead of
// falling through to the single-object (or broadcast) path.
func IsCOVMultipleNotification(a APDU) bool {
	return (a.Type == PDUUnconfirmedRequest && a.Service == ServiceUnconfirmedCOVNotificationMultiple) ||
		(a.Type == PDUConfirmedRequest && a.Service == ServiceConfirmedCOVNotificationMultiple)
}

// COVMultipleNotification decodes a COVNotificationMultiple, confirmed or
// unconfirmed: the subscriber process identifier (tag 0) and one monitored
// object per listOfCOVNotifications element (tag 4). A notification that names
// no object is useless to the router and is rejected rather than broadcast.
func COVMultipleNotification(a APDU) (objects []ObjectID, procID uint32, ok bool) {
	if !IsCOVMultipleNotification(a) {
		return nil, 0, false
	}
	procID, ok = topLevelUint(a.Payload, 0)
	if !ok {
		return nil, 0, false
	}
	objects, err := objectList(a.Payload, 4)
	if err != nil || len(objects) == 0 {
		return nil, 0, false
	}
	return objects, procID, true
}

// objectList finds a top-level constructed list tag and collects the monitored
// object identifier at the start of each element. Both the subscription list
// and the notification list have the same element shape: an opening [0], then
// the object identifier in another [0]. Any later child is skipped, so the
// optional per-property fields never affect routing.
func objectList(payload []byte, listTag uint8) ([]ObjectID, error) {
	r := &tagReader{b: payload}
	for r.i < len(r.b) {
		t, err := r.next()
		if err != nil {
			return nil, err
		}
		if t.Opening && t.Number == listTag {
			return readObjectList(r, listTag)
		}
		if t.Opening {
			if err := r.skipValue(t.Number); err != nil {
				return nil, err
			}
		}
	}
	return nil, fmt.Errorf("bacnet: cov: list tag %d missing", listTag)
}

func readObjectList(r *tagReader, listTag uint8) ([]ObjectID, error) {
	var objects []ObjectID
	for {
		t, err := r.next()
		if err != nil {
			return nil, err
		}
		switch {
		case t.Closing:
			if t.Number != listTag {
				return nil, fmt.Errorf("bacnet: cov: closing tag %d, want %d", t.Number, listTag)
			}
			return objects, nil
		case t.Context && t.Number == 0 && len(t.Data) == 4:
			oid, err := ParseObjectID(t.Data)
			if err != nil {
				return nil, err
			}
			objects = append(objects, oid)
			// The element's second field is the constructed [1] list of
			// monitored properties (subscription) or values (notification).
			// A BACnet SEQUENCE has no tag of its own, so the next tag is
			// either that list or the end of the outer list.
			nxt, err := r.next()
			if err != nil {
				return nil, err
			}
			switch {
			case nxt.Opening && nxt.Number == 1:
				if err := r.skipValue(1); err != nil {
					return nil, err
				}
			case nxt.Closing && nxt.Number == listTag:
				return objects, nil
			default:
				return nil, fmt.Errorf("bacnet: cov: element %d has no [1] list", len(objects)-1)
			}
		default:
			return nil, fmt.Errorf("bacnet: cov: unexpected tag %d in object list", t.Number)
		}
	}
}
