package mdoc

import (
	"fmt"

	"blrcs/cbor"
)

// Present produces a selectively-disclosed IssuerSigned: it keeps only the
// requested elements per namespace and drops all others, leaving issuerAuth (and
// thus the MSO with the full set of value digests) untouched.
//
// reveal maps namespace → set of elementIdentifiers to keep. A namespace absent
// from reveal is dropped entirely. The result still verifies against the original
// issuer key: the verifier digest-checks only the disclosed items.
func Present(issuerSigned []byte, reveal map[string][]string) ([]byte, error) {
	top, err := cbor.Unmarshal(issuerSigned)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	topMap, ok := top.(map[any]any)
	if !ok {
		return nil, ErrMalformed
	}

	issuerAuth, ok := topMap[isIssuerAuth]
	if !ok {
		return nil, fmt.Errorf("%w: missing issuerAuth", ErrMalformed)
	}
	issuerAuthBytes, err := cbor.Marshal(issuerAuth)
	if err != nil {
		return nil, err
	}

	// Build a keep-set for O(1) lookup.
	keep := map[string]map[string]bool{}
	for ns, ids := range reveal {
		set := make(map[string]bool, len(ids))
		for _, id := range ids {
			set[id] = true
		}
		keep[ns] = set
	}

	filteredNS := map[string]any{}
	if nsRaw, ok := topMap[isNameSpaces]; ok && nsRaw != nil {
		nsMap, ok := nsRaw.(map[any]any)
		if !ok {
			return nil, fmt.Errorf("%w: nameSpaces not a map", ErrMalformed)
		}
		for nsKey, itemsRaw := range nsMap {
			ns, ok := nsKey.(string)
			if !ok {
				continue
			}
			wantSet, wanted := keep[ns]
			if !wanted {
				continue // drop entire namespace
			}
			items, ok := itemsRaw.([]any)
			if !ok {
				continue
			}
			kept := make([]any, 0, len(items))
			for _, itemRaw := range items {
				id, err := itemElementID(itemRaw)
				if err != nil {
					return nil, err
				}
				if wantSet[id] {
					kept = append(kept, itemRaw)
				}
			}
			if len(kept) > 0 {
				filteredNS[ns] = kept
			}
		}
	}

	return cbor.Marshal(map[string]any{
		isNameSpaces: filteredNS,
		isIssuerAuth: rawCBOR(issuerAuthBytes),
	})
}

// itemElementID extracts the elementIdentifier from a tag-24 IssuerSignedItem.
func itemElementID(itemRaw any) (string, error) {
	tag, ok := itemRaw.(cbor.Tag)
	if !ok || tag.Number != tagEncodedCBOR {
		return "", fmt.Errorf("%w: item not tag-24", ErrMalformed)
	}
	inner, ok := tag.Content.([]byte)
	if !ok {
		return "", fmt.Errorf("%w: tag-24 content not bstr", ErrMalformed)
	}
	v, err := cbor.Unmarshal(inner)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	m, ok := v.(map[any]any)
	if !ok {
		return "", fmt.Errorf("%w: item not a map", ErrMalformed)
	}
	id, _ := m[isiElementID].(string)
	return id, nil
}
