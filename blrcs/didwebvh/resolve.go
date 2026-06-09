package didwebvh

import (
	"crypto/ed25519"
	"fmt"
	"time"

	"blrcs/multiformats"
)

// CreateParams configures genesis creation of a did:webvh log.
type CreateParams struct {
	// DIDPath is the method-specific id WITHOUT the SCID, e.g.
	// "example.com:dids:abc". The full DID becomes did:webvh:<scid>:<DIDPath>.
	DIDPath string
	// UpdateKey signs the genesis entry; its Multikey goes into updateKeys.
	UpdateKey ed25519.PrivateKey
	// NextKeyHashes optionally pre-commits the next rotation keys.
	NextKeyHashes []string
	// VersionTime is the genesis time (defaults to now UTC).
	VersionTime time.Time
	// StateExtra lets the caller add fields to the genesis DID document.
	StateExtra map[string]any
}

// Create builds and signs the genesis log entry for a new did:webvh DID.
// It returns the entry (with computed SCID and versionId) and the resolved DID.
func Create(p CreateParams) (*LogEntry, string, error) {
	if p.UpdateKey == nil {
		return nil, "", fmt.Errorf("didwebvh: update key required")
	}
	vt := p.VersionTime
	if vt.IsZero() {
		vt = time.Now().UTC()
	}
	updatePub := p.UpdateKey.Public().(ed25519.PublicKey)
	updateMultikey := multiformats.EncodeEd25519Multikey(updatePub)

	// Genesis DID document uses the {SCID} placeholder in its id.
	placeholderDID := "did:" + Method + ":" + SCIDPlaceholder + ":" + p.DIDPath
	state := map[string]any{
		"id": placeholderDID,
	}
	for k, v := range p.StateExtra {
		state[k] = v
	}

	entry := &LogEntry{
		VersionTime: vt.UTC().Format(time.RFC3339),
		Parameters: Parameters{
			Method:        "did:" + Method + ":1.0",
			SCID:          SCIDPlaceholder,
			UpdateKeys:    []string{updateMultikey},
			NextKeyHashes: p.NextKeyHashes,
		},
		State: state,
	}

	// 1. Derive the SCID from the placeholder entry.
	scidInput, err := entryHashInput(entry, SCIDPlaceholder)
	if err != nil {
		return nil, "", err
	}
	scid, err := computeHash(scidInput)
	if err != nil {
		return nil, "", err
	}

	// 2. Substitute the real SCID everywhere the placeholder appears.
	entry.Parameters.SCID = scid
	entry.State = substituteSCID(entry.State, SCIDPlaceholder, scid).(map[string]any)
	did := "did:" + Method + ":" + scid + ":" + p.DIDPath

	// 3. Compute entryHash (predecessor = SCID for genesis) and versionId.
	eh, err := computeEntryHash(entry, scid)
	if err != nil {
		return nil, "", err
	}
	entry.VersionID = "1-" + eh

	// 4. Sign the entry with the update key (predecessor versionId = SCID).
	vm := did + "#" + updateMultikey
	proof, err := signEntry(entry, scid, p.UpdateKey, vm, entry.VersionTime)
	if err != nil {
		return nil, "", err
	}
	entry.Proof = []Proof{proof}
	return entry, did, nil
}

// UpdateParams configures appending a new entry to an existing log.
type UpdateParams struct {
	Log           []LogEntry         // existing verified log
	SignKey       ed25519.PrivateKey // a key authorized by the current entry (or pre-rotated)
	NewState      map[string]any     // the new DID document
	UpdateKeys    []string           // updateKeys to take effect from this entry (Multikey)
	NextKeyHashes []string           // pre-rotation commitments for the next entry
	VersionTime   time.Time
	Deactivate    bool
}

// Update appends a signed entry to the log and returns the new entry.
func Update(p UpdateParams) (*LogEntry, error) {
	if len(p.Log) == 0 {
		return nil, ErrEmptyLog
	}
	if p.SignKey == nil {
		return nil, fmt.Errorf("didwebvh: signing key required")
	}
	prev := p.Log[len(p.Log)-1]
	prevNum, _, err := parseVersionID(prev.VersionID)
	if err != nil {
		return nil, err
	}
	vt := p.VersionTime
	if vt.IsZero() {
		vt = time.Now().UTC()
	}

	scid := effectiveSCID(p.Log)
	did := didFromState(prev.State)

	signPub := p.SignKey.Public().(ed25519.PublicKey)
	signMultikey := multiformats.EncodeEd25519Multikey(signPub)

	updateKeys := p.UpdateKeys
	if updateKeys == nil {
		updateKeys = effectiveUpdateKeys(p.Log)
	}

	entry := &LogEntry{
		VersionTime: vt.UTC().Format(time.RFC3339),
		Parameters: Parameters{
			SCID:          scid,
			UpdateKeys:    updateKeys,
			NextKeyHashes: p.NextKeyHashes,
			Deactivated:   p.Deactivate,
		},
		State: p.NewState,
	}

	eh, err := computeEntryHash(entry, prev.VersionID)
	if err != nil {
		return nil, err
	}
	entry.VersionID = fmt.Sprintf("%d-%s", prevNum+1, eh)

	vm := did + "#" + signMultikey
	proof, err := signEntry(entry, prev.VersionID, p.SignKey, vm, entry.VersionTime)
	if err != nil {
		return nil, err
	}
	entry.Proof = []Proof{proof}
	return entry, nil
}

// ============================================================================
// Verify / Resolve
// ============================================================================

// Resolution is the result of verifying a did:webvh log.
type Resolution struct {
	DID         string
	SCID        string
	Document    map[string]any // latest DID document (state)
	VersionID   string
	VersionTime string
	Deactivated bool
}

// Verify validates a complete did:webvh log and returns the resolved DID
// document. It enforces SCID self-certification, entry hash-chaining, sequential
// versions, monotonic versionTime, update-key authorization, and pre-rotation
// commitments. A deactivated DID resolves successfully with Deactivated=true.
func Verify(log []LogEntry) (*Resolution, error) {
	if len(log) == 0 {
		return nil, ErrEmptyLog
	}

	genesis := &log[0]
	scid := genesis.Parameters.SCID
	if scid == "" {
		return nil, fmt.Errorf("%w: genesis has no scid", ErrMalformedEntry)
	}

	// 1. SCID self-certification.
	derived, err := deriveSCID(genesis)
	if err != nil {
		return nil, err
	}
	if derived != scid {
		return nil, fmt.Errorf("%w: derived %s want %s", ErrSCIDMismatch, derived, scid)
	}

	var (
		predecessorVersionID = scid
		prevNum              = 0
		prevTime             time.Time
		currentUpdateKeys    []string
		pendingNextHashes    []string // nextKeyHashes committed by the previous entry
		deactivated          bool
	)

	for i := range log {
		entry := &log[i]

		// 2. Version sequence.
		num, hash, err := parseVersionID(entry.VersionID)
		if err != nil {
			return nil, err
		}
		if num != prevNum+1 {
			return nil, fmt.Errorf("%w: got %d after %d", ErrVersionSequence, num, prevNum)
		}

		// 3. entryHash chaining.
		eh, err := computeEntryHash(entry, predecessorVersionID)
		if err != nil {
			return nil, err
		}
		if eh != hash {
			return nil, fmt.Errorf("%w: entry %d", ErrEntryHashMismatch, num)
		}

		// 4. versionTime monotonicity.
		if !versionTimeValid(entry.VersionTime) {
			return nil, fmt.Errorf("%w: bad versionTime %q", ErrMalformedEntry, entry.VersionTime)
		}
		t, _ := time.Parse(time.RFC3339, entry.VersionTime)
		if i > 0 && t.Before(prevTime) {
			return nil, fmt.Errorf("%w: versionTime went backwards at entry %d", ErrMalformedEntry, num)
		}

		// 5. Determine the update keys authorized to sign THIS entry.
		//    Genesis is self-authorizing; later entries are authorized by the
		//    keys in effect from the previous entry.
		authKeys := currentUpdateKeys
		if i == 0 {
			authKeys = entry.Parameters.UpdateKeys
		}
		if len(authKeys) == 0 {
			return nil, ErrNoUpdateKeys
		}

		// 6. Pre-rotation: if the predecessor committed nextKeyHashes, this entry
		//    MUST rotate to a pre-committed key. An attacker with the current key
		//    must not be able to bypass the commitment by simply omitting
		//    updateKeys (which would silently keep the compromised key in force).
		//    Genesis (i==0) has no predecessor commitment to honor.
		if i > 0 && pendingNextHashes != nil {
			if entry.Parameters.UpdateKeys == nil {
				return nil, fmt.Errorf("%w: entry %d must rotate to a pre-committed key", ErrPreRotation, num)
			}
			if err := checkPreRotation(entry.Parameters.UpdateKeys, pendingNextHashes); err != nil {
				return nil, err
			}
		}

		// 7. Verify the entry proof against the authorized keys.
		signer, err := verifyEntryProof(entry, predecessorVersionID, authKeys)
		if err != nil {
			return nil, err
		}
		_ = signer

		// Advance rolling state.
		if entry.Parameters.UpdateKeys != nil {
			currentUpdateKeys = entry.Parameters.UpdateKeys
		}
		// nextKeyHashes is "sticky": once set it governs the following entry.
		pendingNextHashes = entry.Parameters.NextKeyHashes
		if entry.Parameters.Deactivated {
			deactivated = true
		}
		predecessorVersionID = entry.VersionID
		prevNum = num
		prevTime = t
	}

	last := &log[len(log)-1]
	return &Resolution{
		DID:         didFromState(genesis.State),
		SCID:        scid,
		Document:    last.State,
		VersionID:   last.VersionID,
		VersionTime: last.VersionTime,
		Deactivated: deactivated,
	}, nil
}

// checkPreRotation ensures every newly-effective update key is committed in the
// predecessor's nextKeyHashes.
func checkPreRotation(newUpdateKeys, committed []string) error {
	commitSet := make(map[string]bool, len(committed))
	for _, h := range committed {
		commitSet[h] = true
	}
	for _, mk := range newUpdateKeys {
		if !commitSet[keyHash(mk)] {
			return fmt.Errorf("%w: key %s not pre-committed", ErrPreRotation, mk)
		}
	}
	return nil
}

// effectiveSCID returns the SCID in force for the log.
func effectiveSCID(log []LogEntry) string {
	if len(log) == 0 {
		return ""
	}
	return log[0].Parameters.SCID
}

// effectiveUpdateKeys returns the update keys in force at the end of the log.
func effectiveUpdateKeys(log []LogEntry) []string {
	var keys []string
	for i := range log {
		if log[i].Parameters.UpdateKeys != nil {
			keys = log[i].Parameters.UpdateKeys
		}
	}
	return keys
}

func didFromState(state map[string]any) string {
	if state == nil {
		return ""
	}
	id, _ := state["id"].(string)
	return id
}
