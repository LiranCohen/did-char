package char

// DecisionRollResponse represents the response from getreferendumdecisionroll
type DecisionRollResponse struct {
	DomainHash   string        `json:"domain_hash"`
	BallotNumber int           `json:"ballot_number"`
	Leader       string        `json:"leader"`
	LeaderIsMine bool          `json:"leader_is_mine"`
	Found        bool          `json:"found"`
	DecisionRoll *DecisionRoll `json:"decision_roll,omitempty"`
}

// DecisionRoll contains the winning vote data
type DecisionRoll struct {
	RollHash     string   `json:"roll_hash"`
	DataHash     string   `json:"data_hash"`
	Serialized   string   `json:"serialized"`
	EnvelopeHash string   `json:"envelope_hash"`
	Data         string   `json:"data"` // Hex-encoded payload
	Proofs       []string `json:"proofs,omitempty"`
}

// AddBambooKVResponse represents the response from addbambookv
type AddBambooKVResponse map[string]bool
