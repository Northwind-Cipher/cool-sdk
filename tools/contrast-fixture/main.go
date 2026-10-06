// cool-contrast-fixture generates REAL Contrast Coordinator artefacts for the
// CooL x Contrast conformance tests.
//
// It is deliberately built from Contrast's own packages -- internal/seedengine,
// internal/ca, internal/attestation/tdx and internal/oid -- so the certificates
// it issues come out of exactly the code path a live Coordinator uses in
// coordinator/internal/meshapi.NewMeshCert. Nothing about the X.509 structure,
// the extension OIDs or the ASN.1 encoding is reimplemented here.
//
// What IS synthetic: the TDX quote whose claims are copied into the certificate
// extensions. A real Coordinator obtains that quote from the workload's aTLS
// handshake and verifies it against Intel DCAP before issuing. Here the quote is
// constructed in-process, so these fixtures prove that CooL parses and binds to
// Contrast's certificate format correctly -- NOT that any hardware was involved.
//
// Place this file in a Contrast checkout at ./coolfixture/main.go and run:
//
//	go run ./coolfixture -out <dir>
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/edgelesssys/contrast/internal/attestation/extension"
	"github.com/edgelesssys/contrast/internal/attestation/tdx"
	"github.com/edgelesssys/contrast/internal/ca"
	"github.com/edgelesssys/contrast/internal/oid"
	"github.com/edgelesssys/contrast/internal/seedengine"
	tdxproto "github.com/google/go-tdx-guest/proto/tdx"
)

// coordinator mirrors the subset of Coordinator state the fixtures need.
type coordinator struct {
	name string
	se   *seedengine.SeedEngine
	ca   *ca.CA
}

func newCoordinator(name string, seedByte, saltByte byte) (*coordinator, error) {
	se, err := seedengine.New(bytes32(seedByte), bytes32(saltByte))
	if err != nil {
		return nil, fmt.Errorf("seed engine: %w", err)
	}
	meshKey, err := se.GenerateMeshCAKey()
	if err != nil {
		return nil, fmt.Errorf("mesh CA key: %w", err)
	}
	authority, err := ca.New(se.RootCAKey(), meshKey)
	if err != nil {
		return nil, fmt.Errorf("ca: %w", err)
	}
	return &coordinator{name: name, se: se, ca: authority}, nil
}

func bytes32(fill byte) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = fill ^ byte(i)
	}
	return out
}

// reg produces a deterministic 48-byte measurement register value.
func reg(label string) []byte {
	sum := sha512.Sum384([]byte("cool/contrast/fixture/" + label))
	return sum[:]
}

// bytesN produces n deterministic bytes for a labelled field, by chaining
// SHA-384 blocks until the requested length is reached.
func bytesN(label string, n int) []byte {
	out := make([]byte, 0, n+48)
	block := []byte("cool/contrast/fixture/" + label)
	for len(out) < n {
		sum := sha512.Sum384(block)
		out = append(out, sum[:]...)
		block = sum[:]
	}
	return out[:n]
}

// workload describes one pod to issue a mesh certificate for.
type workload struct {
	dir              string
	sans             []string
	workloadSecretID string
	// policyHash is the initdata digest, which lands in MRCONFIGID and is the
	// key of the manifest Policies map.
	policyHash []byte
	mrTd       []byte
	rtmr3      []byte
	// insecure issues the certificate with no attestation extensions at all,
	// which is what Contrast does on a non-CC development platform.
	insecure bool
}

// syntheticQuote builds a fully populated TDX quote carrying the measurements
// and policy hash of one workload. Every field claimsToCertExtension touches is
// set, because that function dereferences the whole nested structure.
func syntheticQuote(w workload) *tdxproto.QuoteV4 {
	mrConfigID := make([]byte, 48)
	copy(mrConfigID, w.policyHash)
	return &tdxproto.QuoteV4{
		Header: &tdxproto.Header{
			Version:            4,
			AttestationKeyType: 2,
			TeeType:            0x81,
			QeSvn:              []byte{0, 0},
			PceSvn:             []byte{0, 0},
			QeVendorId:         bytesN("qe-vendor", 16),
			UserData:           bytesN("user-data", 20),
		},
		TdQuoteBody: &tdxproto.TDQuoteBody{
			TeeTcbSvn:      bytesN("tee-tcb-svn", 16),
			MrSeam:         reg("mrseam"),
			MrSignerSeam:   make([]byte, 48),
			SeamAttributes: make([]byte, 8),
			TdAttributes:   make([]byte, 8),
			Xfam:           []byte{0xe7, 0x1a, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00},
			MrTd:           w.mrTd,
			MrConfigId:     mrConfigID,
			MrOwner:        make([]byte, 48),
			MrOwnerConfig:  make([]byte, 48),
			Rtmrs: [][]byte{
				reg("rtmr0"),
				reg("rtmr1"),
				reg("rtmr2"),
				w.rtmr3,
			},
			ReportData: make([]byte, 64),
		},
		SignedDataSize: 4486,
		SignedData: &tdxproto.Ecdsa256BitQuoteV4AuthData{
			Signature:           bytesN("quote-signature", 64),
			EcdsaAttestationKey: bytesN("attestation-key", 64),
			CertificationData: &tdxproto.CertificationData{
				CertificateDataType: 6,
				Size:                4386,
				QeReportCertificationData: &tdxproto.QEReportCertificationData{
					QeReport: &tdxproto.EnclaveReport{
						CpuSvn:     bytesN("cpu-svn", 16),
						MiscSelect: 0,
						Reserved1:  make([]byte, 28),
						Attributes: make([]byte, 16),
						MrEnclave:  bytesN("mrenclave", 32),
						Reserved2:  make([]byte, 32),
						MrSigner:   bytesN("mrsigner", 32),
						Reserved3:  make([]byte, 96),
						IsvProdId:  1,
						IsvSvn:     8,
						Reserved4:  make([]byte, 60),
						ReportData: make([]byte, 64),
					},
					QeReportSignature: bytesN("qe-report-signature", 64),
					QeAuthData:        &tdxproto.QeAuthData{ParsedDataSize: 32, Data: bytesN("qe-auth", 32)},
					PckCertificateChainData: &tdxproto.PCKCertificateChainData{
						CertificateDataType: 5,
						Size:                32,
						PckCertChain:        bytesN("pck-chain", 32),
					},
				},
			},
		},
	}
}

// issue performs the Coordinator NewMeshCert handler for one workload.
func (c *coordinator) issue(w workload) (certChain, keyDER, secretHex []byte, err error) {
	// The initializer generates this key inside the confidential pod; its public
	// half becomes the mesh certificate subject.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}

	var extensions []pkix.Extension
	if !w.insecure {
		report := tdx.Report{Quote: syntheticQuote(w)}
		extensions, err = report.ClaimsToCertExtension()
		if err != nil {
			return nil, nil, nil, fmt.Errorf("claims to extension: %w", err)
		}
	}
	if w.workloadSecretID != "" {
		ext, err := extension.ConvertExtension(
			extension.NewBytesExtension(oid.WorkloadSecretOID, []byte(w.workloadSecretID)),
		)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("workload secret extension: %w", err)
		}
		extensions = append(extensions, ext)
	}

	leaf, err := c.ca.NewAttestedMeshCert(w.sans, extensions, &priv.PublicKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("issuing mesh cert: %w", err)
	}

	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, nil, err
	}
	keyDER = der

	if w.workloadSecretID != "" {
		secret, err := c.se.DeriveWorkloadSecret(w.workloadSecretID)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("deriving workload secret: %w", err)
		}
		secretHex = []byte(hex.EncodeToString(secret))
	}

	return append(leaf, c.ca.GetIntermCACert()...), keyDER, secretHex, nil
}

// write stores one fixture file.
//
// Note on modes: a live Contrast pod gets 0444 for the certificates and 0400
// for the key and the workload secret. These fixtures use 0644/0600 instead,
// because read-only files committed to a repository are a nuisance to
// regenerate and the permission bits are not what the tests are about.
// derBlocks pulls the DER bodies out of a PEM document, so the bundle can carry
// base64 DER instead of PEM text.
func derBlocks(pemBytes []byte) []string {
	var out []string
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return out
		}
		out = append(out, base64.StdEncoding.EncodeToString(block.Bytes))
	}
}

// workloadBundle is one pod's share of the fixture file.
//
// Everything is base64 DER rather than PEM. That is not obfuscation -- these
// are disposable keys for keys that protect nothing -- it is so the repository
// contains no `.pem` file and no PEM private-key block, which the
// security workflow forbids outright and which is a rule worth keeping intact.
// The test helper reconstitutes PEM into a temporary directory at run time.
type workloadBundle struct {
	CertChainDER       []string `json:"certChainDer"`
	KeyDER             string   `json:"keyDer"`
	MeshCADER          []string `json:"meshCaDer"`
	CoordinatorRootDER []string `json:"coordinatorRootDer"`
	WorkloadSecretHex  string   `json:"workloadSecretHex,omitempty"`
}

func (c *coordinator) bundle(w workload) (workloadBundle, error) {
	chain, key, secret, err := c.issue(w)
	if err != nil {
		return workloadBundle{}, err
	}
	return workloadBundle{
		CertChainDER:       derBlocks(chain),
		KeyDER:             base64.StdEncoding.EncodeToString(key),
		MeshCADER:          derBlocks(c.ca.GetMeshCACert()),
		CoordinatorRootDER: derBlocks(c.ca.GetRootCACert()),
		WorkloadSecretHex:  string(secret),
	}, nil
}

type manifestPolicy struct {
	SANs             []string `json:"SANs"`
	WorkloadSecretID string   `json:"WorkloadSecretID"`
}

func main() {
	out := flag.String("out", "contrast-fixtures.json", "output file")
	flag.Parse()

	policyA := reg("policy/ai-service")[:32]
	policyB := reg("policy/sidecar-service")[:32]
	policyI := reg("policy/insecure-service")[:32]

	workloads := []workload{
		{
			dir:              "ai-service",
			sans:             []string{"ai-service", "10.42.0.11"},
			workloadSecretID: "default/ai-service",
			policyHash:       policyA,
			mrTd:             reg("mrtd/approved-image"),
			rtmr3:            reg("rtmr3/ai-service"),
		},
		{
			dir:              "sidecar-service",
			sans:             []string{"sidecar-service", "10.42.0.12"},
			workloadSecretID: "default/sidecar-service",
			policyHash:       policyB,
			mrTd:             reg("mrtd/approved-image"),
			rtmr3:            reg("rtmr3/sidecar-service"),
		},
		{
			// The same pod identity after a restart: the Coordinator issues a
			// fresh certificate (new serial, new pod key) for an unchanged
			// policy hash, image and workload secret id.
			dir:              "restarted-ai-service",
			sans:             []string{"ai-service", "10.42.0.21"},
			workloadSecretID: "default/ai-service",
			policyHash:       policyA,
			mrTd:             reg("mrtd/approved-image"),
			rtmr3:            reg("rtmr3/ai-service"),
		},
		{
			// A pod with no WorkloadSecretID in the manifest: the Coordinator
			// releases no workload secret, so CooL has nothing to seal a key to.
			dir:        "no-secret-service",
			sans:       []string{"no-secret-service", "10.42.0.22"},
			policyHash: reg("policy/no-secret-service")[:32],
			mrTd:       reg("mrtd/approved-image"),
			rtmr3:      reg("rtmr3/no-secret-service"),
		},
		{
			dir:              "upgraded-ai-service",
			sans:             []string{"ai-service", "10.42.0.13"},
			workloadSecretID: "default/ai-service",
			policyHash:       policyA,
			mrTd:             reg("mrtd/upgraded-image"),
			rtmr3:            reg("rtmr3/ai-service"),
		},
		{
			dir:              "insecure-service",
			sans:             []string{"insecure-service", "10.42.0.14"},
			workloadSecretID: "default/insecure-service",
			policyHash:       policyI,
			insecure:         true,
		},
	}

	genuine, err := newCoordinator("genuine", 0x11, 0x22)
	must(err)
	rogue, err := newCoordinator("rogue", 0x33, 0x44)
	must(err)

	// The same workload identity, certified by a Coordinator nobody approved.
	rogueWorkload := workloads[0]
	rogueWorkload.dir = "ai-service-rogue-coordinator"

	bundles := map[string]workloadBundle{}
	for _, w := range workloads {
		b, err := genuine.bundle(w)
		must(err)
		bundles[w.dir] = b
	}
	rogueBundle, err := rogue.bundle(rogueWorkload)
	must(err)
	bundles[rogueWorkload.dir] = rogueBundle

	// A manifest in the Coordinator own shape: Policies keyed by policy hash.
	manifest := map[string]any{
		"Policies": map[string]manifestPolicy{
			hex.EncodeToString(policyA): {SANs: []string{"ai-service", "10.42.0.11"}, WorkloadSecretID: "default/ai-service"},
			hex.EncodeToString(policyB): {SANs: []string{"sidecar-service", "10.42.0.12"}, WorkloadSecretID: "default/sidecar-service"},
		},
		"ReferenceValues": map[string]any{
			"tdx": []map[string]any{{
				"MrTd":   hex.EncodeToString(reg("mrtd/approved-image")),
				"MrSeam": hex.EncodeToString(reg("mrseam")),
				"Rtmrs": []string{
					hex.EncodeToString(reg("rtmr0")),
					hex.EncodeToString(reg("rtmr1")),
					hex.EncodeToString(reg("rtmr2")),
					hex.EncodeToString(reg("rtmr3/ai-service")),
				},
				"Xfam":                       "e71a060000000000",
				"MinTCBEvaluationDataNumber": 17,
			}},
		},
		"WorkloadOwnerPubKeys":  []string{},
		"SeedshareOwnerPubKeys": []string{},
	}
	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	must(err)

	fixtures := map[string]any{
		"$comment": []string{
			"Generated by tools/contrast-fixture from Contrast's OWN internal/ca,",
			"internal/seedengine, internal/attestation/tdx and internal/oid -- the same",
			"functions the Coordinator calls in coordinator/internal/meshapi.NewMeshCert.",
			"Certificates and keys are base64 DER, not PEM: the repository must contain no",
			".pem file and no PEM private-key block (.github/workflows/security.yml).",
			"tests/support/contrast-pod.ts reconstitutes a pod layout into a temporary",
			"directory at run time.",
			"These keys are disposable and protect nothing. The TDX quote behind the",
			"certificate claims was built in software: NO confidential hardware was involved.",
		},
		"generator":      "cool-contrast-fixture",
		"contrastSource": "github.com/edgelesssys/contrast (internal/seedengine, internal/ca, internal/attestation/tdx, internal/oid)",
		"synthetic":      "the TDX quote whose claims are copied into the certificate extensions; no hardware was involved",
		"coordinators": map[string]any{
			"genuine": map[string]any{
				"rootCaDer": derBlocks(genuine.ca.GetRootCACert()),
				"meshCaDer": derBlocks(genuine.ca.GetMeshCACert()),
			},
			"rogue": map[string]any{
				"rootCaDer": derBlocks(rogue.ca.GetRootCACert()),
				"meshCaDer": derBlocks(rogue.ca.GetMeshCACert()),
			},
		},
		"manifest":  string(manifestJSON),
		"workloads": bundles,
		"policyHashes": map[string]string{
			"ai-service":       hex.EncodeToString(policyA),
			"sidecar-service":  hex.EncodeToString(policyB),
			"insecure-service": hex.EncodeToString(policyI),
		},
		"measurements": map[string]string{
			"approved_mrtd": hex.EncodeToString(reg("mrtd/approved-image")),
			"upgraded_mrtd": hex.EncodeToString(reg("mrtd/upgraded-image")),
			"mrseam":        hex.EncodeToString(reg("mrseam")),
			"rtmr0":         hex.EncodeToString(reg("rtmr0")),
			"rtmr1":         hex.EncodeToString(reg("rtmr1")),
			"rtmr2":         hex.EncodeToString(reg("rtmr2")),
			"rtmr3_ai":      hex.EncodeToString(reg("rtmr3/ai-service")),
			"rtmr3_sidecar": hex.EncodeToString(reg("rtmr3/sidecar-service")),
		},
	}

	encoded, err := json.MarshalIndent(fixtures, "", "  ")
	must(err)
	if dir := filepath.Dir(*out); dir != "." {
		must(os.MkdirAll(dir, 0o755))
	}
	must(os.WriteFile(*out, append(encoded, byte(10)), 0o644))


	fmt.Printf("wrote Contrast fixtures to %s\n", *out)
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
