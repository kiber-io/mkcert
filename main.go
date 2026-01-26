// Copyright 2018 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Command mkcert is a simple zero-config tool to make development certificates.
package main

import (
	"crypto"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net"
	"net/mail"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"

	"golang.org/x/net/idna"
)

const shortUsage = `Usage of mkcert:

	$ mkcert -install
	Install the local CA in the system trust store.

	$ mkcert -generate-ca
	Generate the local CA without installing it.

	$ mkcert example.org
	Generate "example.org.pem" and "example.org-key.pem".

	$ mkcert example.com myapp.dev localhost 127.0.0.1 ::1
	Generate "example.com+4.pem" and "example.com+4-key.pem".

	$ mkcert "*.example.it"
	Generate "_wildcard.example.it.pem" and "_wildcard.example.it-key.pem".

	$ mkcert -uninstall
	Uninstall the local CA (but do not delete it).

`

const advancedUsage = `Advanced options:

	-cert-file FILE, -key-file FILE, -p12-file FILE
	    Customize the output paths.

	-out-dir DIR
	    Customize the output directory for generated certificates.

	-cert-file-name NAME, -key-file-name NAME, -p12-file-name NAME
	    Customize output filenames. Requires -out-dir.

	-client
	    Generate a certificate for client authentication.

	-ecdsa
	    Generate a certificate with an ECDSA key.

	-pkcs12
	    Generate a ".p12" PKCS #12 file, also know as a ".pfx" file,
	    containing certificate and key for legacy applications.

	-cert-validity-days N
	    Customize the leaf certificate validity period in days.

	-config FILE
	    Load configuration from the specified TOML file. Defaults to
	    "mkcert.toml" in the executable directory.

	-csr CSR
	    Generate a certificate based on the supplied CSR. Conflicts with
	    all other flags and arguments except -install and -cert-file.

	-ca-organization NAME
	    Customize the root CA certificate Organization
	    when creating a new local CA.

	-ca-common-name NAME
	    Customize the root CA certificate Common Name.

	-ca-common-name NAME
	    Customize the root CA certificate Common Name.

	-ca-validity-years N
	    Customize the root CA certificate validity period in years.
	    Only applies when creating a new local CA.

	-ca-org-unit NAME
	    Customize the root CA certificate Organizational Unit.
	    Only applies when creating a new local CA.

	-generate-ca
	    Generate a new local CA without installing it.

	-cert-org NAME
	    Customize the leaf certificate Organization field.

	-cert-org-unit NAME
	    Customize the leaf certificate Organizational Unit field.

	$TRUST_STORES (environment variable)
	    A comma-separated list of trust stores to install the local
	    root CA into. Options are: "system", "java" and "nss" (includes
	    Firefox). Autodetected by default.

`

// Version can be set at link time to override debug.BuildInfo.Main.Version,
// which is "(devel)" when building from within the module. See
// golang.org/issue/29814 and golang.org/issue/29228.
var Version string

func main() {
	if len(os.Args) == 1 {
		fmt.Print(shortUsage)
		return
	}
	log.SetFlags(0)
	var (
		installFlag   = flag.Bool("install", false, "")
		uninstallFlag = flag.Bool("uninstall", false, "")
		pkcs12Flag    = flag.Bool("pkcs12", false, "")
		ecdsaFlag     = flag.Bool("ecdsa", false, "")
		clientFlag    = flag.Bool("client", false, "")
		helpFlag      = flag.Bool("help", false, "")
		csrFlag       = flag.String("csr", "", "")
		certFileFlag  = flag.String("cert-file", "", "")
		keyFileFlag   = flag.String("key-file", "", "")
		p12FileFlag   = flag.String("p12-file", "", "")
		outDirFlag    = flag.String("out-dir", "", "")
		certNameFlag  = flag.String("cert-file-name", "", "")
		keyNameFlag   = flag.String("key-file-name", "", "")
		p12NameFlag   = flag.String("p12-file-name", "", "")
		// Android enforces a 398-day maximum for leaf cert validity.
		// See https://cs.android.com/android/platform/superproject/main/+/main:external/cronet/tot/net/cert/cert_verify_proc.cc;l=827;drc=61197364367c9e404c7da6900658f1b16c42d0da
		certDaysFlag  = flag.Int("cert-validity-days", 398, "")
		configFlag    = flag.String("config", "mkcert.toml", "")
		caNameFlag    = flag.String("ca-organization", "", "")
		caCommonNameFlag = flag.String("ca-common-name", "", "")
		caYearsFlag   = flag.Int("ca-validity-years", 10, "")
		caOrgUnitFlag = flag.String("ca-org-unit", "", "")
		genCAFlag     = flag.Bool("generate-ca", false, "")
		certOrgFlag   = flag.String("cert-org", "", "")
		certOUFlag    = flag.String("cert-org-unit", "", "")
		versionFlag   = flag.Bool("version", false, "")
	)
	flag.Usage = func() {
		fmt.Fprint(flag.CommandLine.Output(), shortUsage)
		fmt.Fprintln(flag.CommandLine.Output(), `For more options, run "mkcert -help".`)
	}
	flag.Parse()
	if *helpFlag {
		fmt.Print(shortUsage)
		fmt.Print(advancedUsage)
		return
	}
	if *versionFlag {
		if Version != "" {
			fmt.Println(Version)
			return
		}
		if buildInfo, ok := debug.ReadBuildInfo(); ok {
			fmt.Println(buildInfo.Main.Version)
			return
		}
		fmt.Println("(unknown)")
		return
	}
	if *installFlag && *uninstallFlag {
		log.Fatalln("ERROR: you can't set -install and -uninstall at the same time")
	}
	if *csrFlag != "" && (*pkcs12Flag || *ecdsaFlag || *clientFlag) {
		log.Fatalln("ERROR: can only combine -csr with -install and -cert-file")
	}
	if *csrFlag != "" && flag.NArg() != 0 {
		log.Fatalln("ERROR: can't specify extra arguments when using -csr")
	}
	if (*certNameFlag != "" || *keyNameFlag != "" || *p12NameFlag != "") && *outDirFlag == "" {
		log.Fatalln("ERROR: -cert-file-name, -key-file-name, and -p12-file-name require -out-dir")
	}
	if *certFileFlag != "" && *certNameFlag != "" {
		log.Fatalln("ERROR: can't combine -cert-file and -cert-file-name")
	}
	if *keyFileFlag != "" && *keyNameFlag != "" {
		log.Fatalln("ERROR: can't combine -key-file and -key-file-name")
	}
	if *p12FileFlag != "" && *p12NameFlag != "" {
		log.Fatalln("ERROR: can't combine -p12-file and -p12-file-name")
	}
	if *genCAFlag && (*installFlag || *uninstallFlag || *csrFlag != "" || flag.NArg() != 0) {
		log.Fatalln("ERROR: -generate-ca can't be combined with other actions or arguments")
	}
	if err := initConfig(*configFlag); err != nil {
		log.Fatalf("ERROR: failed to load config: %s", err)
	}

	setFlags := map[string]bool{}
	flag.CommandLine.Visit(func(f *flag.Flag) {
		setFlags[f.Name] = true
	})
	cfg := getConfig()
	if cfg == nil {
		cfg = &config{}
	}

	certDays := *certDaysFlag
	leafServerDays := 0
	leafClientDays := 0
	if !setFlags["cert-validity-days"] {
		if cfg.Leaf.Server.ValidityDays > 0 {
			leafServerDays = cfg.Leaf.Server.ValidityDays
		}
		if cfg.Leaf.Client.ValidityDays > 0 {
			leafClientDays = cfg.Leaf.Client.ValidityDays
		}
		if cfg.Leaf.ValidityDays > 0 {
			if leafServerDays == 0 {
				leafServerDays = cfg.Leaf.ValidityDays
			}
			if leafClientDays == 0 {
				leafClientDays = cfg.Leaf.ValidityDays
			}
		}
	}
	if certDays <= 0 {
		log.Fatalln("ERROR: cert-validity-days must be a positive integer")
	}

	caYears := *caYearsFlag
	caDays := 0
	caDaysSet := false
	caYearsSet := false
	if !setFlags["ca-validity-years"] {
		if cfg.CA.ValidityDays > 0 {
			caDays = cfg.CA.ValidityDays
			caDaysSet = true
		} else if cfg.CA.ValidityYears > 0 {
			caYears = cfg.CA.ValidityYears
			caYearsSet = true
		}
	}
	if caDaysSet && caDays <= 0 {
		log.Fatalln("ERROR: ca.validity-days must be a positive integer")
	}
	if caYearsSet && caYears <= 0 {
		log.Fatalln("ERROR: ca-validity-years must be a positive integer")
	}
	if caDays <= 0 && caYears <= 0 {
		log.Fatalln("ERROR: ca-validity-years must be a positive integer")
	}

	caName := *caNameFlag
	if !setFlags["ca-organization"] {
		if cfg.CA.Name != "" {
			caName = cfg.CA.Name
		}
	}
	caCommonName := *caCommonNameFlag
	if !setFlags["ca-common-name"] {
		if cfg.CA.CommonName != "" {
			caCommonName = cfg.CA.CommonName
		}
	}
	caOrgUnit := *caOrgUnitFlag
	if !setFlags["ca-org-unit"] {
		if cfg.CA.OrgUnit != "" {
			caOrgUnit = cfg.CA.OrgUnit
		}
	}
	certOrg := *certOrgFlag
	if !setFlags["cert-org"] {
		if cfg.Leaf.Org != "" {
			certOrg = cfg.Leaf.Org
		}
	}
	certOrgUnit := *certOUFlag
	if !setFlags["cert-org-unit"] {
		if cfg.Leaf.OrgUnit != "" {
			certOrgUnit = cfg.Leaf.OrgUnit
		}
	}

	var leafServerKeyUsage x509.KeyUsage
	var leafClientKeyUsage x509.KeyUsage
	leafServerKeyUsageSet := false
	leafClientKeyUsageSet := false
	if len(cfg.Leaf.Server.KeyUsage) > 0 {
		ku, err := parseKeyUsage(cfg.Leaf.Server.KeyUsage)
		if err != nil {
			log.Fatalf("ERROR: invalid leaf.server.key_usage in config: %s", err)
		}
		leafServerKeyUsage = ku
		leafServerKeyUsageSet = true
	}
	if len(cfg.Leaf.Client.KeyUsage) > 0 {
		ku, err := parseKeyUsage(cfg.Leaf.Client.KeyUsage)
		if err != nil {
			log.Fatalf("ERROR: invalid leaf.client.key_usage in config: %s", err)
		}
		leafClientKeyUsage = ku
		leafClientKeyUsageSet = true
	}

	(&mkcert{
		installMode: *installFlag, uninstallMode: *uninstallFlag, csrPath: *csrFlag,
		pkcs12: *pkcs12Flag, ecdsa: *ecdsaFlag, client: *clientFlag,
		certFile: *certFileFlag, keyFile: *keyFileFlag, p12File: *p12FileFlag,
		outDir:       *outDirFlag,
		certFileName: *certNameFlag, keyFileName: *keyNameFlag, p12FileName: *p12NameFlag,
		certValidityDays:       certDays,
		caName:                 caName,
		caCommonName:           caCommonName,
		caOrgUnit:              caOrgUnit,
		caValidityDays:         caDays,
		certOrg:                certOrg,
		certOrgUnit:            certOrgUnit,
		leafServerValidityDays: leafServerDays,
		leafClientValidityDays: leafClientDays,
		leafServerKeyUsage:     leafServerKeyUsage,
		leafServerKeyUsageSet:  leafServerKeyUsageSet,
		leafClientKeyUsage:     leafClientKeyUsage,
		leafClientKeyUsageSet:  leafClientKeyUsageSet,
		generateCA:             *genCAFlag,
	}).Run(flag.Args())
}

const rootName = "rootCA.pem"
const rootKeyName = "rootCA-key.pem"

type mkcert struct {
	installMode, uninstallMode bool
	pkcs12, ecdsa, client      bool
	keyFile, certFile, p12File string
	outDir                     string
	certFileName               string
	keyFileName                string
	p12FileName                string
	certValidityDays           int
	leafServerValidityDays     int
	leafClientValidityDays     int
	leafServerKeyUsage         x509.KeyUsage
	leafServerKeyUsageSet      bool
	leafClientKeyUsage         x509.KeyUsage
	leafClientKeyUsageSet      bool
	csrPath                    string
	caName                     string
	caCommonName               string
	caOrgUnit                  string
	caValidityDays             int
	certOrg                    string
	certOrgUnit                string
	generateCA                 bool

	CAROOT string
	caCert *x509.Certificate
	caKey  crypto.PrivateKey

	// The system cert pool is only loaded once. After installing the root, checks
	// will keep failing until the next execution. TODO: maybe execve?
	// https://github.com/golang/go/issues/24540 (thanks, myself)
	ignoreCheckFailure bool
}

func (m *mkcert) Run(args []string) {
	m.CAROOT = getCAROOT()
	if m.CAROOT == "" {
		log.Fatalln("ERROR: failed to find the default CA location, set one as the CAROOT env var")
	}
	fatalIfErr(os.MkdirAll(m.CAROOT, 0755), "failed to create the CAROOT")

	if m.generateCA {
		if pathExists(filepath.Join(m.CAROOT, rootName)) || pathExists(filepath.Join(m.CAROOT, rootKeyName)) {
			log.Fatalln("ERROR: local CA already exists; remove it or set CAROOT to a new location")
		}
		m.newCA()
		return
	}

	m.loadCA()

	if m.installMode {
		m.install()
		if len(args) == 0 {
			return
		}
	} else if m.uninstallMode {
		m.uninstall()
		return
	} else {
		var warning bool
		if storeEnabled("system") && !m.checkPlatform() {
			warning = true
			log.Println("Note: the local CA is not installed in the system trust store.")
		}
		if storeEnabled("nss") && hasNSS && CertutilInstallHelp != "" && !m.checkNSS() {
			warning = true
			log.Printf("Note: the local CA is not installed in the %s trust store.", NSSBrowsers)
		}
		if storeEnabled("java") && hasJava && !m.checkJava() {
			warning = true
			log.Println("Note: the local CA is not installed in the Java trust store.")
		}
		if warning {
			log.Println("Run \"mkcert -install\" for certificates to be trusted automatically ⚠️")
		}
	}

	if m.csrPath != "" {
		m.makeCertFromCSR()
		return
	}

	if len(args) == 0 {
		flag.Usage()
		return
	}

	hostnameRegexp := regexp.MustCompile(`(?i)^(\*\.)?[0-9a-z_-]([0-9a-z._-]*[0-9a-z_-])?$`)
	for i, name := range args {
		if ip := net.ParseIP(name); ip != nil {
			continue
		}
		if email, err := mail.ParseAddress(name); err == nil && email.Address == name {
			continue
		}
		if uriName, err := url.Parse(name); err == nil && uriName.Scheme != "" && uriName.Host != "" {
			continue
		}
		punycode, err := idna.ToASCII(name)
		if err != nil {
			log.Fatalf("ERROR: %q is not a valid hostname, IP, URL or email: %s", name, err)
		}
		args[i] = punycode
		if !hostnameRegexp.MatchString(punycode) {
			log.Fatalf("ERROR: %q is not a valid hostname, IP, URL or email", name)
		}
	}

	m.makeCert(args)
}

func getCAROOT() string {
	if cfg := getConfig(); cfg != nil {
		if cfg.Paths.CAROOT != "" {
			return cfg.Paths.CAROOT
		}
	}

	var dir string
	switch {
	case runtime.GOOS == "windows":
		dir = os.Getenv("LocalAppData")
	case os.Getenv("XDG_DATA_HOME") != "":
		dir = os.Getenv("XDG_DATA_HOME")
	case runtime.GOOS == "darwin":
		dir = os.Getenv("HOME")
		if dir == "" {
			return ""
		}
		dir = filepath.Join(dir, "Library", "Application Support")
	default: // Unix
		dir = os.Getenv("HOME")
		if dir == "" {
			return ""
		}
		dir = filepath.Join(dir, ".local", "share")
	}
	return filepath.Join(dir, "mkcert")
}

func (m *mkcert) install() {
	if storeEnabled("system") {
		if m.checkPlatform() {
			log.Print("The local CA is already installed in the system trust store! 👍")
		} else {
			if m.installPlatform() {
				log.Print("The local CA is now installed in the system trust store! ⚡️")
			}
			m.ignoreCheckFailure = true // TODO: replace with a check for a successful install
		}
	}
	if storeEnabled("nss") && hasNSS {
		if m.checkNSS() {
			log.Printf("The local CA is already installed in the %s trust store! 👍", NSSBrowsers)
		} else {
			if hasCertutil && m.installNSS() {
				log.Printf("The local CA is now installed in the %s trust store (requires browser restart)! 🦊", NSSBrowsers)
			} else if CertutilInstallHelp == "" {
				log.Printf(`Note: %s support is not available on your platform. ℹ️`, NSSBrowsers)
			} else if !hasCertutil {
				log.Printf(`Warning: "certutil" is not available, so the CA can't be automatically installed in %s! ⚠️`, NSSBrowsers)
				log.Printf(`Install "certutil" with "%s" and re-run "mkcert -install" 👈`, CertutilInstallHelp)
			}
		}
	}
	if storeEnabled("java") && hasJava {
		if m.checkJava() {
			log.Println("The local CA is already installed in Java's trust store! 👍")
		} else {
			if hasKeytool {
				m.installJava()
				log.Println("The local CA is now installed in Java's trust store! ☕️")
			} else {
				log.Println(`Warning: "keytool" is not available, so the CA can't be automatically installed in Java's trust store! ⚠️`)
			}
		}
	}
	log.Print("")
}

func (m *mkcert) uninstall() {
	if storeEnabled("nss") && hasNSS {
		if hasCertutil {
			m.uninstallNSS()
		} else if CertutilInstallHelp != "" {
			log.Print("")
			log.Printf(`Warning: "certutil" is not available, so the CA can't be automatically uninstalled from %s (if it was ever installed)! ⚠️`, NSSBrowsers)
			log.Printf(`You can install "certutil" with "%s" and re-run "mkcert -uninstall" 👈`, CertutilInstallHelp)
			log.Print("")
		}
	}
	if storeEnabled("java") && hasJava {
		if hasKeytool {
			m.uninstallJava()
		} else {
			log.Print("")
			log.Println(`Warning: "keytool" is not available, so the CA can't be automatically uninstalled from Java's trust store (if it was ever installed)! ⚠️`)
			log.Print("")
		}
	}
	if storeEnabled("system") && m.uninstallPlatform() {
		log.Print("The local CA is now uninstalled from the system trust store(s)! 👋")
		log.Print("")
	} else if storeEnabled("nss") && hasCertutil {
		log.Printf("The local CA is now uninstalled from the %s trust store(s)! 👋", NSSBrowsers)
		log.Print("")
	}
}

func (m *mkcert) checkPlatform() bool {
	if m.ignoreCheckFailure {
		return true
	}

	_, err := m.caCert.Verify(x509.VerifyOptions{})
	return err == nil
}

func storeEnabled(name string) bool {
	stores := os.Getenv("TRUST_STORES")
	if stores == "" {
		return true
	}
	for _, store := range strings.Split(stores, ",") {
		if store == name {
			return true
		}
	}
	return false
}

func fatalIfErr(err error, msg string) {
	if err != nil {
		log.Fatalf("ERROR: %s: %s", msg, err)
	}
}

func fatalIfCmdErr(err error, cmd string, out []byte) {
	if err != nil {
		log.Fatalf("ERROR: failed to execute \"%s\": %s\n\n%s\n", cmd, err, out)
	}
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func binaryExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

var sudoWarningOnce sync.Once

func commandWithSudo(cmd ...string) *exec.Cmd {
	if u, err := user.Current(); err == nil && u.Uid == "0" {
		return exec.Command(cmd[0], cmd[1:]...)
	}
	if !binaryExists("sudo") {
		sudoWarningOnce.Do(func() {
			log.Println(`Warning: "sudo" is not available, and mkcert is not running as root. The (un)install operation might fail. ⚠️`)
		})
		return exec.Command(cmd[0], cmd[1:]...)
	}
	return exec.Command("sudo", append([]string{"--prompt=Sudo password:", "--"}, cmd...)...)
}
