package cmd

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/BurntSushi/toml"
	"github.com/spf13/cobra"
	"github.com/mfycheng/lp-aws-saml/lastpassaws"
	cookiejar "github.com/vinhjaxt/persistent-cookiejar"
	"golang.org/x/crypto/ssh/terminal"
)

type config struct {
	Username     string `toml:"username"`
	SAMLConfigID string `toml:"saml_config_id"`
	SAMLGUUID    string `toml:"saml_guuid"`
	Profile      string `toml:"profile_name"`
	Duration     int    `toml:"duration"`
	Quiet        bool   `toml:"bool"`
}

var (
	quiet      bool
	configPath string
)

func getCanonicalPath(path string) string {
	usr, _ := user.Current()
	if path == "~" {
		return usr.HomeDir
	}
	if strings.HasPrefix(path, "~/") {
		return filepath.Join(usr.HomeDir, path[2:])
	}

	return path
}
func getConfig(profile string) (config, error) {
	m := make(map[string]config)
	if _, err := toml.DecodeFile(getCanonicalPath(configPath), &m); err != nil {
		return config{}, err
	}

	if _, ok := m[profile]; !ok {
		return config{}, errors.New("profile not configured")
	}

	return m[profile], nil
}

var rootCmd = &cobra.Command{
	Use:   "lp-aws-saml",
	Short: "Temporary Credentials for AWS CLI for LastPass SAML login",
	Long:  "Get temporary AWS credentials when using LastPass as a SAML login for AWS",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		conf, err := getConfig(args[0])
		if err != nil {
			return err
		}

		if !quiet {
			log.Println("Logging in with: ", conf.Username)
		}

		options := cookiejar.Options{
			Filename: fmt.Sprintf("%s/.aws/lp_cookies", lastpassaws.HomeDir()),
		}
		jar, _ := cookiejar.New(&options)
		session := &http.Client{
			Jar: jar,
		}

		var assertion string
		// Attempt to use stored cookies
		for {
			assertion, err = lastpassaws.SamlToken(session, conf.Username, conf.SAMLConfigID, conf.SAMLGUUID)
			if err != nil {
				log.Fatalf("Can't get the saml: %s", err)
			}
			if assertion != "" {
				break
			}
			log.Println("Don't have session, trying to log in")

			fmt.Print("Lastpass Password: ")
			bytePassword, _ := terminal.ReadPassword(int(syscall.Stdin))
			fmt.Println()
			fmt.Print("Lastpass OTP: ")
			byteOtp, _ := terminal.ReadPassword(int(syscall.Stdin))
			fmt.Println()

			password := string(bytePassword)
			otp := string(byteOtp)

			if err := lastpassaws.Login(session, conf.Username, password, otp); err != nil {
				log.Printf("Invalid Credentials: %s", err)
			} else {
				jar.Save()
			}

		}

		roles := lastpassaws.SamlRoles(assertion)
		if len(roles) == 0 {
			return fmt.Errorf("No roles available for %s!\n", conf.Username)
		}
		role := lastpassaws.PromptForRole(roles)

		response, err := lastpassaws.AssumeAWSRole(assertion, role[0], role[1], conf.Duration)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		lastpassaws.SetAWSProfile(conf.Profile, response)

		if !quiet {
			fmt.Printf("A new AWS CLI profile '%s' has been added.\n", conf.Profile)
			fmt.Println("You may now invoke the aws CLI tool as follows:")
			fmt.Println()
			fmt.Printf("    aws --profile %s [...] \n", conf.Profile)
			fmt.Println()
			fmt.Printf("This token expires in %.2d hours.\n", (conf.Duration / 60 / 60))
		}

		return nil
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute(version string) {
	rootCmd.Version = version
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().BoolVar(&quiet, "quiet", true, "Don't output debug info")
	rootCmd.Flags().StringVar(&configPath, "config", "~/.aws/lp_config.toml", "Config path")
}
