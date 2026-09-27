// Installation steps the settings page shows in a copy-to-clipboard box.
// Nothing in this file runs a command; the strings are displayed to the user.
export const steps = [
  {
    title: "Install the CLI",
    detail: "On macOS or Linux run the installer, then sign in.",
    code: `curl -fsSL https://cli.example.com/install.sh | bash
example-cli login`,
  },
  {
    title: "Check it worked",
    code: "example-cli integrations:list",
  },
];
