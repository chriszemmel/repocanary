# You ran a repository you now think was malicious. Here is what to do.

Read this even if you never ran a scan. If you cloned and ran a stranger's
repository, especially as part of a "job interview", and something feels
wrong, work through these steps in order. The order matters, and the reasons
are given so you can adapt when a step does not fit your situation. Do not
freeze, and do not waste time confirming whether it was "really" malware:
act as if it was, then find out.

## 1. Disconnect the machine from the internet. Now, before anything else.

Turn off Wi-Fi and unplug the network cable. Do it before you investigate,
before you back anything up, before you finish reading this.

Why first: this kind of malware works by sending your stolen data out and by
letting the attacker reach back in. Every second you stay connected, more can
leave and more commands can arrive. Cutting the network stops the bleeding
immediately, even though it does not remove the infection.

## 2. From a DIFFERENT, trusted device, move any crypto funds.

Use your phone or another computer that never touched the repository. If you
hold cryptocurrency, move it to a new wallet whose seed phrase has never been
on the infected machine.

Why second, and why a different device: crypto theft is irreversible. Once
funds move, no one can claw them back, so this is the highest-stakes loss and
it comes right after stopping the leak. You use another device because the
infected one may be watching your screen and keystrokes; typing a seed phrase
into it hands the attacker the new wallet too.

## 3. From that trusted device, revoke tokens and rotate keys.

Sign out and revoke active sessions, then rotate credentials, roughly in the
order an attacker monetizes them:

- Cloud provider keys (AWS, GCP, Azure) and any that were in your environment
  or `.env` files: revoke and reissue. These can run up huge bills and reach
  far beyond your laptop.
- Personal access tokens and SSH keys (GitHub, GitLab, npm): revoke on the
  provider's site and generate new ones. Assume anything in `~/.ssh` and
  `~/.npmrc` is compromised.
- API keys for any paid service.

Why before passwords: tokens and keys often are not protected by your
password and give direct access to money and infrastructure. They are the
fastest path to real damage, so close them first.

## 4. Rotate passwords, email first.

From the trusted device, change your passwords. Start with the email account
that receives your password resets, then move to financial accounts, then
everything important. Turn on two-factor authentication everywhere it is
offered, using an authenticator app rather than SMS.

Why email first: whoever controls your email can reset the password on
everything else. Securing it first stops the attacker from undoing the rest
of your work as you do it. If your browser stored passwords, treat every one
of them as exposed; this malware specifically reads the browser's saved
passwords.

## 5. Tell your employer or school, if a work or school machine was involved.

Contact your IT or security team and tell them plainly what happened. Do not
hide it out of embarrassment.

Why now, not later: if this device can reach a company network, the incident
is bigger than you, and their tools can contain it in ways yours cannot.
Reporting early makes you the person who caught it, not the person who hid
it. These attacks fool experienced engineers; being targeted is not a
failing.

## 6. Rebuild the machine. Do not trust a cleanup.

Back up only your personal documents (photos, papers, plain data), never
applications, scripts, or system files, to external media. Then wipe the disk
and reinstall the operating system from scratch. Change your passwords a
final time afterward from the freshly rebuilt machine.

Why a full wipe: this malware installs persistence, footholds designed to
survive a reboot and reinstall themselves. Antivirus removal and "cleaning"
cannot be trusted to catch all of it. The only way to be sure the machine is
yours again is to start over.

## 7. Report it, so the next person is warned.

- Report the repository to GitHub: https://github.com/contact/report-abuse
- Report the "recruiter" on the platform where they reached you (LinkedIn,
  Telegram, Discord, email provider).
- In the United States, report to the FBI's IC3 at https://www.ic3.gov.
  Elsewhere, report to your national cybercrime unit.

Why last but not skipped: reporting does not help your machine, which is why
it comes after you have secured yourself. It helps everyone the same
operation targets next, and it feeds the takedowns and advisories that make
tools like this one possible.

---

If you have not run anything yet and you are reading this to prepare: good.
Scan the repository first (`npx repocanary owner/repo`), read the code
yourself, and run anything unfamiliar inside a throwaway virtual machine that
holds none of your passwords, keys, or wallets. The safest interview task is
one you review without ever running.
