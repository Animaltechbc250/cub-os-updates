# Cub component updates

Small signed fixes between monthly ISO releases, without reinstalling Cub OS.

## Install an update

On a Cub system with the component updater provisioned, open **Cub Control
Center → Updates & alerts → Open small updates**. Select **Check for updates**,
read the release notes, then select **Install update**. Download, verification,
installation and written-file checks run automatically. No reboot is forced.

The component updater must already be provisioned by a trusted installation.
Publishing this channel does not add its client to older Cub installations.

## Trust and rollback

The client verifies the installation's pinned Ed25519 publisher key. Packages
declare exact file paths, starting hashes, new hashes, sizes and modes. It
refuses unapproved paths, unexpected installed files and invalid signatures.
Packages cannot supply arbitrary post-install commands. Starting files are
backed up before replacement and retained for rollback.

Select **Roll back last update** to restore the previous component files.
Locally edited files or corrupt backups are held for inspection instead of
being overwritten. A rolled-back package ID is retained; reinstalling that
change requires a new publisher-issued package ID. This is file rollback, not
a guarantee against every hardware failure or loss of power.

## First trial: HelixSR 3.2.0

This optional prerelease trial installs the complete official HelixSR 3.2.0 ZIP,
a desktop-user setup launcher and explanatory notes. The archive downloads
directly from the author's GitHub release and is checked against its pinned
size and SHA256. It includes prebuilt HLX FSR4 shaders based on AMD's FSR SDK
2.4.0 / FSR 4.1.2. No performance improvement or game compatibility is claimed
by the update-delivery checks.

Existing Proton payloads, game files and launch options are not changed by
this package. After installation, reopen Control Center and use **FSR & Proton
→ Open HelixSR setup** only for a game you choose. Do not stack another injector
over an existing Decky/Proton setup. Game modifications made through the separate
official setup require its own uninstall/backup; Cub component rollback only
removes the files added by this package.

No kernel, Mesa, firmware, VCN or hardware-setting changes are part of this
trial. Checking for updates does not need administrator authentication;
installation uses the trusted client's narrow authorization policy.

The client has passed native Linux signature, install, rollback, corruption,
path, lock and interrupted-process tests, a real signed-payload HTTPS download
and rollback fixture, and Qt notes/button checks. User acceptance of the actual
Control Center installation and per-game setup remains separate.

Upstream release: https://github.com/lonewolf0622/HelixSR/releases/tag/v3.2.0

Private signing keys and machine data are not part of this repository.

