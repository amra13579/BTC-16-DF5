# DF-5 evidence — `files/evidence/`

Small, self-contained lab artifacts for BTCMP-16 Module 5 (case **AF-2026-0817**,
fictional **Ashcombe Freight Ltd**). Analysed on **one Windows 10 VM** with the LMS tools
natively. Provisioned **directly** (total ~4.6 MB — no GitHub Releases needed). Produced
by the build-time harness in `../../../generation/`.

| File | Size | Used by | Contains |
|---|---|---|---|
| `evidence/df5.1-hives/NTUSER.DAT` | 12 KB | DF-5.1 | HKCU `Run` (`WinDefendUpd`) + `RunMRU` |
| `evidence/df5.1-hives/SOFTWARE` | 12 KB | DF-5.1 | HKLM `Run` baseline |
| `evidence/df5.1-hives/SYSTEM` | 12 KB | DF-5.1 | USBSTOR history (S/N `AF14X99204F0`) |
| `evidence/df5.1-hives/SAM` | 12 KB | DF-5.1 | account skeleton (completeness) |
| `evidence/df5.2-af-billing.img.gz` | ~3.5 MB | DF-5.2 | **real Alpine** ext4 image → gunzipped to 128 MiB; `/var/log/messages` + OpenRC persistence service `af-telemetry` |
| `evidence/df5.3-usb1.E01` | ~520 KB | DF-5.3 | USB#1: `autorun.inf` + base64 VBS implant (`sys\svchost.vbs`) |
| `evidence/df5.4-usb2.E01` | ~520 KB | DF-5.4 | USB#2: `autorun.inf` + **deleted** hex JS implant (`winupd.js`) |
| `evidence/SHA256SUMS.txt` | — | all | chain-of-custody hashes |

The playbook stages these read-only to `C:\Cases\DF5\` and decompresses the ext4 image.

## Answers (see `../../solution-writeup.md` for the full derivation)
- 5.1 Run value: `WinDefendUpd` · USB serial: `AF14X99204F0`
- 5.2 attacker IP (logs): `203.0.113.66` · persistence service: `af-telemetry`
- 5.3 flag (base64 implant): `CTF{4ut0run_vbs_dr0pp3r}`
- 5.4 flag (deleted hex implant): `CTF{d3l3t3d_h3x_1mpl4nt}`

Machine-verified at the evidence/decoding level by the harness
(`../../testing/verification.log`); the Windows GUI paths are **⚠ verify** on the VM.

## The USB "implants" — guardrail note
Both implants are **inert, obfuscated analysis artifacts**, not working malware:
- USB#1 `sys\svchost.vbs` — a VBScript wrapper around a **base64** blob that decodes to an
  illustrative PowerShell dropper (sets the `WinDefendUpd` Run key, beacons to the dead
  C2 `203.0.113.66`).
- USB#2 `winupd.js` (deleted) — a JScript wrapper around a **hex** blob decoding to a
  `schtasks`+`bitsadmin` string pointing at the dead exfil host `198.51.100.23`.
The sticks are only **imaged and examined offline**; nothing executes, all IPs are
RFC-5737 doc ranges, and no exploit/self-replication/evasion code is present (consistent
with the "don't author novel malware" guardrail — these are evidence to analyse, like the
DF-13.3 maldoc).

## Range integrity
Offline-analysis range: all evidence is handed to the trainee, so nothing is "hidden".
Each USB flag sits behind the **intended tool path** (FTK Imager export+decode for #1;
Autopsy deleted-file recovery+decode for #2) but is also reachable by other means
(`strings`, raw carving) — acceptable for training; the two flags are distinct so each
level checks the right technique.

## Notes / SME confirmation (FIRST Windows CR)
- **Most tooling is auto-installed by the playbook over WinRM via DIRECT downloads**
  (Autopsy from its GitHub Release `.msi`, DiskInternals Linux Reader + RegRipper +
  Registry Explorer from vendor/GitHub, 7-Zip + .NET via chocolatey) — the repo hosts no
  installers, so there is no redistribution question. Confirm the pinned versions/URLs and
  provision-time internet egress on the instance (⚠ in `../playbook.yml`).
- **FTK Imager 8.3.0.27 IS provisioned** (same direct-download pattern as the rest). The
  Download button on Exterro's FTK Imager page links straight to the installer on their
  CDN — no registration, no account: verified 2026-09-07 from a clean client (HTTP 200, no
  form/cookie/referer, 405,808,295 bytes, sha256 matching the vendor's own
  `x-amz-meta-checksum-sha256`). The URL + sha256 are pinned in `../playbook.yml`; the repo
  hosts nothing, so redistribution does not arise. **⚠ SME:** the interactive install
  prompts for the CodeMeter runtime, Bonjour (Apple device support) and a Defender
  exclusion — confirm the silent switches absorb all three on the VM (see the ⚠ block in
  the playbook). Provision-time egress must reach `d1kpmuwb7gvu1i.cloudfront.net`, and the
  download is ~387 MB.
- **Defender exclusions + working directory.** The playbook creates `C:\Cases\DF5\Export`
  as the trainee's working directory and excludes the FTK install dir and `C:\Cases\DF5`
  (which covers `Export\`). This is load-bearing: DF-5.3/5.4 have the trainee export the
  obfuscated `.vbs` / carved `.js` implants out of the E01s onto disk, where Defender would
  otherwise quarantine them and make the levels unsolvable. Real-time protection stays ON
  elsewhere; the exclusion is applied before evidence is copied in. The training text,
  handout and the on-VM `READ_ME_FIRST.txt` all tell the trainee to work from `Export\`.
  ⚠ Confirm this fits your range hardening policy, and dry-run the export of both implants
  before the range goes live.
- DF-5.2 uses an ext-browser (**Linux Reader**), not FTK Imager.
- Confirm the **Windows base image name, WinRM mgmt user**, and **trainee account** creation
  (the Linux `user-access` role does not apply).
- **Registry hive `LastWrite` times** read `2010-02-02` — the training skeleton's timestamp;
  the analytic signal in DF-5.1 is the *values*, not the times.
- Regenerate any artifact with `../../generation/` (re-run resets the E01 acquisition hash;
  the implant flags live in file content and are stable).
