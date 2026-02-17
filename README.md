# Complete-guide-for-secure-boot-on-Arch-Linux-with-rEFInd

> Complete guide to Secure Boot + module signature enforcement on Arch Linux with rEFInd, VMware, and Nvidia



I want to start this by being honest: getting `module.sig_enforce=1` working on Arch Linux took me way longer than it should have because the documentation is scattered across Red Hat docs, kernel mailing lists, and GitHub issues. This guide is my attempt to put everything in one place, explain not just *what* to do but *why*, and save you the hours I lost debugging things that should have been obvious.

By the end of this I had a fully locked-down system where every kernel module is cryptographically verified before it loads. No more "tainting kernel" messages, no unsigned code running in kernel space.

------

## My Setup

Before diving in, here's what I'm working with, because some of this is hardware-specific:

**Hardware:**

- CPU: Intel Core i5-12400F
- GPU: Nvidia GT 1030
- Motherboard: ASUS (this matters because ASUS ships with their own Secure Boot keys pre-enrolled)

**Software:**

- Arch Linux, LUKS2 on LVM (full disk encryption)
- Kernel: custom linux-lts build (I'll explain why I had to build a custom kernel)
- Bootloader: rEFInd with Shim
- Desktop: Hyprland
- VMware Workstation 25.0.0 (installed manually from Broadcom, not from AUR)
- Nvidia 550.163.01 via DKMS

I use VMware heavily for security research and CTF work. I also need my Nvidia GPU working. These two requirements created a lot of the complexity here, because both VMware and Nvidia ship kernel modules that need to be signed to work with signature enforcement.

------

## What I Was Trying to Do

The goal was simple in theory: enable `module.sig_enforce=1`. This kernel parameter tells the kernel to refuse to load any module that isn't cryptographically signed by a trusted key. It's part of a hardened boot chain where you can verify that nothing has tampered with the code running in kernel space.

The problem is that to trust a module, the kernel needs to know about your signing key. And getting your signing key into the kernel's trust store on Arch Linux is not straightforward at all.

------

## Understanding the Moving Parts

Before getting into commands, I want to explain what's actually happening when you boot a UEFI system with Secure Boot enabled. This took me a while to properly understand, and once I did, everything else clicked.

### UEFI and Secure Boot

Your UEFI firmware is the first thing that runs when you power on. It has a built-in database of trusted certificates called the **Signature Database (db)**. On most consumer boards, this contains Microsoft's certificates and your OEM's certificates (which is why ASUS keys showed up in my keyring - my ASUS motherboard pre-enrolled their own keys).

When Secure Boot is enabled, the firmware will only execute EFI binaries (bootloaders, kernels loaded directly) that are signed by a certificate in this db. Anything else gets rejected before it even starts.

**Why this matters:** You can't just add your own key to the UEFI db without going into BIOS and manually enrolling it, or replacing the Platform Key entirely. That's a route some people take (replacing the UEFI keys completely), but it's risky and overkill for most use cases. There's a better way.

### Shim: The Bridge Between Microsoft and You

Shim (`shimx64.efi`) is a small EFI bootloader signed by Microsoft. Because Microsoft signed it, your UEFI firmware will happily launch it even with Secure Boot enabled.

Here's the clever part: Shim has its own key database called the **MOK (Machine Owner Key) database**, stored in NVRAM. Shim will launch any bootloader or kernel that's signed by a certificate in the MOK database, effectively extending the chain of trust from Microsoft → Shim → your custom-signed software.

This is why you need Shim. It lets you use your own signing key without replacing the UEFI keys, and it's the officially supported mechanism for exactly this use case.

**Why I use rEFInd as my bootloader:** rEFInd is a feature-rich EFI boot manager that auto-detects kernels. I'm using it because I like being able to see all my boot options clearly and configure them easily. You could use GRUB instead and the process would be similar, but I'll stick to rEFInd here since that's what I use.

When you run `refind-install --shim`, it:

- Installs rEFInd as `grubx64.efi` (Shim looks for a file with that name to chainload)
- Copies `shimx64.efi` to your ESP
- Generates a local key pair in `/etc/refind.d/keys/`
- Signs rEFInd with that key
- Creates a boot entry pointing to Shim

So the boot chain becomes: **UEFI firmware → shimx64.efi (signed by Microsoft) → grubx64.efi/rEFInd (signed by your MOK) → kernel (signed by your MOK)**

### The Kernel Keyring Problem

Here's where everything gets complicated, and where every Arch guide I found fell short.

The kernel maintains several internal key stores called **keyrings**. When you load a kernel module with `module.sig_enforce=1` active, the kernel checks the module's signature against these keyrings. If the signing key isn't in any of the trusted keyrings, loading fails with "Key was rejected by service."

The relevant keyrings are:

**`.builtin_trusted_keys`** - Keys compiled directly into the kernel binary at build time. Every kernel has an ephemeral key pair generated during compilation; modules built as part of that kernel compilation are signed with this key. This is why in-tree modules (the ones that come with the kernel) work fine with sig_enforce - they're signed with the kernel's own key.

**`.platform`** - Keys loaded from the UEFI Signature Database (db) at boot. This is where Microsoft's certificates, your ASUS OEM keys, etc. end up. Many guides incorrectly say your MOK ends up here. **It doesn't, at least not on Arch.**

**`.machine`** - This is where MOKs should go. Keys loaded from Shim's MOK database (the `MokListRT` UEFI variable) at boot. This is the keyring that enables your custom-signed out-of-tree modules (like VMware and Nvidia) to work with sig_enforce.

**`.secondary_trusted_keys`** - A keyring that contains references to both `.builtin_trusted_keys` and `.machine`. Module signature verification ultimately checks against this combined keyring.

**The problem:** For MOKs to load into `.machine`, the kernel needs a feature called `CONFIG_IMA_SECURE_AND_OR_TRUSTED_BOOT`. Which needs CONFIG_IMA, CONFIG_IMA_APPRAISE as well as CONFIG_IMA_ARCH_POLICY. Without it, the kernel sees the MOK data in NVRAM but ignores it entirely. Your key stays in the MOK database but never makes it to the kernel keyring.

**And Arch kernels don't have this enabled.**

```bash
# Check the stock Arch kernel
zcat /proc/config.gz | grep IMA_SECURE_AND_OR_TRUSTED_BOOT
# CONFIG_IMA_SECURE_AND_OR_TRUSTED_BOOT is not set
```

Why doesn't Arch enable it? Arch's philosophy is minimal by default. IMA (Integrity Measurement Architecture) is considered an enterprise feature - it adds overhead and complexity that most desktop users don't need. Ubuntu, Fedora, and RHEL enable it because their kernels are designed for enterprise/server environments where this kind of security matters.

For my use case it absolutely matters, so I had to build my own kernel.

### What IMA Actually Is

IMA (Integrity Measurement Architecture) is a Linux kernel subsystem that measures and optionally enforces the integrity of files. It can measure binaries before execution, verify signatures on files, and log anything that doesn't meet policy.

The specific config I needed, `CONFIG_IMA_SECURE_AND_OR_TRUSTED_BOOT`, makes IMA responsible for loading UEFI keys (including MOKs from Shim) into the kernel keyrings at boot. Without this, those keyrings just never get populated from UEFI.

### MOKListTrustedRT: The Other Missing Step

Even with a kernel that has IMA enabled, there's one more thing required that almost nothing documents for Arch: you need to run `mokutil --trust-mok`.

When you enroll a MOK with `mokutil --import`, it gets added to the MOK database so Shim can use it to verify bootloaders. But getting it into the *kernel's* `.machine` keyring is a separate opt-in step.

Running `mokutil --trust-mok` sets a UEFI variable called `MokListTrustedRT` to `01`. This tells Shim: "when you're done loading, pass these MOKs along to the kernel too." Without this flag set, the MOKs stay in Shim's world and never reach the kernel.

```bash
# Verify it's set after running --trust-mok and rebooting
sudo efivar -p -n 605dab50-e046-4300-abb6-3dd810dd8b23-MokListTrustedRT | xxd
# Look for 01 at offset 0x80
```

I spent a long time debugging this. I enrolled my key over and over, checked that Shim was in the boot chain, confirmed Secure Boot was enabled, and still got an empty `.machine` keyring. The answer was just this one extra command.

------

## The Gotchas (Mistakes I Made)

Before the step-by-step, here are the things that wasted the most of my time:

**Thinking rEFInd --shim was enough.** It sets up the signing chain for the bootloader and kernel.  It doesn't enable MOK propagation to the kernel keyring or module signing enforcemnt. You still need `mokutil --trust-mok` and to set the module.sig_enforce=1 paramater in the bootloader config.

**Enrolling  duplicate MOKs.** When nothing worked, I kept running `mokutil --import` thinking maybe it hadn't taken. It had. The problem was elsewhere. Check `sudo mokutil --list-enrolled | grep -c "Certificate:"` before importing again.

**Trying linux-hardened first.** I initially tried building linux-hardened with IMA support. Nvidia drivers refused to compile against it due to the aggressive hardening patches. Switched to linux-lts and everything worked. Unless you specifically need the hardening patches, linux-lts is the right choice for a system that also runs proprietary drivers.

**Trying to sign compressed .ko.zst files.** When I figured out I needed to sign Nvidia modules, I found them as `.ko.zst` (compressed) files and ran sign-file on them directly. This corrupts the file because you're appending a signature to compressed data instead of signing the actual ELF binary. DKMS has a built-in signing mechanism that signs before compression - use that instead.

**Adding module.sig_enforce=1 too early.** I added it to my kernel parameters before I'd actually verified the MOKs were loading and modules were signed. System wouldn't boot. Always test that everything works first, then add enforcement.


------

## The Solution: Custom Kernel + Proper MOK Setup

Here's what actually needs to happen:

1. Build linux-lts with `CONFIG_IMA_SECURE_AND_OR_TRUSTED_BOOT` enabled
2. Set up Shim + rEFInd boot chain
3. Enroll your MOK and explicitly enable trust with `mokutil --trust-mok`
4. Configure DKMS to sign modules automatically
5. Sign VMware modules manually
6. Add enforcement parameters and boot with Secure Boot on

Let's go through it.

------

## Step 1: Build linux-lts with IMA Support

**Why linux-lts specifically?** The LTS kernel is the best balance of stability and compatibility. It gets security backports, has good hardware support, and proprietary drivers like Nvidia build against it reliably. linux-hardened has patches that make Nvidia's driver fail to compile. The regular `linux` kernel would work too, but you'd have to rebuild it on every Arch update since it updates very frequently.

**Why do we need to build at all?** Because adding kernel configs isn't something you can do at runtime. These are compile-time options that determine what code is included in the kernel binary. The only way to get `CONFIG_IMA_SECURE_AND_OR_TRUSTED_BOOT` is to build a kernel with it.

### Install Build Dependencies

```bash
sudo pacman -S base-devel bc cpio gettext libelf pahole perl python tar xz git
```

Most of these are standard build tools. `libelf` and `pahole` are needed for BTF (BPF Type Format) generation. `bc` is used in the kernel's build scripts for math operations.

### Clone the PKGBUILD

Arch maintains PKGBUILDs for all their official kernels on GitLab. We clone this instead of the raw kernel source because it includes Arch-specific patches and the correct config for our architecture.

```bash
cd ~/
git clone https://gitlab.archlinux.org/archlinux/packaging/packages/linux-lts.git
cd linux-lts
```

### Add IMA Configuration

The `config` file in this directory is the kernel configuration. We need to add IMA support:

```bash
nano config
```

Add these lines at the end of the file:

```
CONFIG_IMA=y
CONFIG_IMA_APPRAISE=y
CONFIG_IMA_ARCH_POLICY=y
CONFIG_IMA_SECURE_AND_OR_TRUSTED_BOOT=y
CONFIG_IMA_APPRAISE_BOOTPARAM=y
CONFIG_IMA_APPRAISE_MODSIG=y
CONFIG_IMA_LSM_RULES=y
CONFIG_IMA_KEYRINGS_PERMIT_SIGNED_BY_BUILTIN_OR_SECONDARY=y
```

What each does:

- `CONFIG_IMA=y` - Enables IMA subsystem. Everything else depends on this.
- `CONFIG_IMA_APPRAISE=y` - Enables IMA appraisal (checking signatures, not just measuring).
- `CONFIG_IMA_ARCH_POLICY=y` - Enables architecture-specific IMA policy, which on x86 includes loading UEFI keys.
- `CONFIG_IMA_SECURE_AND_OR_TRUSTED_BOOT=y` - **The critical one.** Enables loading MOKs from Shim into the kernel keyring.
- `CONFIG_IMA_APPRAISE_BOOTPARAM=y` - Allows the `ima_appraise=log` boot parameter. Without this, IMA runs in enforce mode from the start and can block your boot if files aren't signed. This gives you a safe way to test.
- `CONFIG_IMA_APPRAISE_MODSIG=y` - Enables checking module signatures through IMA. Important for `module.sig_enforce=1` to work correctly with IMA policy.
- `CONFIG_IMA_LSM_RULES=y` - Integrates IMA with LSM (Linux Security Module) framework.
- `CONFIG_IMA_KEYRINGS_PERMIT_SIGNED_BY_BUILTIN_OR_SECONDARY=y` - Allows keys signed by the builtin or secondary keyrings to be used. This is what allows your MOK (in `.machine`) to be used for module verification via `.secondary_trusted_keys`.

Also verify module signing is already enabled (it should be in the stock config):

```bash
grep CONFIG_MODULE_SIG config
```

You want to see `CONFIG_MODULE_SIG=y`, `CONFIG_MODULE_SIG_ALL=y`, and a hash algorithm like `CONFIG_MODULE_SIG_SHA512=y`. These are usually already set in Arch's config.

### Build

```bash
makepkg -s --skipchecksums --skippgpcheck
```

**Why --skipchecksums:** We modified the `config` file, so its checksum no longer matches what's in the PKGBUILD. This flag tells makepkg to skip that verification.

**Why --skippgpcheck:** You might not have the GPG keys for Linus Torvalds or the linux-hardened maintainer in your keyring. This skips verifying the kernel source signatures. Since we're building from Arch's official GitLab, this is fine.

You'll see a lot of warnings during the build - Perl warnings about pattern matching, documentation warnings about RST formatting. All of these are from documentation generation scripts and don't affect the kernel binary. Ignore them.

This will take 45-90 minutes depending on your CPU. My i5-12400F took about an hour.

When it's done you'll see:

```
==> Finished making: linux-lts 6.12.72-1 (timestamp)
```

### Install

Create a snapshot first:

```bash
sudo pacman -S timeshift
sudo timeshift --create --comments "Before custom linux-lts with IMA"
```

Then install:

```bash
sudo pacman -U linux-lts-6.12.72-1-x86_64.pkg.tar.zst \
              linux-lts-headers-6.12.72-1-x86_64.pkg.tar.zst
```

**Why not the docs package?** The `-docs` package just contains kernel documentation. You don't need it and it's large.

**Why headers?** The linux-lts-headers package contains the kernel build system and header files. DKMS and VMware both need these to compile modules against the new kernel. Without headers, `sign-file` also won't be available at `/usr/lib/modules/<version>/build/scripts/sign-file`.

------

## Step 2: Set Up Shim + rEFInd

**Why Shim?** As explained earlier, Shim is the bridge that lets you use your own keys without touching the UEFI Secure Boot database. It's the correct and officially supported mechanism for exactly this situation.

**Why rEFInd?** Personal preference. I like that it auto-detects kernels, has a nice menu, and is easy to configure. GRUB works too.

### Install Packages

```bash
sudo pacman -S sbsigntools refind efibootmgr
yay -S shim-signed
```

**sbsigntools** - Provides `sbsign` and `sbverify` for signing and verifying EFI binaries (kernels, bootloaders). This is different from `sign-file` which signs kernel modules. Different tools for different things:

- `sbsign` → signs EFI binaries (bootloaders, kernels) with PE/COFF signatures
- `sign-file` → signs kernel modules with PKCS#7 signatures

**shim-signed** is from the AUR. It's Fedora's pre-built, Microsoft-signed Shim binary. Using a pre-built signed binary is important because if you compile Shim yourself, it won't be signed by Microsoft and UEFI won't launch it with Secure Boot enabled.

### Install rEFInd with Shim

```bash
sudo refind-install --shim /usr/share/shim-signed/shimx64.efi --localkeys
```

This single command does a lot:

- Installs rEFInd to `/boot/efi/EFI/refind/`
- Renames rEFInd's binary to `grubx64.efi` (Shim automatically looks for this filename to chainload)
- Copies `shimx64.efi` and `mmx64.efi` (MokManager) to the same directory
- Generates a local RSA key pair in `/etc/refind.d/keys/` (refind_local.key and refind_local.crt)
- Signs rEFInd (`grubx64.efi`) with the generated key
- Creates a UEFI boot entry pointing to Shim



\> **Note:** If you already have rEFInd installed **with Shim**, skip this step. If rEFInd was installed without Shim, you still need to run this command to add Shim to your existing installation.



Your keys are:

- `/etc/refind.d/keys/refind_local.key` - Private key. Keep this safe. Used for signing.
- `/etc/refind.d/keys/refind_local.crt` - Public certificate in PEM format. Used with sign-file.
- `/etc/refind.d/keys/refind_local.cer` - Public certificate in DER format. Used with mokutil for enrollment.



You can also copy the certificate to EFI for enrollment and import it from there:

```bash
sudo mkdir -p /efi/refind/keys
sudo cp /etc/refind.d/keys/refind_local.cer /efi/refind/keys/
```

### Verify Boot Entries

```bash
efibootmgr -v
```

You should see two rEFInd entries:

- `Boot0000* rEFInd Boot Manager (direct)` → points to `grubx64.efi` (bypasses Shim)
- `Boot0001* rEFInd Boot Manager` → points to `shimx64.efi` (goes through Shim)

**Boot0001 must be your default.** Check:

```bash
efibootmgr -v | grep "BootCurrent\|BootOrder"
```

If Boot0001 isn't first in BootOrder, fix it:

```bash
sudo efibootmgr -o 0001,0000
```

### Sign the Kernel

Now sign the kernel so Shim can verify it:

```bash
sudo sbsign --key /etc/refind.d/keys/refind_local.key \
            --cert /etc/refind.d/keys/refind_local.crt \
            --output /boot/vmlinuz-linux-lts \
            /boot/vmlinuz-linux-lts
```

**Why sbsign and not sign-file?** sbsign creates PE/COFF signatures appropriate for EFI binaries. sign-file creates PKCS#7 signatures for kernel modules. The kernel and Shim expect PE/COFF for EFI binary verification, and the kernel module loader expects PKCS#7 for module verification. Wrong tool = verification fails.

Verify it worked:

```bash
sbverify --list /boot/vmlinuz-linux-lts
```

Should show:

```
image signature issuers:
 - /CN=Locally-generated rEFInd key
```

------

## Step 3: Enroll MOK and Enable Trust

This is the step that most guides either skip or explain poorly.

### Export the Certificate

Your public key was generated in PEM format (`.crt`). mokutil expects DER format (`.cer`). The install script should have generated `.cer` already, but verify:

```bash
ls /etc/refind.d/keys/
# Should see refind_local.key, refind_local.crt, refind_local.cer
```

If `.cer` is missing, convert it:

```bash
openssl x509 -in /etc/refind.d/keys/refind_local.crt \
             -outform DER \
             -out /etc/refind.d/keys/refind_local.cer
```

### Enroll the MOK

```bash
sudo mokutil --import /etc/refind.d/keys/refind_local.cer
reboot
```

You'll be prompted for a password. This is a one-time password used only in MokManager to confirm the enrollment. Set something you'll remember for the next 2 minutes.

**What this does:** Stages the certificate for enrollment by writing it to a pending-enrollment UEFI variable. On next boot, Shim detects this pending request and launches MokManager to let you confirm it.

### Enable MOK Trust (CRITICAL)

You need to untrust the MOK first - it won't work without this step.

```bash
sudo mokutil --untrust-mok
reboot
```

Set another password (can be the same as above).

```bash
sudo mokutil --trust-mok
reboot
```

Set password.

**What this does:** Stages a request to set `MokListTrustedRT=1`. Without this, your MOK is only used by Shim for bootloader/kernel signature verification. It does NOT get propagated to the kernel's `.machine` keyring. You'd have Secure Boot working but module signature enforcement would still fail because the kernel wouldn't know about your key.

This is the step I missed for a very long time.

### Reboot Through MokManager

```bash
reboot
```

MokManager will appear **once for each action**:

**First boot - Enroll MOK:**

1. Select "Enroll MOK"
2. Select "Continue"
3. Review the key details
4. Select "Yes"
5. Enter the password from the `--import` step
6. Select "Reboot"

**Second boot - Untrust MOK:**

1. Select "Change Secure Boot state" (or similar wording)
2. Enter the password from the `--untrust-mok` step
3. Select "Yes"
4. Select "Reboot"

**Third boot - Enable Trust:**

1. Select "Change Secure Boot state" (or similar wording)
2. Enter the password from the `--trust-mok` step
3. Select "Yes"
4. Select "Reboot"

### Verify the Setup

After rebooting with Secure Boot enabled:

```bash
# Check MokListTrustedRT is set
sudo efivar -p -n 605dab50-e046-4300-abb6-3dd810dd8b23-MokListTrustedRT | xxd
# Look for '01' at offset 0x80

# Check kernel loaded the MOK
sudo dmesg | grep "integrity.*Loaded X.509 cert.*rEFInd"
# Should show: integrity: Loaded X.509 cert 'Locally-generated rEFInd key: ...'

# Check .machine keyring
sudo keyctl list %:.machine
# Should show your key
```

------

## Step 4: Sign Kernel Modules

Here's where my specific setup required extra work because of Nvidia and VMware.

### Why Modules Need Signing

When `module.sig_enforce=1` is active, the kernel won't load any module that isn't signed by a key it trusts. In-tree modules (compiled with the kernel) are automatically signed by the kernel's ephemeral build key, which is in `.builtin_trusted_keys`. Out-of-tree modules (Nvidia, VMware) are not compiled with the kernel, so they need to be signed with your MOK which you've put in `.machine`.

### Why .ko.zst Files Can't Be Signed Directly

Arch compresses kernel modules with zstd to save space. If you try to append a signature to a compressed file, you're signing the compressed blob rather than the actual ELF binary. When the kernel decompresses the module and tries to verify the signature, the signature won't match the decompressed content. The result is a corrupted module.

The correct approach is to sign the ELF binary *before* compression. DKMS has a built-in mechanism for this.

### Configure DKMS Auto-Signing

DKMS (Dynamic Kernel Module Support) is the system that automatically rebuilds out-of-tree modules when you update the kernel. It also supports automatic signing if you configure it.

Create or edit `/etc/dkms/framework.conf`:

```bash
sudo nano /etc/dkms/framework.conf
```

Add:

```bash
sign_tool="/usr/lib/modules/$kernelver/build/scripts/sign-file"
mok_signing_key="/etc/refind.d/keys/refind_local.key"
mok_certificate="/etc/refind.d/keys/refind_local.crt"
```

This tells DKMS to run `sign-file` on each module after compiling it but before compressing it. The `$kernelver` variable is automatically set by DKMS during the build process.

### Rebuild and Sign Nvidia Modules

Now rebuild Nvidia with signing:

```bash
sudo dkms remove nvidia/550.163.01 -k 6.12.72-1-lts
sudo dkms install nvidia/550.163.01 -k 6.12.72-1-lts
```

You should see output like:

```
Building module(s)................. done.
Signing module /var/lib/dkms/nvidia/550.163.01/build/nvidia.ko
Signing module /var/lib/dkms/nvidia/550.163.01/build/nvidia-uvm.ko
Signing module /var/lib/dkms/nvidia/550.163.01/build/nvidia-modeset.ko
Signing module /var/lib/dkms/nvidia/550.163.01/build/nvidia-drm.ko
Signing module /var/lib/dkms/nvidia/550.163.01/build/nvidia-peermem.ko
Installing ...
Running depmod... done.
```

The signing happens before the "Installing" step, which is when compression occurs.

### Sign VMware Modules

VMware Workstation doesn't use DKMS - it has its own module compilation system. When VMware detects a new kernel, it compiles vmmon and vmnet from its own source tree.

The modules end up in `/usr/lib/modules/<kernelversion>/misc/` as uncompressed `.ko` files, so we can sign them directly with `sign-file`.

Create the signing script:

```bash
sudo nano /usr/local/bin/sign-vmware
```

```bash
#!/bin/bash

kernel_version=${1:-$(uname -r)}
key="/etc/refind.d/keys/refind_local.key"
cert="/etc/refind.d/keys/refind_local.crt"
sign_file="/usr/lib/modules/$kernel_version/build/scripts/sign-file"
module_path="/usr/lib/modules/$kernel_version/misc"

if [ ! -f "$sign_file" ]; then
    echo "ERROR: sign-file not found at $sign_file"
    echo "Is linux-lts-headers installed for $kernel_version?"
    exit 1
fi

if [ ! -f "$module_path/vmmon.ko" ]; then
    echo "ERROR: vmmon.ko not found at $module_path"
    echo "Has VMware compiled modules for $kernel_version?"
    exit 1
fi

echo "Signing VMware modules for kernel $kernel_version..."

$sign_file sha256 "$key" "$cert" "$module_path/vmmon.ko"
echo "  Signed vmmon.ko"

$sign_file sha256 "$key" "$cert" "$module_path/vmnet.ko"
echo "  Signed vmnet.ko"

echo "Done. Verifying..."
modinfo "$module_path/vmmon.ko" | grep "signer:"
modinfo "$module_path/vmnet.ko" | grep "signer:"

```

```bash
sudo chmod +x /usr/local/bin/sign-vmware
```



**Why sha256 and not sha512?** VMware's module format expects sha256. Using sha512 would fail verification. Nvidia doesn't care because DKMS handles that automatically based on the kernel's configured algorithm.

Build and sign VMware modules:

```bash
# Open VMware - it will detect the new kernel and prompt to compile modules
vmware

# After VMware compiles them, sign
sudo sign-vmware
```

Or if you want to compile without opening the GUI:

```bash
sudo vmware-modconfig --console --install-all
sudo sign-vmware
```

------

## Step 5: Enable Enforcement

Now everything is in place. Time to actually turn on enforcement.

### Add Boot Parameters

Edit your rEFInd boot configuration:

```bash
sudo nano /boot/refind_linux.conf
```

Your boot line probably looks something like:

```
"Boot with standard options" "root=/dev/mapper/vg0-root rw cryptdevice=UUID=your-uuid:cryptlvm ..."
```

Add these parameters:

```
ima_appraise=log ima_policy=tcb module.sig_enforce=1
```

**`ima_appraise=log`** - Runs IMA in log-only mode. It checks file integrity and logs violations to dmesg but doesn't block anything. This is safe for testing and useful for monitoring. If you want IMA to actually enforce file integrity (block unsigned executables, etc.), you'd use `ima_appraise=enforce`, but that's a much bigger commitment that requires signing your entire userspace. I'm not going that far - I just want module enforcement.

**`ima_policy=tcb`** - The Trusted Computing Base policy tells IMA what to measure. TCB measures everything that could affect the system's security state, including kernel modules. This is needed for `ima_appraise` to work properly with modules.

**`module.sig_enforce=1`** - The main goal. Tells the kernel to refuse loading any module without a valid signature from a trusted key. With your MOK in `.machine` and `.machine` in `.secondary_trusted_keys`, your signed modules will pass. Anything unsigned will be rejected.

### Enable Secure Boot and Reboot

Go into your BIOS/UEFI settings and enable Secure Boot if it's not already on. Save and exit.

```bash
reboot
```

If the system boots successfully, you're done with the hard part.

If it doesn't boot:

- Enter BIOS and temporarily disable Secure Boot
- Boot into the system
- Run `sudo journalctl -u systemd-modules-load.service` to see what failed to load
- Sign the failing module
- Re-enable Secure Boot and try again

------

## Verifying Everything Works

Run through these checks after a successful boot:

```bash
# Secure Boot must be on
sudo mokutil --sb-state
# Expected: SecureBoot enabled

# IMA is running with your custom kernel
zcat /proc/config.gz | grep IMA_SECURE_AND_OR_TRUSTED_BOOT
# Expected: CONFIG_IMA_SECURE_AND_OR_TRUSTED_BOOT=y

# Module enforcement is active
cat /proc/cmdline | grep sig_enforce
# Expected: shows module.sig_enforce=1

# Your MOK loaded into .machine keyring
sudo keyctl list %:.machine
# Expected: shows "Locally-generated rEFInd key"

# .machine is trusted by the kernel
sudo keyctl list %:.secondary_trusted_keys
# Expected: shows .builtin_trusted_keys and .machine

# Modules are signed with your key
modinfo nvidia | grep signer
modinfo vmmon | grep signer
# Expected: signer: Locally-generated rEFInd key

# Modules load cleanly without tainting
sudo modprobe -r vmmon && sudo modprobe vmmon
sudo dmesg | tail -5
# Expected: no "tainting kernel" message
# Should see: Module vmmon: initialized

# Module loader succeeded at boot
systemctl status systemd-modules-load.service
# Expected: active (exited), status=0/SUCCESS
```

------

## Maintenance

The downside of building a custom kernel is that you have to rebuild it when the upstream linux-lts version updates. Arch updates linux-lts fairly infrequently (LTS kernels have long support cycles), so this isn't too painful.

### When linux-lts Updates

```bash
cd ~/linux-lts
git pull

# Check if the config file changed significantly
# If so, you may need to review which IMA options are still present
nano config
# Add the 8 IMA lines again if needed

# Rebuild
makepkg -s --skipchecksums --skippgpcheck

# Install
sudo pacman -U linux-lts-*.pkg.tar.zst linux-lts-headers-*.pkg.tar.zst

# Sign the new kernel
sudo sbsign --key /etc/refind.d/keys/refind_local.key \
            --cert /etc/refind.d/keys/refind_local.crt \
            --output /boot/vmlinuz-linux-lts \
            /boot/vmlinuz-linux-lts

# DKMS auto-rebuilds and auto-signs Nvidia (because of framework.conf)

# Sign VMware manually
sudo sign-vmware

# Test boot
reboot
```

### When Nvidia Updates

DKMS handles this automatically. The `framework.conf` we created ensures every DKMS-managed module gets signed during installation. You shouldn't need to do anything manually.

### When VMware Updates

After installing a new VMware version, it will detect the new modules are missing and either auto-rebuild or prompt you to rebuild. After that:

```bash
sudo sign-vmware
```

------

## Why This Matters

The whole point of this exercise is to have a kernel-level guarantee that the code running in kernel space is exactly what you authorized. With `module.sig_enforce=1` active and your MOK as the only signing key, no module can load without you having explicitly signed it.

 If someone managed to install a malicious kernel module (a rootkit, for example), it would fail to load because it wouldn't have your signature. Combined with LUKS encryption, Secure Boot, and a locked-down firewall, the overall security posture is solid.

On Ubuntu/Fedora/RHEL, this happens automatically because they enable `CONFIG_IMA_SECURE_AND_OR_TRUSTED_BOOT=y` in their kernels. This config makes the kernel grab MOKs from Shim and load them into a keyring called `.machine`. There you just have to enable secure boot in BIOS, sign the modules and import the certificate into MOK.

------

## References

- [Red Hat docs: Signing a kernel and modules for Secure Boot](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/managing_monitoring_and_updating_the_kernel/signing-a-kernel-and-modules-for-secure-boot_managing-monitoring-and-updating-the-kernel) - A good documentation on MOK and module signing I found. Written for RHEL but the concepts apply everywhere.
- [LWN: Enroll kernel keys through MOK](https://lwn.net/Articles/880582/) - The kernel patch series that introduced CONFIG_IMA_SECURE_AND_OR_TRUSTED_BOOT. Reading the patch description helped me understand exactly what this config does.
- [Arch GitLab Issue #35: Request IMA support in Arch kernels](https://gitlab.archlinux.org/archlinux/packaging/packages/linux/-/issues/35) - Where I confirmed that Arch intentionally omits this config and saw others running into the same problem.
- [Arch Wiki: Secure Boot](https://wiki.archlinux.org/title/Unified_Extensible_Firmware_Interface/Secure_Boot) - Good overview but doesn't cover the MOK trust step or the IMA requirement.
- [Rod Smith: Managing EFI Boot Loaders for Linux](https://www.rodsbooks.com/efi-bootloaders/secureboot.html) - Comprehensive UEFI Secure Boot reference. Good for understanding the firmware side.

------

*System: i5-12400F, Nvidia GT 1030, Arch Linux with LUKS on LVM, Hyprland, VMware Workstation 25.0.0, linux-lts 6.12.72*

*If something in this guide is wrong or there's a better way to do something, open an issue. This took me a long time to figure out and I'd rather have an accurate guide than a wrong one.*
