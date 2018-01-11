        Reading privileged memory with a side-channel [1]


1. Summary

CVE names: CVE-2017-5715, CVE-2017-5753, CVE-2017-5754
Affected software: Many operating Systems including the Linux kernel
Versions affected: All
Severity: High
Affected hardware: All modern CPUs based on speculative execution, including certain processors by Intel, AMD, NXP and ARM.
Mitigation/workaround: 
   - Separating the kernel and user space page table
   - Disabling indirect branch prediction upon entry into the kernel or into the hypervisor
   - Fencing speculative loads of certain memory locations
Downside of the mitigation: 
Estimated 5-30% performance loss depending on the amount of system calls performed (and interrupts serviced).

2. Description

An industry-wide issue has been disclosed by Google Project Zero project in the way many modern microprocessor designs have implemented speculative execution of instructions (a commonly used performance optimization). The CPU data cache timing can be abused to efficiently leak information out of mis-speculated execution, leading to arbitrary virtual memory read vulnerabilities across local security boundaries in various contexts.
The Project Zero research team at Google identified three variants of the exploits within the speculative execution research:

Variant 1: bounds check bypass (Spectre, CVE-2017-5753)
Variant 2: branch target injection (Spectre, CVE-2017-5715)
Variant 3: rogue data cache load (Meltdown, CVE-2017-5754)

Spectre
=======
There is work to harden software against future exploitation of Spectre, respectively to patch software after exploitation through Spectre (LLVM patch, ARM speculation barrier header).
E.g. Intel has issued Updates to protect systems from Security Exploits: https://newsroom.intel.com/news-releases/intel-issues-updates-protect-systems-security-exploits/

Meltdown
========
Software patches (Kernel address space isolation, “KAISER”) are available estimated 5-30% performance loss depending on the amount of system calls Performed (and interrupts serviced). M Intel CPUs are affected by this vulnerability.
There are patches against Meltdown for Linux, KPTI (formerly KAISER https://lwn.net/Articles/738975/).

Mitigation
==========
Mitigation involves steps below:

-	Separating the kernel and user virtual address spaces
  This is performed using a design change to the Operating System kernel known as KPTI (Kernel Page Table Isolation), sometimes referred   to using the older name “KAISER”. 
-	Disabling indirect branch prediction upon entry into the kernel or into the hypervisor 
  New capabilities have been added to many microprocessors across the industry through microcode, millicode, firmware, and other   updates. These new capabilities are leveraged by updates to Red Hat Enterprise Linux which control their use.
-	Fencing speculative loads of certain memory locations: Such loads have to be annotated through small changes to the Linux kernel, which have been integrated into Red Hat updates.

These software solutions, in combination with microcode, millicode, and firmware updates can mitigate the attacks.

Linux upstream kernel
=================
Kernel Page Table Isolation is a mitigation in the Linux Kernel, originally named KAISER.

  •	Version 4.14.11 contains KPTI.
  •	Version 4.15-rc6 contains KPTI.
  •	Longterm support kernels Version 4.9.75 contain KPTI backports.

Explanation of PCID, which will reduce performance impact of KPTI on newer kernels.

QEMU patches
============
Unofficial patch published: https://lists.nongnu.org/archive/html/qemu-devel/2018-01/msg00811.html
official blog post: https://www.qemu.org/2018/01/04/spectre/ 

KVM update
========== 
KVM developer, posted in a tweet the following status update for CVE-2017-5715 (Spectre): Already in Linus's tree: clearing registers on vmexit

First wave of KVM fixes here: https://marc.info/?l=kvm&m=151543506500957&w=2
He is also mentioning that a full solution will require all the Linux parts to be agreed upon, but this will unblock the QEMU updates.

Vendor statement
================
Arm
According to Arm the majority of Arm processors are not impacted by any variation of the side-channel speculation mechanism.
A definitive list of the small subset of Arm-designed processors which are susceptible can be found here:
    https://developer.arm.com/support/security-update

Variant 1 Action required:
    •	Search your code for the code snippets as described in the Cache speculation Side-channels whitepaper.
    •	Once identified use the compiler support for mitigations as described in compiler support for mitigations to modify your code, and recompile using an updated compiler.

Variant 2
    The mitigation will vary by processor micro-architecture, for Cortex-A57 and Cortex-A72: 
        Apply all kernel patches provided by Arm and available at
       https://git.kernel.org/pub/scm/linux/kernel/git/arm64/linux.git/log/?h=kpti


Variant 3 (for Cortex-A15, Cortex-A57, and Cortex-A72):
        In general, it is not believed that software mitigations for this issue are necessary.
        Please download the Cache Speculation Side-channels whitepaper for more info.

 Arm Trusted Firmware patches are also available.

Intel
All Intel processor which implements out-of-order execution is potentially affected, which is effectively every processor since 1995 (except Intel Itanium and Intel Atom before 2013).
Further info provided by Intel:
- Speculative Execution and Indirect Branch Prediction Side Channel Analysis Method: https://security-center.intel.com/advisory.aspx?intelid=INTEL-SA-00088&languageid=en-fr 
- Intel Analysis of Speculative Execution Side Channels (Whitepaper): https://newsroom.intel.com/wp-content/uploads/sites/11/2018/01/Intel-Analysis-of-Speculative-Execution-Side-Channels.pdf
- Intel Issues Updates to Protect Systems from Security Exploits: https://newsroom.intel.com/news-releases/intel-issues-updates-protect-systems-security-exploits/

Security Exploits and Intel Products (Press Kit): https://newsroom.intel.com/press-kits/security-exploits-intel-products/ 
Facts about The New Security Research Findings and Intel® Products:
https://www.intel.com/content/www/us/en/architecture-and-technology/facts-about-side-channel-analysis-and-intel-products.html

AMD
The AMD research team identified three variants within the speculative execution research. The below grid details the specific variants detailed in the research and the AMD response details.
               
Variant One (Bounds Check Bypass)
  -Resolved by software / OS updates to be made available by system vendors and manufacturers. Negligible performance impact expected.

Variant Two (Branch Target Injection )
  - Differences in AMD architecture mean there is a near zero risk of exploitation of this variant. Vulnerability to Variant 2 has not been demonstrated on AMD processors to date.

Variant Three (Rogue Data Cache Load)           
   - Zero AMD vulnerability due to AMD architecture differences. http://www.amd.com/en/corporate/speculative-execution

NXP 
We are waiting for official statement by NXP. Please refer to NXP community discussion: 
https://community.nxp.com

e500 (P1021 and ADS8560) has Branch prediction support so e500 seems to be affected, see "1.5.2 Branch Detection and Prediction".
https://www.nxp.com/docs/en/reference-manual/E500CORERM.pdf  

G2 and e300 cores have Static Branch Prediction, thus relies on application using __builtin_expect() or compile time options -fprofile-arcs:  
https://www.nxp.com/docs/en/reference-manual/G2CORERM.pdf 
https://www.nxp.com/docs/en/reference-manual/e300coreRM.pdf 

IBM Power8 and Power9 servers
RedHat patched IBM POWER8 (Big Endian and Little Endian), and POWER9 (Little Endian).", so this shows the attack is possible on this architecture:
https://access.redhat.com/security/vulnerabilities/speculativeexecution 

Downside of the fix
====================
The downside to this separation is that it is estimated relatively expensive, time wise, to keep switching between two separate address spaces for every system call and for every interrupt from the hardware.
These context switches do not happen instantly, and they force the processor to dump cached data and reload information from memory. This increases the kernel's overhead, and slows down the computer 5% -30 % depending on the amount of system calls performed and interrupts serviced.

Industry Testing Shows Recently Released Security Updates Not Impacting Performance in Real-World Deployments: 
https://newsroom.intel.com/news-releases/industry-testing-shows-recently-released-security-updates-not-impacting-performance-real-world-deployments/

Affected Enea Releases
======================
Enea releases are affected but the problem is only known to exist on certain processors from Intel, AMD, NXP and Arm which implement speculative execution. See “vendor statement” and “Questions & Answers” sections for more info. 
Please refer to your hardware vendor or Enea support team for detailed info.

3. Questions & Answers
======================
Q: What is Meltdown and Spectre?
A: Meltdown and Spectre are hardware design vulnerabilities in all modern CPUs based on speculative execution.

Q: Why is it called Meltdown?
A: The vulnerability basically melts security boundaries which are normally enforced by the hardware.

Q: Why is it called Spectre?
A: The name is based on the root cause, speculative execution. As it is not easy to fix, it will haunt us for quite some time.

Q: Am I affected by the vulnerability?
A: Most certainly, yes.

Q: Which systems are affected by Meltdown?
A: Desktop, Laptop, and Cloud computers may be affected by Meltdown. More technically, every Intel processor which implements out-of-order execution is potentially affected, which is effectively every processor since 1995 (except Intel Itanium and Intel Atom before 2013). 

Q: Meltdown have only been verified on Intel processors. It is unclear whether AMD processors are also affected by Meltdown.  
A: According to Arm, some of their processors are also affected.

Q: Which systems are affected by Spectre?
A: Almost every system is affected by Spectre: Desktops, Laptops, Cloud Servers, as well as Smartphones.

Q: Is there any known exploit for Meltdown or Spectre?
A: We are not aware of any public exploit. 

Q: Can antivirus detect or block this attack?
A: While possible in theory, this is unlikely in practice. Unlike usual malware, Meltdown and Spectre are hard to distinguish from regular benign applications. However, antivirus may detect malware which uses the attacks by comparing binaries after they become known.

Q: What can be leaked?
A: If your system is affected, the exploit can read the memory content of your computer. This may include passwords and sensitive data stored on the system.

4. References

    https://github.com/hannob/meltdownspectre-patches
    https://www.schneier.com/blog/archives/2018/01/spectre_and_mel.html
    https://en.wikipedia.org/wiki/Side-channel_attack
    http://www.techdesignforums.com/practice/guides/side-channel-analysis-attacks
    https://googleprojectzero.blogspot.ca/2018/01/reading-privileged-memory-with-side.html
    https://spectreattack.com/spectre.pdf
    https://meltdownattack.com/meltdown.pdf
    https://developer.arm.com/support/security-update
    http://www.amd.com/en/corporate/speculative-execution
    https://access.redhat.com/security/vulnerabilities/speculativeexecution 

[1] A side-channel attack is any attack based on information gained from the physical implementation of cryptosystem rather than brute force or theoretical weaknesses in the crypto algorithms. For example, timing information, power consumption, electromagnetic leaks or even sound can provide an extra source of information, which can be exploited to break the system. 
Some side-channel attacks require technical knowledge of the internal operation of the system on which the cryptography is implemented, although others such as differential power analysis are effective as black-box attacks. Many powerful side-channel attacks are based on statistical methods pioneered by Paul Kocher (an American cryptographer).

5. Acknowledgements

    Thanks to Google Project Zero for reporting these flaws.




