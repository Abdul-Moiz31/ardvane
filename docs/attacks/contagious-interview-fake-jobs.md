# Contagious Interview — fake jobs and coding tests

North Korean operators (tracked under names such as **Famous Chollima**, **Void Dokkaebi** and **WaterPlum**) pose as
recruiters or companies and invite developers to a "technical interview". The victim is asked to clone and run a
project — a take-home test, a bug to fix, a demo app. The project looks real (thousands of lines of plausible code),
but a few hidden lines start the malware. The Cloud Security Alliance reports more than 30,000 devices in over 100
countries infected by one wave between December 2025 and July 2026.

## How it reaches you

- LinkedIn / Telegram / email messages from "recruiters", often for crypto, Web3 or well-paid remote roles.
- A repository on GitHub, GitLab or Bitbucket to clone and run, or a zip file.
- Sometimes a fake video-call page asking you to "fix" your camera with a command (see [ClickFix](clickfix-fake-meeting-fix.md)).
- Newer waves self-propagate: infected developers' repositories infect the next person (see [PolinRider](polinrider-worm.md)).

## What it does

- Running the project (`npm install`, `npm start`, opening it in an editor with auto-run tasks) starts a loader.
- The loader installs stealers and a backdoor ([BeaverTail / InvisibleFerret](beavertail-invisibleferret-stealers.md)):
  browser passwords and cookies, crypto wallets, files, a remote-access trojan, clipboard theft.
- Researchers report large crypto thefts tied to the campaign.

## How to spot it

- Unsolicited, unusually attractive offers; pressure to run the code quickly; a "company" with a thin web presence.
- The repo asks you to run something during the interview, or ships `.vscode` tasks, install scripts or oversized config files.
- `checkrepo <folder>` flags the known loader patterns.

## How to protect yourself

- **Never run interview code on your main machine.** Use a cloud dev environment (e.g. GitHub Codespaces) or a disposable VM.
- Scan first: `checkrepo <folder>`; keep VS Code automatic tasks off and npm `ignore-scripts` on (this kit sets both).
- Verify the recruiter and the company through official channels before running anything.

## Sources

1. Palo Alto Networks Unit 42 — "Contagious Interview: DPRK Threat Actors Lure Tech Industry Job Seekers…": https://unit42.paloaltonetworks.com/north-korean-threat-actors-lure-tech-job-seekers-as-fake-recruiters/
2. Cloud Security Alliance — "Contagious Interview: WaterPlum's 30,000-Device Global Developer Campaign": https://labs.cloudsecurityalliance.org/research/csa-research-note-contagious-interview-waterplum-campaign-20/
3. Elastic Security Labs — Contagious Interview malware analysis: https://www.elastic.co/security-labs/contagious-interview-malware-svg-steganography
4. Atlassian — "Disrupting Contagious Interview": https://www.atlassian.com/blog/bitbucket/disrupting-contagious-interview
5. Silent Push — "Contagious Interview (DPRK) Launches a New Campaign Creating Three Front Companies…": https://www.silentpush.com/blog/contagious-interview-front-companies/
6. Dark Reading — "DPRK Fake Job Scams Self-Propagate in 'Contagious Interview'": https://www.darkreading.com/cyberattacks-data-breaches/dprk-fake-job-scams-self-propagate-contagious-interview
7. The420.in — "Void Dokkaebi: fake job interviews developer malware campaign": https://the420.in/void-dokkaebi-fake-job-interviews-developer-malware-campaign/
8. Infosecurity Magazine — "North Korean Actors Expand Contagious Interview Campaign with New Malware": https://www.infosecurity-magazine.com/news/north-korean-contagious-interview/
