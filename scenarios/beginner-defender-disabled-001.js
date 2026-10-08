/* CTI Casefile — Scenario definition
 * Pure data. Loaded as a classic script so the app also works from file://
 * (fetch() of JSON would be blocked by CORS on a local disk).
 *
 * Source of truth for content: ../new.scenario (beginner-defender-disabled-001)
 */
(function () {
  window.CTI_SCENARIOS = window.CTI_SCENARIOS || [];

  window.CTI_SCENARIOS.push({
    id: 'beginner-defender-disabled-001',
    title: 'The Turned-Off Alarm',
    difficulty: 'Beginner',
    seed: 107,
    caseRef: 'CASE 004',
    host: 'sec-win-05',
    host_ip: '10.0.4.12',
    log_sources: ['auth'],

    mission: {
      brief: 'Investigate workstation sec-win-05.',
      objective: 'Determine why endpoint protection was disabled on this workstation, and what it was preparing for.',
      client: 'Internal Security Operations — Tier 1 Escalation Desk'
    },

    narrative:
      'An attacker with a foothold on a workstation disabled Windows Defender in real time by running PowerShell ' +
      'commands that turned off real-time protection and added a folder exclusion, then launched a command shell. ' +
      'This is a classic pre-malware step: turn off the alarm before doing the damage.',

    /* ---------------------------------------------------------------
     * Strings the engine reads from the scenario, so no fact about this
     * case is written into app.js. Every value here comes from new.scenario;
     * the evidence, stream and questions that follow are built on it.
     * --------------------------------------------------------------- */
    engine: {
      /* stage 2 — the record stream banner */
      stream: {
        window: '08:00–08:45',
        files: ['secwin5-events.evtx', 'defender-operational.evtx']
      },

      /* stage 5 / 6 — section headings and the progress checklist labels */
      sections: {
        behaviour: 'name the behaviour',
        second: 'read the Defender log',
        trail: 'assemble the change sequence',
        attack: 'map it to attack',
        attackAlso: 'supporting techniques',
        iocs: 'keep the intelligence'
      },

      /* stage 1 — the three questions the analyst carries into the data */
      carryQuestions: [
        'Whose session turned protection off, and does that account have any reason to change endpoint settings?',
        'What exactly changed on the host between the command running and the alarm going quiet?',
        'What was done in the window those changes opened — and is there any record of what came next?'
      ],

      /* stage 3 — what the cadence of the sequence means */
      cadenceNote:
        'The order is the finding: PowerShell at 08:03, real-time protection off at 08:04, a folder excluded from ' +
        'scanning 27 seconds later, and a command shell 84 seconds after that. The host is disarmed before it is ' +
        'used — nothing has been dropped yet, and that is why the missing payload is itself a finding.',

      /* ledger wording, so the analyst journal reads in the case's own terms */
      awards: {
        evidence:
          'Reviewed the full evidence set: three alerts plus account and change-window reference data',
        timeline:
          'Identified the pattern: protection disabled, a scan exclusion added, and only then a command shell',
        triageContext:
          'Kept the compromised logon as context rather than evidence — it anchors the timeline without proving ' +
          'the tampering',
        board:
          'Correlated the full chain: external source → compromised account → PowerShell → Defender changes → ' +
          'command shell',
        attack: 'Mapped the tampering to ATT&CK T1562.001 Impair Defenses: Disable or Modify Tools',
        attackAlso:
          'Identified the interpreters behind it: T1059.001 PowerShell and T1059.003 Windows Command Shell',
        host: 'Scoped the incident to host sec-win-05'
      },

      /* stage 5 — the collapsed trail card, and its journal entry */
      trailRows: [
        { k: 'Subject', v: 'asmith', flag: '— standard account, no admin rights, no change ticket' },
        { k: 'Command', v: 'Set-MpPreference -DisableRealtimeMonitoring $true', flag: '— typed by hand at 08:03:05' },
        { k: 'Changes', v: '5001 → 5007', flag: '— protection off, then Temp excluded from scanning' },
        { k: 'Trail', v: 'asmith 08:03:05 → powershell.exe → 5001 08:04:31 → 5007 08:04:58 → cmd.exe 08:06:22' }
      ],
      trailLabel: 'REVEAL THE FULL CHAIN',
      journalDecode:
        'Assembled the change sequence — PowerShell at 08:03:05, real-time protection off at 08:04:31, Temp ' +
        'exclusion added at 08:04:58, command shell spawned at 08:06:22',

      /* stage 6 — the live assessment preview */
      reportPreview: {
        rows: [
          { label: 'Host', value: 'sec-win-05 (10.0.4.12)', code: true },
          { label: 'Account', value: 'asmith', code: true },
          { label: 'Disable command', value: 'Set-MpPreference -DisableRealtimeMonitoring $true', code: true },
          { label: 'Defender changes', value: '1 disable (5001) and 1 scan exclusion (5007) — no approved change window', code: true },
          { label: 'Afterwards', value: 'cmd.exe spawned 84 seconds after the exclusion, no payload captured', code: true },
          { label: 'TTP', value: 'Impair Defenses: Disable or Modify Tools T1562.001', code: false }
        ],
        note:
          'Assemble your justification in the fields above. The assessment is only defensible if the reasoning ' +
          'is visible.'
      }
    },

    /* ---------------------------------------------------------------
     * STAGE 2 — TRIAGE
     * The student tags each event as signal / context / noise.
     * tags: 'signal' | 'context' | 'noise'
     * --------------------------------------------------------------- */
    events: [
      {
        id: 'ev-4624-foothold',
        ts: '08:01:12',
        code: 4624,
        kind: 'event',
        host: 'sec-win-05',
        actor: 'asmith',
        text: 'Successful interactive logon. Source 203.0.113.45 (remote). Logon type 10.',
        tags: 'context',
        why:
          'This is the foothold — the interactive entry point, not the malicious behaviour itself. You need it to ' +
          'anchor the timeline and to know whose session did the rest, but one remote logon is not evidence of ' +
          'tampering.'
      },
      {
        id: 'ev-4688-powershell',
        ts: '08:03:05',
        code: 4688,
        kind: 'event',
        host: 'sec-win-05',
        actor: 'asmith',
        text: 'Process created: powershell.exe. Command line: Set-MpPreference -DisableRealtimeMonitoring $true.',
        tags: 'signal',
        why:
          'An interactive PowerShell session with a hand-typed Defender preference. There is no legitimate script ' +
          'on a workstation that switches off real-time protection, and the $true switch is not something a user ' +
          'accidentally types.'
      },
      {
        id: 'ev-5001-defender-off',
        ts: '08:04:31',
        code: 5001,
        kind: 'event',
        host: 'sec-win-05',
        text: 'Windows Defender real-time protection disabled. Changed by: asmith. Previous state: enabled.',
        tags: 'signal',
        why:
          'This is the alarm going quiet. It is the outcome of the previous record, not an independent event — and ' +
          'it happened in production hours with no approved maintenance window open.'
      },
      {
        id: 'ev-5007-exclusion',
        ts: '08:04:58',
        code: 5007,
        kind: 'event',
        host: 'sec-win-05',
        text: 'Windows Defender exclusion added. Path: C:\\Users\\asmith\\AppData\\Local\\Temp. Changed by: asmith.',
        tags: 'signal',
        why:
          'Twenty-seven seconds later, a folder is carved out of scanning — and it is the attacker user\u2019s own ' +
          'Temp directory, which is exactly where a dropped payload would be staged. The host now has a place ' +
          'nothing will look at.'
      },
      {
        id: 'ev-4688-cmd',
        ts: '08:06:22',
        code: 4688,
        kind: 'event',
        host: 'sec-win-05',
        actor: 'asmith',
        text: 'Process created: cmd.exe (Command Prompt). Parent: powershell.exe. Creator: asmith.',
        tags: 'signal',
        why:
          'A command shell started from inside the PowerShell session, 84 seconds after the alarm was disabled. ' +
          'This is the first work done in the blind spot the two Defender changes created — which is why the ' +
          'absence of any malware record is itself worth reporting.'
      },

      /* ---------- noise: baseline user activity ---------- */
      { id: 'ev-n01', ts: '08:00:41', code: 4624, kind: 'event', host: 'FIN-WS-14', actor: 'jdoe', text: 'Successful logon. Logon type 2. Source 10.0.4.10.', tags: 'noise' },
      { id: 'ev-n02', ts: '08:02:03', code: 4634, kind: 'event', host: 'FIN-WS-14', actor: 'jdoe', text: 'Logoff. Session closed.', tags: 'noise' },
      { id: 'ev-n03', ts: '08:02:44', code: 4672, kind: 'event', host: 'HR-LT-03', actor: 'mchen', text: 'Special privileges assigned to new logon.', tags: 'noise' },
      { id: 'ev-n04', ts: '08:03:18', code: 4624, kind: 'event', host: 'OPS-WS-09', actor: 'kpatel', text: 'Successful logon. Logon type 2. Source 10.0.4.20.', tags: 'noise' },
      { id: 'ev-n05', ts: '08:05:03', code: 4634, kind: 'event', host: 'FIN-WS-14', actor: 'jdoe', text: 'Logoff. Session closed.', tags: 'noise' },
      { id: 'ev-n06', ts: '08:05:27', code: 4624, kind: 'event', host: 'ENG-WS-02', actor: 'svega', text: 'Successful logon. Logon type 2. Source 10.0.4.11.', tags: 'noise' },
      { id: 'ev-n07', ts: '08:06:40', code: 4634, kind: 'event', host: 'HR-LT-03', actor: 'mchen', text: 'Logoff. Session closed.', tags: 'noise' },
      { id: 'ev-n08', ts: '08:07:44', code: 4672, kind: 'event', host: 'OPS-WS-09', actor: 'kpatel', text: 'Special privileges assigned to new logon.', tags: 'noise' },
      { id: 'ev-n09', ts: '08:08:15', code: 4624, kind: 'event', host: 'FIN-LT-11', actor: 'rneuman', text: 'Successful logon. Logon type 2. Source 10.0.4.10.', tags: 'noise' },
      { id: 'ev-n10', ts: '08:09:12', code: 4634, kind: 'event', host: 'OPS-WS-09', actor: 'kpatel', text: 'Logoff. Session closed.', tags: 'noise' },
      { id: 'ev-n11', ts: '08:10:26', code: 4672, kind: 'event', host: 'HR-LT-03', actor: 'svega', text: 'Special privileges assigned to new logon.', tags: 'noise' },
      { id: 'ev-n12', ts: '08:11:39', code: 4624, kind: 'event', host: 'ENG-WS-02', actor: 'svega', text: 'Successful logon. Logon type 2. Source 10.0.4.20.', tags: 'noise' },
      { id: 'ev-n13', ts: '08:12:03', code: 4634, kind: 'event', host: 'FIN-LT-11', actor: 'rneuman', text: 'Logoff. Session closed.', tags: 'noise' },
      { id: 'ev-n14', ts: '08:14:22', code: 4624, kind: 'event', host: 'HR-LT-03', actor: 'mchen', text: 'Successful logon. Logon type 2. Source 10.0.4.11.', tags: 'noise' },
      { id: 'ev-n15', ts: '08:16:37', code: 4634, kind: 'event', host: 'ENG-WS-02', actor: 'svega', text: 'Logoff. Session closed.', tags: 'noise' },
      { id: 'ev-n16', ts: '08:17:09', code: 4672, kind: 'event', host: 'FIN-WS-14', actor: 'jdoe', text: 'Special privileges assigned to new logon.', tags: 'noise' },
      { id: 'ev-n17', ts: '08:19:28', code: 4624, kind: 'event', host: 'SALES-LT-11', actor: 'kpatel', text: 'Successful logon. Logon type 2. Source 10.0.4.20.', tags: 'noise' },
      { id: 'ev-n18', ts: '08:21:46', code: 4634, kind: 'event', host: 'SALES-LT-11', actor: 'rneuman', text: 'Logoff. Session closed.', tags: 'noise' },
      { id: 'ev-n19', ts: '08:24:03', code: 4624, kind: 'event', host: 'FIN-LT-11', actor: 'rneuman', text: 'Successful logon. Logon type 2. Source 10.0.4.10.', tags: 'noise' },
      { id: 'ev-n20', ts: '08:26:12', code: 4672, kind: 'event', host: 'HR-LT-03', actor: 'mchen', text: 'Special privileges assigned to new logon.', tags: 'noise' }
    ],

    /* ---------------------------------------------------------------
     * STAGE 1 — EVIDENCE INBOX
     * --------------------------------------------------------------- */
    evidence: [
      {
        id: 'al-5001',
        ref: 'ALERT-01',
        severity: 'high',
        title: 'Windows Defender real-time protection disabled',
        blurb: 'Real-time protection was turned off on sec-win-05 (Event 5001). This should only occur during approved maintenance.',
        detail:
          'Defender Operational Event 5001 — "Antimalware protection disabled". Fields of interest: the process ' +
          'that requested the change, the account under which it ran, and the timestamp. Real-time protection is ' +
          'normally off only inside an approved change window, and only on request from the endpoint team.',
        hint: 'Ask: who turned it off, when, and is there a change record that says they should have?'
      },
      {
        id: 'al-5007',
        ref: 'ALERT-02',
        severity: 'high',
        title: 'Windows Defender exclusion added',
        blurb: 'A folder path exclusion was added to Windows Defender on sec-win-05 (Event 5007). Exclusions prevent files in that path from being scanned.',
        detail:
          'Defender Operational Event 5007 — "Antimalware protection exclusion changed". The excluded path is ' +
          'C:\\Users\\asmith\\AppData\\Local\\Temp. An exclusion is not a policy setting an administrator ' +
          'pre-configures; on a managed workstation it is either a mistake or an instruction to the malware ' +
          'author that this folder will never be inspected.',
        hint: 'Ask: which folder, and is that a folder where a payload would be staged?'
      },
      {
        id: 'al-4688-cmd',
        ref: 'ALERT-03',
        severity: 'medium',
        title: 'Command shell spawned after Defender disabled',
        blurb: 'cmd.exe was spawned on sec-win-05 within 2 minutes of Defender being disabled.',
        detail:
          'Sysmon / Security Event 4688 — "A new process has been created". cmd.exe was created by powershell.exe ' +
          'at 08:06:22, 84 seconds after the exclusion was added. No malware file is visible in the hour, which is ' +
          'consistent with an attacker who is still preparing: the first command after disarming a host is ' +
          'usually to open a shell and start typing.',
        hint: 'Ask: what is the shell for, and what would the attacker do next that we would not have seen?'
      },
      {
        id: 'ev-user',
        ref: 'EVID-04',
        severity: 'info',
        title: 'Account information — asmith',
        blurb: 'Directory record for the account under which the Defender changes were made.',
        detail:
          'asmith — A. Smith, Operations Coordinator, 26 months in post. Group membership: Domain Users, ' +
          'Ops-Read. Not a member of local Administrators and not a member of any software-deployment group, so ' +
          'no scripted deployment would run as this user. Interactive logon history for 90 days: 10.0.4.x and ' +
          'VPN concentrator addresses only. Last password change 96 days ago.',
        hint: 'Ask: does this account have any legitimate route to changing endpoint protection settings?'
      },
      {
        id: 'ev-baseline',
        ref: 'EVID-05',
        severity: 'info',
        title: 'Baseline activity — other hosts this hour',
        blurb: 'Reference traffic and change records for the estate during the same window.',
        detail:
          'No change ticket is open for endpoint maintenance today; the last approved window was three days ago ' +
          'and it covered six named hosts, none of them sec-win-05. In this hour 5 baseline users generated 20 ' +
          'logon, logoff and privilege events across FIN-WS-14, HR-LT-03, ENG-WS-02, OPS-WS-09, FIN-LT-11 and ' +
          'SALES-LT-11. No other host produced a 5001 or a 5007, and no other host ran PowerShell with a ' +
          'Defender preference on the command line.',
        hint: 'Ask: is sec-win-05 the only host where protection changed, and was anyone authorised to change it?'
      }
    ],

    alerts: [
      { name: 'Windows Defender real-time protection disabled', severity: 'high' },
      { name: 'Windows Defender exclusion added', severity: 'high' },
      { name: 'Command shell spawned after Defender disabled', severity: 'medium' }
    ],

    /* ---------------------------------------------------------------
     * STAGE 3 — TIMELINE
     * --------------------------------------------------------------- */
    timeline: [
      { t: 'T+0', ts: '08:01:12', label: 'Logon', detail: "1 successful logon for 'asmith' on sec-win-05 from 203.0.113.45 (compromised session)", net: null },
      { t: 'T+2', ts: '08:03:05', label: 'Process', detail: 'process_created (4688): powershell.exe — Set-MpPreference -DisableRealtimeMonitoring $true', net: null },
      { t: 'T+3', ts: '08:04:31', label: 'Defence', detail: 'windows_defender_disabled (5001) on sec-win-05 — changed by asmith', net: null },
      { t: 'T+3', ts: '08:04:58', label: 'Defence', detail: 'windows_defender_exclusion_added (5007) on sec-win-05 — path C:\\Users\\asmith\\AppData\\Local\\Temp', net: null },
      { t: 'T+5', ts: '08:06:22', label: 'Process', detail: "process_created (4688): cmd.exe spawned by 'asmith' on sec-win-05", net: null }
    ],

    timelineQuestion: {
      id: 'q-timeline',
      prompt: 'What pattern do you see in this sequence?',
      options: [
        { id: 'a', label: 'Routine endpoint maintenance: an administrator disabling protection, adding a vendor exclusion and opening a shell to verify it' },
        { id: 'b', label: 'An antivirus definition problem — Defender disabled itself, then repaired itself' },
        { id: 'c', label: 'A compromised session that disarms endpoint protection, carves out an unscanned folder, and only then opens a command shell — preparation, in that order' },
        { id: 'd', label: 'A user who installed unapproved software and tried to hide it from corporate protection' }
      ],
      correct: ['c'],
      xp: 10,
      explain:
        'The order is what rules out maintenance. In an approved window the change would be scheduled, the ' +
        'account would hold deployment rights, and a verification shell would be expected — here all three are ' +
        'absent, and the sequence runs protection off, exclusion added, shell opened. That is an attacker ' +
        'removing the host\u2019s ability to report what happens next.'
    },

    /* ---------------------------------------------------------------
     * STAGE 4 — CORRELATION BOARD
     * --------------------------------------------------------------- */
    boardNodes: [
      { id: 'n-src', label: '203.0.113.45', sub: 'external source', x: 8, y: 8 },
      { id: 'n-user', label: 'asmith', sub: 'compromised account', x: 8, y: 62 },
      { id: 'n-ps', label: 'powershell.exe', sub: 'Set-MpPreference', x: 40, y: 36 },
      { id: 'n-mp', label: 'real-time protection', sub: 'turned off (5001)', x: 72, y: 8 },
      { id: 'n-excl', label: '…\\AppData\\Local\\Temp', sub: 'excluded (5007)', x: 72, y: 62 },
      { id: 'n-cmd', label: 'cmd.exe', sub: 'shell spawned', x: 40, y: 82 }
    ],
    boardLinks: [
      { from: 'n-src', to: 'n-user', label: 'authenticates as', correct: true },
      { from: 'n-user', to: 'n-ps', label: 'launches', correct: true },
      { from: 'n-ps', to: 'n-mp', label: 'disables', correct: true },
      { from: 'n-ps', to: 'n-excl', label: 'excludes', correct: true },
      { from: 'n-ps', to: 'n-cmd', label: 'executes', correct: true },
      { from: 'n-src', to: 'n-ps', label: 'downloads from', correct: false },
      { from: 'n-mp', to: 'n-cmd', label: 'launches', correct: false }
    ],
    boardXp: 10,

    /* ---------------------------------------------------------------
     * STAGE 5 — ANALYSIS: behaviour, ATT&CK, IoCs
     * --------------------------------------------------------------- */
    behaviourQuestions: [
      {
        id: 'q-persist',
        prompt: 'How would you classify disabling real-time protection and adding a scan exclusion?',
        options: [
          { id: 'a', label: 'Defense evasion — removing the host\u2019s ability to detect or stop what happens next' },
          { id: 'b', label: 'Initial Access — this is how the attacker reached the workstation' },
          { id: 'c', label: 'Impact — the malware has already done its damage' },
          { id: 'd', label: 'Persistence only — the setting survives a reboot, so nothing else matters' }
        ],
        correct: ['a'],
        xp: 10,
        explain:
          'Nothing was exploited to get here and nothing was destroyed yet: the sequence is preparation. Removing ' +
          'the host\u2019s ability to report on, or stop, the next action is textbook defense evasion. The setting ' +
          'does survive a reboot, which is why the fourth option tempts — but durability is not the tactic being ' +
          'used here, and no malware was delivered in this hour either way.'
      },
      {
        id: 'q-ps',
        prompt: 'Why would the attacker add an exclusion for C:\\Users\\asmith\\AppData\\Local\\Temp?',
        options: [
          { id: 'a', label: 'To keep Defender\u2019s scan history from filling the disk' },
          { id: 'b', label: 'To create a folder on this host that will never be scanned — a landing zone for whatever comes next' },
          { id: 'c', label: 'Because Defender is designed not to scan Temp folders' },
          { id: 'd', label: 'To make the exclusion list match a documented Microsoft default' }
        ],
        correct: ['b'],
        xp: 10,
        explain:
          'A scan exclusion is a promise that the path will not be inspected. Pointing that promise at the ' +
          'compromised user\u2019s own Temp directory tells a malware author which path to stage files in — ' +
          'Windows still writes there constantly, and it is the folder most likely to be missed. Defender scans ' +
          'Temp by default, so option C is the comfortable assumption to break.'
      }
    ],

    decodedCommand: {
      encoded: 'asmith 08:03:05 → powershell.exe → 5001 08:04:31 → 5007 08:04:58 → cmd.exe 08:06:22',
      decoded: 'Set-MpPreference -DisableRealtimeMonitoring $true (4688) → real-time protection disabled (5001) → Temp folder excluded from scanning (5007) → command shell started (4688)',
      note:
        'The two Defender event IDs are not two findings. They are the output of one hand-typed command line, and ' +
        'what they produce between them is an unscanned folder on this host — the thing the shell at 08:06:22 is ' +
        'then used to work in.'
    },

    attack: {
      /* the engine renders primary.prompt and alsoPresent.prompt as the question text */
      primary: {
        prompt: 'Which technique best explains this activity?',
        options: [
          { id: 'a', label: 'Impair Defenses: Disable or Modify Tools', meta: 'T1562.001 · Defense Evasion' },
          { id: 'b', label: 'Create or Modify System Process: Windows Defender', meta: 'T1543.003 · Persistence' },
          { id: 'c', label: 'Execution: User Execution', meta: 'T1204 · Execution' },
          { id: 'd', label: 'OS Credential Dumping', meta: 'T1003 · Credential Access' }
        ],
        correct: ['a'],
        xp: 10,
        explain:
          'The defining artifact is a security control being switched off and then configured to look elsewhere, ' +
          'by hand, from a session that should have had no route to endpoint settings. That is Impair Defenses: ' +
          'Disable or Modify Tools, T1562.001. The product is what was disabled, not the technique — replacing ' +
          'Defender with another scanner would still be this technique.'
      },
      alsoPresent: {
        prompt: 'Two other techniques are genuinely present in this activity. Select both.',
        options: [
          { id: 'a', label: 'Command and Scripting Interpreter: PowerShell', meta: 'T1059.001 · Execution' },
          { id: 'b', label: 'Command and Scripting Interpreter: Windows Command Shell', meta: 'T1059.003 · Execution' },
          { id: 'c', label: 'OS Credential Dumping', meta: 'T1003 · Credential Access' },
          { id: 'd', label: 'Indicator Removal: Clear Windows Event Logs', meta: 'T1070.001 · Defense Evasion' }
        ],
        correct: ['a', 'b'],
        xp: 10,
        explain:
          'The work is done through interpreters, not through malware: PowerShell carries the Defender preference ' +
          '(T1059.001) and cmd.exe is the interactive shell it hands over to (T1059.003). The logs were not ' +
          'cleared — every step is still recorded, which is why the case is solvable at all — and no credentials ' +
          'were dumped, so the other two options describe nothing that happened here.'
      }
    },

    iocs: {
      prompt: 'Which of these would you preserve as indicators or investigative pivots?',
      options: [
        { id: 'i1', label: '203.0.113.45', role: 'indicator' },
        { id: 'i2', label: 'Set-MpPreference -DisableRealtimeMonitoring', role: 'indicator' },
        { id: 'i3', label: 'sec-win-05', role: 'context' },
        { id: 'i4', label: 'asmith', role: 'context' },
        { id: 'i5', label: 'Event 5001', role: 'context' },
        { id: 'i6', label: 'protection disabled outside a change window', role: 'behaviour' },
        { id: 'i7', label: 'Temp folder added as a scan exclusion', role: 'behaviour' },
        { id: 'i8', label: 'command shell spawned after the alarm was turned off', role: 'behaviour' }
      ],
      correct: ['indicator', 'behaviour', 'context'],
      xp: 10,
      explain:
        'Two of these eight are things you act on today: the external source 203.0.113.45 (block it and look ' +
        'for other hosts) and the literal command line Set-MpPreference -DisableRealtimeMonitoring, which is a ' +
        'precise hunt signature rather than a description. The behaviours — protection disabled with no change ' +
        'window, an exclusion pointed at a staging folder, a shell spawned inside that window — are the detections ' +
        'worth engineering. sec-win-05, asmith and Event 5001 are context: they scope the incident and tell you ' +
        'where to pivot, but they are not indicators of compromise.'
    },

    /* ---------------------------------------------------------------
     * STAGE 6 — REPORT
     * --------------------------------------------------------------- */
    report: {
      host: {
        prompt: 'Which host is compromised?',
        options: [
          { id: 'a', label: 'sec-win-05' },
          { id: 'b', label: 'FIN-LT-11' },
          { id: 'c', label: 'HR-LT-03' },
          { id: 'd', label: '10.0.4.20' }
        ],
        correct: ['a'],
        xp: 10,
        explain:
          'Every one of the five relevant records belongs to sec-win-05: the external logon, the PowerShell ' +
          'command, both Defender changes and the shell. The other hosts were active in the same hour and produced ' +
          'nothing, and 10.0.4.20 is an address, not a host.'
      },
      what: {
        prompt: 'What happened?',
        options: [
          { id: 'a', label: 'An attacker working in a compromised session for asmith used PowerShell to disable Windows Defender real-time protection, excluded the user\u2019s Temp folder from scanning, and then started a command shell — preparing a host that would no longer report what happened on it.' },
          { id: 'b', label: 'Endpoint maintenance ran out of schedule: an administrator disabled protection across the estate to install an update.' },
          { id: 'c', label: 'A vendor support engineer remotely disabled protection to resolve a ticket, as the process allows.' },
          { id: 'd', label: 'The workstation lost power mid-scan, Defender restarted itself and opened a shell to recover its state.' }
        ],
        correct: ['a'],
        xp: 10,
        explain:
          'The assessment has to name all three actions in order, because each one is evidence for the next: the ' +
          'command line shows intent, the two Defender records show it executed, and the shell shows it was used. ' +
          'A statement that only says protection was disabled misses the staging folder, which is where the ' +
          'malware would be.'
      },
      why: {
        prompt: 'Why is it suspicious? Select every reason that holds.',
        options: [
          { id: 'a', label: 'The changes were made under a standard account with no rights to endpoint settings' },
          { id: 'b', label: 'Real-time protection was disabled at 08:04:31 with no approved change window open' },
          { id: 'c', label: 'A scan exclusion was added 27 seconds later, pointing at the compromised user\u2019s own Temp folder' },
          { id: 'd', label: 'A command shell was spawned 84 seconds after that, inside the window the two changes opened' },
          { id: 'e', label: 'Protection is routinely disabled during patch cycles' },
          { id: 'f', label: 'Users sometimes switch off antivirus to install software' }
        ],
        correct: ['a', 'b', 'c', 'd'],
        xp: 10,
        explain:
          'Every one of the four is anchored to a record or to a fact you were given: an account with no route to ' +
          'the setting, a timestamp outside any authorised window, an exclusion aimed at a staging folder 27 ' +
          'seconds later, and a shell 84 seconds after that. The last two are not reasons — patch cycles do not ' +
          'open interactive shells as standard users, and a user who cannot change a centrally managed setting ' +
          'is not evidence of anything.'
      },
      confidence: {
        prompt: 'Analyst confidence in this assessment',
        options: [
          { id: 'a', label: 'Low' },
          { id: 'b', label: 'Medium' },
          { id: 'c', label: 'High' }
        ],
        correct: ['c'],
        xp: 10,
        explain:
          'The command line, the two Defender records, the change calendar and the account record all agree, and ' +
          'they agree on timing. What is missing — the payload itself — is missing because the attacker is still ' +
          'preparing, and that limits what we can say about intent beyond this host, not whether the tampering ' +
          'happened.'
      },
      actions: {
        prompt: 'Recommended next actions. Select the three that follow from this assessment.',
        options: [
          { id: 'a', label: 'Re-enable real-time protection, remove the Temp exclusion and verify tamper protection and the management policy are still intact' },
          { id: 'b', label: 'Reset asmith\u2019s credentials and revoke active sessions and cached credentials' },
          { id: 'c', label: 'Sweep the estate for 5001 and 5007 events outside approved windows and hunt for the Set-MpPreference command line' },
          { id: 'd', label: 'Reimage every workstation in the operations department as a precaution' },
          { id: 'e', label: 'Remove Windows Defender centrally and rely on network controls instead' },
          { id: 'f', label: 'Suspend change management for a week so the team is not blocked by alerts' }
        ],
        correct: ['a', 'b', 'c'],
        xp: 10,
        explain:
          'First put the alarm back: re-enable protection, delete the exclusion and confirm nothing else was ' +
          'altered, because that also closes the blind spot while you investigate. Second, the account is still ' +
          'the attacker\u2019s — reset it and kill its sessions. Third, this pattern has no reason to exist on one ' +
          'host only, so sweep for the same two events and the same command line. The other three are ' +
          'indiscriminate: they damage availability, remove the control estate-wide, and suppress the detections ' +
          'you would need next.'
      }
    },

    reasoning: {
      prompt: 'Which three pieces of evidence most strongly support your assessment? Select exactly three.',
      options: [
        { id: 'r1', label: 'PowerShell ran Set-MpPreference -DisableRealtimeMonitoring $true in the session opened from 203.0.113.45 (4688)', key: true },
        { id: 'r2', label: 'Real-time protection was disabled 86 seconds later with no approved change window open (5001)', key: true },
        { id: 'r3', label: 'A Temp-folder scan exclusion was added 27 seconds after that (5007)', key: true },
        { id: 'r4', label: 'asmith is a member of Domain Users only', key: false },
        { id: 'r5', label: 'Five baseline users were active on the estate during the same hour', key: false },
        { id: 'r6', label: 'The workstation had definition updates pending that morning', key: false },
        { id: 'r7', label: 'Defender is known to switch itself off on battery power', key: false }
      ],
      correctCount: 3,
      xp: 10,
      explain:
        'No single record proves an attacker: Defender does get disabled, users do open shells, and admins do ' +
        'change settings. What makes this defensible is the command line — it names the setting and sets it to ' +
        'false explicitly — plus the two records that show the change took effect 86 and then 113 seconds later, ' +
        'in a session that came from outside the estate. Three artifacts that only make sense together.'
    },

    /* mirrored verbatim from new.scenario — the dotted keys are kept as written
       there, because this block is the record of what the case is actually made of */
    ground_truth: {
      defender_disabled_events: 1,
      defender_exclusion_added_events: 1,
      powershell_executions: 1,
      target_host: 'sec-win-05',
      attacker_ip: '203.0.113.45',
      event_ids_present: [4624, 4688, 5001, 5007]
    },

    ranking: [
      { min: 90, rank: 'Lead Intelligence Analyst', note: 'You produced defensible intelligence, not just correct answers.' },
      { min: 75, rank: 'Threat Intelligence Analyst', note: 'Strong correlation and a defensible judgment.' },
      { min: 55, rank: 'Junior CTI Investigator', note: 'You found the tampering and explained it. Tighten the correlation and the reporting.' },
      { min: 0, rank: 'Case Officer Trainee', note: 'Re-run the case. Start with Event 5001 and work backwards to the command that caused it.' }
    ],

    assist: {
      nudge: { label: 'Nudge', mult: 0.85, text: 'Ignore how alarming each Defender record looks on its own, and look at what came before them. What was typed?' },
      hint: { label: 'Analyst Hint', mult: 0.7, text: 'One record shows the intent, two show the result, and one shows what happened in the gap. Put them in that order.' },
      explain: { label: 'Explain', mult: 0.5, text: 'A session for asmith from 203.0.113.45 typed Set-MpPreference -DisableRealtimeMonitoring $true into PowerShell at 08:03:05. Real-time protection went off at 08:04:31 (5001), an exclusion was added for C:\\Users\\asmith\\AppData\\Local\\Temp 27 seconds later (5007), and cmd.exe was spawned at 08:06:22 — inside the blind spot those two changes created. That is Impair Defenses: Disable or Modify Tools, T1562.001, executed through PowerShell (T1059.001) and the Windows Command Shell (T1059.003). No payload was captured in this hour, and that absence is part of the finding.' }
    }
  });
})();