"""Threat-actor taxonomy for the Russia-Ukraine hacktivism dashboard.

The extraction in `analysis.ipynb` labels any capitalised noun phrase near an attack
as a `group`, so the raw output mixes real actors with attack techniques, nationality
adjectives and the names of the outlets that ran the story. This module does three
things to the raw group strings:

1. `DROP_EXACT` / `DROP_PATTERNS` remove the non-actors.
2. `ALIASES` merge spelling variants onto one canonical actor.
3. `ALIGNMENT` hand-codes each canonical actor's side in the war.

Alignment is editorial, not extracted: it is coded from public reporting and
threat-intelligence naming (CISA, ENISA, Mandiant, Recorded Future, ESET and the
groups' own Telegram channels), and every actor not listed here falls through to
`unaligned`. Treat it as a coding sheet to argue with, not as ground truth - the
`sides` key in each entry records why the actor was coded the way it was.
"""

import re

# --- 1. not actors --------------------------------------------------------------

def key(name):
    """Comparison key: case, spacing and punctuation carry no meaning in these strings."""
    return re.sub(r'[^a-z0-9]', '', name.lower())


# Attack techniques, malware families, botnets, generic nouns and the names of
# publications and vendors that reported the story.
DROP_EXACT = {
    # the technique the whole dataset is about
    'ddos', 'ddosattack', 'ddosattacks', 'dos', 'dosattack', 'ddo', 'ddos2', 'ddosing',
    'distributeddenialofservice', 'distributeddenialofserviceddos', 'ddosprotection',
    'distributeddenialofserviceattack', 'distributeddenialofserviceattacks',
    'denialofservice', 'denialofserviceddos', 'denialofserviceattack', 'ddosforhire',
    # malware and botnets, not actors
    'malware', 'ransomware', 'botnet', 'phishing', 'wipermalware', 'mirai', 'meris',
    'danabot', 'cyclopsblink', 'solorigate', 'industroyer', 'notpetya', 'emotet',
    # generic descriptors
    'hackers', 'hacker', 'hacking', 'hackergroup', 'hackergroups', 'group', 'groups',
    'hacktivists', 'hacktivist', 'hacktivism', 'hacktivistgroup', 'hacktivistgroups',
    'attackers', 'attacker', 'cyberattack', 'cyberattacks', 'cybercriminals',
    'threatactors', 'threatactor', 'actors', 'apt', 'aptgroup', 'unknown', 'unknownactor',
    'cybercrime', 'cybercriminal', 'statesponsoredhackers', 'nationstate',
    # platforms, vendors and outlets
    'telegram', 'twitter', 'x', 'cloudflare', 'akamai', 'microsoft', 'google',
    'gbhackers', 'zataz', 'oodaloop', 'bleepingcomputer', 'securityaffairs',
    'thehackernews', 'reuters', 'scmedia', 'theregister', 'securityboulevard',
    'bankinfosecurity', 'siliconuk', 'infosecurity', 'cybernews', 'hackread',
}

# Nationality or allegiance adjectives with no named actor behind them. These are
# dropped rather than folded into a side: "pro-Russian hackers" tells us the side but
# not the actor, and counting it as one would inflate every pro-Russian figure.
DROP_PATTERNS = [
    re.compile(
        r'^(pro)?(russian?|ukrainian?|chinese|iranian|israeli|american|turkish|indian|'
        r'pakistani|belarusian|serbian|polish|northkorean|palestinian|moscow|kremlin)'
        r'(speaking|linked|backed|aligned|based|state|government|military|intelligence)?'
        r'(hackers?|hackergroups?|hackinggroups?|groups?|hacktivists?|hacktivistgroups?|'
        r'cybergroups?|threatactors?|actors?|collective|cybercriminals?|forces)?$'),
    re.compile(r'^(russia|ukraine|china|iran|israel|kremlin|nato|eu|us|usa|uk|'
               r'unitedstates|europe|west|thewest)$'),
    re.compile(r'^(russians|ukrainians|unitedrussia|russiangovernment|'
               r'ukrainiangovernment|ukrainesmilitary)$'),
]


# --- 2. one actor, one name -----------------------------------------------------

ALIASES = {
    # pro-Russian hacktivist collectives
    'killnet': 'Killnet', 'killnets': 'Killnet', 'killnetgroup': 'Killnet',
    'russiankillnet': 'Killnet', 'killmilk': 'Killnet', 'killnetcollective': 'Killnet',
    'legion': 'Killnet', 'legioncyberspetsnaz': 'Killnet',  # Killnet sub-unit
    'noname': 'NoName057(16)', 'noname057': 'NoName057(16)', 'noname57': 'NoName057(16)',
    'noname05716': 'NoName057(16)', 'nonameo5716': 'NoName057(16)',
    'ddosia': 'NoName057(16)',  # NoName's crowdsourced attack tool
    'anonymousrussia': 'Anonymous Russia',
    'anonymoussudan': 'Anonymous Sudan', 'stormm1359': 'Anonymous Sudan',
    'storm1359': 'Anonymous Sudan',
    'russiancyberarmy': 'Cyber Army of Russia Reborn',
    'russiancyberarmyteam': 'Cyber Army of Russia Reborn',
    'russiancyberarmyreborn': 'Cyber Army of Russia Reborn',
    'cyberarmyofrussiareborn': 'Cyber Army of Russia Reborn',
    'cyberarmyrussiareborn': 'Cyber Army of Russia Reborn',
    'cyberarmyofrussia': 'Cyber Army of Russia Reborn',
    'carr': 'Cyber Army of Russia Reborn',
    'peoplescyberarmy': 'Cyber Army of Russia Reborn',
    'digitalrussia': 'Digital Russia', 'overflame': 'OverFlame',
    'zpentest': 'Z-Pentest', 'usersec': 'UserSec', 'phoenix': 'Phoenix',
    'cybervolk': 'CyberVolk', 'digitalmatrix': 'Digital Matrix',
    'from64': 'From Russia with Love', 'xakn3t': 'Xaknet', 'xaknet': 'Xaknet',

    # pro-Ukrainian hacktivist collectives
    'itarmy': 'IT Army of Ukraine', 'itarmyofukraine': 'IT Army of Ukraine',
    'ukrainianitarmy': 'IT Army of Ukraine', 'ukrainesitarmy': 'IT Army of Ukraine',
    'ukraineitarmy': 'IT Army of Ukraine', 'itarmyukraine': 'IT Army of Ukraine',
    'ukrainiancyberalliance': 'Ukrainian Cyber Alliance',
    'ukrainiancyberarmy': 'Ukrainian Cyber Alliance',
    'patriotsofukraine': 'Patriots of Ukraine',
    'squad303': 'Squad303', 'teamonefist': 'Team OneFist', 'boteam': 'BO Team',
    'cyberpartisans': 'Belarusian Cyber Partisans',
    'belarusiancyberpartisans': 'Belarusian Cyber Partisans',
    'anonymous': 'Anonymous', 'anonymouscollective': 'Anonymous',
    'distributeddenialofsecrets': 'Distributed Denial of Secrets', 'ddosecrets':
        'Distributed Denial of Secrets',

    # state services
    'hur': 'HUR (Ukraine military intelligence)',
    'gur': 'HUR (Ukraine military intelligence)',
    'diu': 'HUR (Ukraine military intelligence)',
    'ukrainianintelligence': 'HUR (Ukraine military intelligence)',
    'ukrainesmilitaryintelligence': 'HUR (Ukraine military intelligence)',
    'ukrainianmilitaryintelligence': 'HUR (Ukraine military intelligence)',
    'ukrainesintelligenceagency': 'HUR (Ukraine military intelligence)',
    'ukrainesdefenceintelligence': 'HUR (Ukraine military intelligence)',
    'sbu': 'SBU (Ukraine security service)',
    'ukrainiansecurityservice': 'SBU (Ukraine security service)',
    'gru': 'GRU (Russian military intelligence)',
    'fsb': 'FSB (Russian security service)',
    'svr': 'SVR (Russian foreign intelligence)',
    'sandworm': 'Sandworm (GRU Unit 74455)', 'unit74455': 'Sandworm (GRU Unit 74455)',
    'fancybear': 'Fancy Bear (APT28)', 'apt28': 'Fancy Bear (APT28)',
    'cozybear': 'Cozy Bear (APT29)', 'apt29': 'Cozy Bear (APT29)',
    'gamaredon': 'Gamaredon', 'turla': 'Turla',

    # criminal
    'lockbit': 'LockBit', 'revil': 'REvil', 'conti': 'Conti',
    'scatteredspider': 'Scattered Spider', 'blackcat': 'BlackCat/ALPHV',
    'alphv': 'BlackCat/ALPHV', 'cl0p': 'Cl0p', 'clop': 'Cl0p',

    # other
    'hamas': 'Hamas', 'ddosguard': 'DDoS-Guard', 'koddos': 'KoDDoS',
    'operationeastwood': 'Operation Eastwood',  # law-enforcement takedown, not an actor
}


# --- 3. which side -------------------------------------------------------------

PRO_RU = 'pro-Russian hacktivist'
PRO_UA = 'pro-Ukrainian hacktivist'
RU_STATE = 'Russian state-linked'
UA_STATE = 'Ukrainian state-linked'
CRIMINAL = 'criminal'
OTHER = 'unaligned'

# canonical name -> (alignment, short note on the coding)
ALIGNMENT = {
    'Killnet': (PRO_RU, 'Pro-Kremlin collective formed Jan 2022; DDoS against NATO states'),
    'NoName057(16)': (PRO_RU, 'Runs the crowdsourced DDoSia project against Ukraine and its allies'),
    'Anonymous Russia': (PRO_RU, 'Killnet-affiliated Telegram collective'),
    'Anonymous Sudan': (PRO_RU, 'Assessed as Russia-aligned despite the name; allied with Killnet'),
    'Cyber Army of Russia Reborn': (PRO_RU, 'Linked by Mandiant to Sandworm/APT44'),
    'Digital Russia': (PRO_RU, 'Pro-Kremlin Telegram collective'),
    'OverFlame': (PRO_RU, 'Pro-Russian DDoS collective'),
    'Z-Pentest': (PRO_RU, 'Pro-Russian group targeting OT/ICS in NATO states'),
    'UserSec': (PRO_RU, 'Pro-Russian collective, NoName ally'),
    'Phoenix': (PRO_RU, 'Pro-Russian collective'),
    'CyberVolk': (PRO_RU, 'India-based, publicly pro-Russian'),
    'Digital Matrix': (PRO_RU, 'Pro-Russian DDoS collective'),
    'From Russia with Love': (PRO_RU, 'Pro-Russian collective'),
    'Xaknet': (PRO_RU, 'Pro-Russian collective active against Ukraine since 2022'),

    'IT Army of Ukraine': (PRO_UA, 'Volunteer DDoS army called up by Ukraine\'s government Feb 2022'),
    'Ukrainian Cyber Alliance': (PRO_UA, 'Volunteer collective active since 2016'),
    'Patriots of Ukraine': (PRO_UA, 'Pro-Ukrainian collective'),
    'Squad303': (PRO_UA, 'Polish collective supporting Ukraine'),
    'Team OneFist': (PRO_UA, 'International volunteer collective'),
    'BO Team': (PRO_UA, 'Pro-Ukrainian collective, works alongside HUR'),
    'Belarusian Cyber Partisans': (PRO_UA, 'Anti-Lukashenko, anti-invasion collective'),
    'Anonymous': (PRO_UA, '#OpRussia from Feb 2022; the brand is open, so coding is loose'),
    'Distributed Denial of Secrets': (PRO_UA, 'Leak publisher; hosted the 2022 Russian leaks'),

    'GRU (Russian military intelligence)': (RU_STATE, 'State service'),
    'FSB (Russian security service)': (RU_STATE, 'State service'),
    'SVR (Russian foreign intelligence)': (RU_STATE, 'State service'),
    'Sandworm (GRU Unit 74455)': (RU_STATE, 'GRU unit'),
    'Fancy Bear (APT28)': (RU_STATE, 'GRU-attributed'),
    'Cozy Bear (APT29)': (RU_STATE, 'SVR-attributed'),
    'Gamaredon': (RU_STATE, 'FSB-attributed, Crimea-based'),
    'Turla': (RU_STATE, 'FSB-attributed'),

    'HUR (Ukraine military intelligence)': (UA_STATE, 'State service'),
    'SBU (Ukraine security service)': (UA_STATE, 'State service'),

    'LockBit': (CRIMINAL, 'Ransomware-as-a-service'),
    'REvil': (CRIMINAL, 'Ransomware-as-a-service'),
    'Conti': (CRIMINAL, 'Ransomware; declared support for Russia Feb 2022'),
    'BlackCat/ALPHV': (CRIMINAL, 'Ransomware-as-a-service'),
    'Cl0p': (CRIMINAL, 'Ransomware / extortion'),
    'Scattered Spider': (CRIMINAL, 'Financially motivated intrusion set'),
    'Hamas': (OTHER, 'Unrelated conflict'),
    'DDoS-Guard': (OTHER, 'Russian hosting provider; appears as infrastructure, not attacker'),
    'KoDDoS': (OTHER, 'Hosting provider'),
    'Operation Eastwood': (OTHER, 'Europol takedown operation against NoName057(16)'),
}

# Which alignments count as hacktivism for the "hacktivist actors only" filter.
HACKTIVIST = {PRO_RU, PRO_UA}

# Russia's full-scale invasion. Used to split the data into pre-war and war phases.
INVASION = '2022-02-24'


def is_dropped(name):
    k = key(name)
    return not k or k in DROP_EXACT or any(p.match(k) for p in DROP_PATTERNS)


def alias(name):
    """Canonical name for a raw group string, or None if it is not an actor."""
    if is_dropped(name):
        return None
    return ALIASES.get(key(name))


def alignment_of(name):
    return ALIGNMENT.get(name, (OTHER, None))[0]


def note_of(name):
    return ALIGNMENT.get(name, (OTHER, None))[1]
