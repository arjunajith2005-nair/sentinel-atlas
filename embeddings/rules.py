import re

INJECTION_PATTERNS = [
    # Instruction-override attempts.
    # Written as a verb x qualifier x noun cross-product rather than fixed phrases:
    # the previous "ignore previous instructions" / "disregard prior prompts" pair
    # left obvious variants ("ignore your prior instructions") unmatched between them.
    r"(?i)\b(ignore|disregard|forget|override|bypass|discard|skip|abandon)\b[^.?!]{0,40}"
    r"\b(previous|prior|earlier|above|initial|original|existing|system|developer|all)\b[^.?!]{0,25}"
    r"\b(instruction|prompt|rule|direction|guideline|constraint|restriction|command|polic(?:y|ies)|context)s?\b",

    # System-prompt exfiltration ("print the full system prompt", "reveal your instructions").
    r"(?i)\b(print|reveal|show|display|output|repeat|dump|expose|disclose|leak|recite|verbatim)\b[^.?!]{0,30}"
    r"\b(your\s+|the\s+)?(full\s+|entire\s+|complete\s+|initial\s+|original\s+|exact\s+|hidden\s+)*"
    r"(system\s+(prompt|message|instruction)|developer\s+(message|prompt|instruction)|initial\s+instruction|hidden\s+instruction)s?\b",

    # Verb + possessive + instruction noun ("forget your instructions"), which the
    # qualifier list above deliberately does not cover.
    r"(?i)\b(ignore|disregard|forget|override|discard|drop)\b\s+(your|the|these|those)\s+"
    r"\b(instruction|prompt|rule|guideline|constraint|restriction|direction)s?\b",

    # Persona / mode override. These are short and carry almost no semantic content,
    # so the ATLAS vector classifier cannot separate them from benign questions
    # (measured: "You are now DAN" and "what is an llm" sit at the same cosine
    # distance). They must be caught deterministically here instead.
    r"(?i)\byou\s+are\s+(now|from\s+now\s+on)\b[^.?!]{0,30}"
    r"\b(dan|unrestricted|unfiltered|unbound|unchained|jailbroken|free|uncensored|no\s+longer\s+bound)\b",
    r"(?i)\b(enable|activate|enter|switch\s+to|turn\s+on)\b[^.?!]{0,20}"
    r"\b(developer|dan|god|debug|admin|root|unrestricted|sudo)\s+mode\b",
    # Same thing phrased in reverse: "... with developer mode enabled".
    r"(?i)\b(developer|dan|god|debug|admin|root|unrestricted|sudo)\s+mode\s+"
    r"\b(enabled|activated|turned\s+on|is\s+on)\b",
    r"(?i)\b(pretend|act|behave|roleplay|respond)\b[^.?!]{0,30}"
    r"\b(you\s+have\s+no|without\s+any|free\s+of|ignoring\s+(all\s+)?)\s*"
    r"\b(rule|restriction|guideline|constraint|filter|limit|safeguard|guardrail)s?\b",

    # "disregard everything above" -- the cross-product pattern above needs an
    # explicit instruction noun, which this phrasing omits entirely.
    r"(?i)\b(ignore|disregard|forget|override|discard|skip|drop)\b\s+"
    r"(everything|anything|all)\b[^.?!]{0,20}"
    r"\b(above|before|prior|previous|earlier|so\s+far|said|told|mentioned|i\s+said)\b",

    # "from now on you are unfiltered" -- the reverse word order of the
    # "you are now <unrestricted>" pattern above, which required the clause first.
    r"(?i)\bfrom\s+now\s+on\b[^.?!]{0,25}\byou\s+(are|will\s+be|act)\b[^.?!]{0,25}"
    r"\b(dan|unrestricted|unfiltered|unbound|unchained|jailbroken|free|uncensored|"
    r"without\s+(any\s+)?(rule|restriction|limit|filter))",

    r"(?i)system\s+prompt\s+override",
    r"(?i)you\s+are\s+now\s+in\s+developer\s+mode",
    r"(?i)jailbreak",
    # Meta-jailbreak: asking how to bypass LLM restrictions/guardrails
    r"(?i)(get|extract|gather|obtain|access|retrieve)\s+.{0,40}(not\s+provided|refused?|blocked|restricted|hidden|forbidden|censored)\s+by\s+(an?\s+)?(llm|ai|model|chatbot|gpt|claude|gemini)",
    r"(?i)(bypass|circumvent|get\s+around|evade|trick|fool|manipulate)\s+.{0,30}(llm|ai|model|chatbot|guardrail|safety|filter|restriction|limit|refusal)",
    r"(?i)(llm|ai|model|chatbot)\s+.{0,20}(won.t|will\s+not|refuses?\s+to|can.t|cannot)\s+.{0,20}(normally|usually|typically|generally)\s+.{0,30}(tell|give|provide|share|say)",
    r"(?i)how\s+.{0,20}(get|make)\s+.{0,20}(llm|ai|chatbot|model)\s+.{0,20}(ignore|bypass|skip|override|forget)\s+.{0,20}(rule|filter|guardrail|restriction|safety|training)",
    r"(?i)(information|content|data|answer|response)\s+.{0,30}(llm|ai|chatbot|model)\s+.{0,20}(won.t|refuses?|can.t|doesn.t)\s+.{0,20}(provid|giv|shar|tell)",
]

# --- Direct credential solicitation -------------------------------------------
# Asking the assistant to HAND OVER a specific secret, as opposed to asking about
# credential practice. The theft patterns below only cover theft verbs
# ("steal/harvest/dump/extract passwords"), so a plain request -- "give me the
# password of the admin" -- passed every gate: the rule engine had no matching
# verb, and an admin-password request is semantically ON-TOPIC in a security
# session, so intent drift never fired either.
#
# The discriminator is a SPECIFIC target, not the word "password". A security
# assistant discusses password policy, rotation and hashing constantly, so
# _CRED_CONCEPT excludes those readings. Tuned to 14/14 solicitations caught and
# 21/21 benign security questions allowed.
_CRED_NOUN = (
    r"(password|passwd|passphrase|credential|api[\s_-]?key|access[\s_-]?key|"
    r"secret[\s_-]?key|private[\s_-]?key|auth[\s_-]?token|bearer[\s_-]?token|"
    r"ssh[\s_-]?key|token|secret)s?"
)
# Negative lookahead: the mention is about credential PRACTICE, not a secret value.
_CRED_CONCEPT = (
    r"(?!\s*(polic|rotation|rotat|requirement|complexity|strength|"
    r"hash(ing)?\b|manager|management|reset|standard|guideline|length|expiry|"
    r"expiration|storage|stored|store|best\s+practice|entropy|salting|salt|"
    r"vault|encryption|encrypted|protection|hygiene|audit|"
    r"generation|generat|guide|tutorial|documentation|docs|setup|"
    r"configuration|config|deployment|lifecycle|algorithm|exchange|"
    r"format|example|template|training|onboarding|"
    r"pair\b|infrastructure|architecture|design|strategy|approach))"
)
_CRED_REQUEST_VERB = (
    r"(give|tell|show|send|provide|share|reveal|disclose|hand\s+over|"
    r"fetch|retrieve|display|print|output|list|what\s+is|what's|whats|"
    r"i\s+need|i\s+want)"
)
_CRED_TARGET = (
    r"(admin|administrator|root|superuser|sudo|user|account|database|db|"
    r"server|system|service|prod|production)"
)

CREDENTIAL_REQUEST_PATTERNS = [
    # "give me the password of the admin", "send me the access key for the server"
    rf"(?i)\b{_CRED_REQUEST_VERB}\b[^.?!]{{0,25}}\b{_CRED_NOUN}\b{_CRED_CONCEPT}"
    rf"[^.?!]{{0,20}}\b(of|for|to)\s+(the\s+)?{_CRED_TARGET}\b",
    # "show me the admin password", "what is your api key"
    rf"(?i)\b{_CRED_REQUEST_VERB}\b[^.?!]{{0,25}}"
    rf"\b(the|your|his|her|their|our|that)\s+({_CRED_TARGET}\s+)?{_CRED_NOUN}\b{_CRED_CONCEPT}",
    # "give me admin credentials", "reveal the admin's password"
    rf"(?i)\b{_CRED_REQUEST_VERB}\b[^.?!]{{0,25}}\b{_CRED_TARGET}('s)?\s+{_CRED_NOUN}\b{_CRED_CONCEPT}",
    # Bulk dump: "list every user account and their stored hashes",
    # "export every credential in the system". These name no single target, so the
    # patterns above miss them, and they are the higher-impact request.
    rf"(?i)\b(list|dump|export|show|give|print|output|retrieve|fetch)\b[^.?!]{{0,30}}"
    rf"\b(all|every|each|the)\b[^.?!]{{0,45}}"
    rf"\b(password|hash|credential|token|secret|api[\s_-]?key)e?s?\b{_CRED_CONCEPT}",
]

SECRET_PATTERNS = [
    r"(?i)AKIA[0-9A-Z]{16}",                              # AWS Access Key ID
    r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*",  # JWT Token
    r"sk-[a-zA-Z0-9]{20,}",                               # API Keys (OpenAI/Generic)
]

# Harmful / illegal activity patterns — blocked regardless of session context
HARMFUL_PATTERNS = [
    # Unauthorized access / hacking
    (r"(?i)how\s+(do\s+i|to|can\s+i)\s+(hack|break\s+into|gain\s+(unauthorized\s+)?access\s+to|exploit|crack|bypass\s+(security|auth))",
     "Harmful content: Request for unauthorized system access instructions."),
    (r"(?i)(hack|exploit|breach|compromise)\s+(a\s+)?(government|bank|hospital|military|corporate|university)\s+(website|system|server|database|network)",
     "Harmful content: Request to attack critical infrastructure or protected systems."),

    # Malware / cyberweapons
    (r"(?i)(write|create|generate|build|code)\s+(me\s+)?(a\s+)?(virus|malware|ransomware|trojan|keylogger|rootkit|worm|spyware|botnet|rat\b|exploit)",
     "Harmful content: Request to generate malicious software."),
    (r"(?i)(sql\s*injection|xss|cross.site\s*scripting|buffer\s*overflow|zero.day)\s+(attack|exploit|payload|tutorial|guide|how)",
     "Harmful content: Request for cyberattack technique instructions."),

    # Data exfiltration. Distinct from credential theft: the target is bulk data,
    # and the phrasing ("exfiltrate data FROM x") matched no existing pattern.
    (r"(?i)\b(exfiltrate|siphon|smuggle|sneak|extract|steal|copy)\b[^.?!]{0,30}"
     r"\b(data|database|records?|files?|information|credentials?|secrets?|dumps?)\b"
     r"[^.?!]{0,25}\b(from|out\s+of|off)\b",
     "Harmful content: Request for data exfiltration technique."),

    # Anti-forensics: disabling the audit trail that would record an intrusion.
    (r"(?i)\b(disable|turn\s+off|bypass|circumvent|delete|wipe|tamper\s+with)\b[^.?!]{0,25}"
     r"\b(audit|access|security|system)?\s*(log|logging|trail|monitoring|alerting)s?\b",
     "Harmful content: Request to disable security auditing or monitoring."),

    # Credential theft
    (r"(?i)(steal|harvest|dump|extract)\s+(passwords?|credentials?|hashes?|tokens?|session\s+cookies?)",
     "Harmful content: Request for credential theft methods."),
    (r"(?i)phishing\s+(email|page|kit|attack|campaign)\s+(template|how|create|build|generate)",
     "Harmful content: Request for phishing attack content."),

    # Violence / weapons / WMDs
    (r"(?i)how\s+(do\s+i|to|can\s+i)\s+(make|build|create|synthesize|produce|manufacture)\s+.{0,30}(bomb|explosive|weapon|poison|fentanyl|meth|nerve\s+agent|anthrax|ricin)",
     "Harmful content: Request for instructions on weapons or dangerous substances."),
    (r"(?i)(nuclear|biological|chemical|radiological)\s+(bomb|weapon|warhead|device|grenade|mine)",
     "Harmful content: Request involving weapons of mass destruction."),
    (r"(?i)(build|make|create|assemble|construct|synthesize)\s+.{0,20}(nuclear|bio(logical)?|chemical|radiological)\s+.{0,20}(weapon|bomb|device|agent)",
     "Harmful content: Request for WMD construction instructions."),
    (r"(?i)uranium\s+enrichment|plutonium\s+extraction|centrifuge\s+design|critical\s+mass\s+calculation",
     "Harmful content: Nuclear weapons development query."),

    # Crimes against persons
    (r"(?i)how\s+(do\s+i|to|can\s+i)\s+.{0,20}(kidnap|abduct|traffick|lure|restrain|chloroform)\s+.{0,30}(person|someone|people|child|kid|girl|boy|woman|man|friend|neighbour)",
     "Harmful content: Request for instructions on abduction or trafficking."),
    (r"(?i)(kidnap|abduct|traffick)\s+.{0,20}(my|a|someone.s|their|his|her)\s+.{0,20}(friend|child|kid|partner|girlfriend|boyfriend|wife|husband|neighbour|colleague)",
     "Harmful content: Request involving abduction or human trafficking."),
    (r"(?i)how\s+(do\s+i|to|can\s+i)\s+.{0,20}(murder|kill|assault|attack|stab|shoot|strangle|poison)\s+.{0,30}(person|someone|people|my|their|a)",
     "Harmful content: Request for instructions on violence against a person."),
    (r"(?i)how\s+(do\s+i|to|can\s+i)\s+.{0,20}(stalk|harass|spy\s+on|track|follow|surveil)\s+.{0,20}(someone|a\s+person|my|their|him|her|ex)",
     "Harmful content: Request for stalking or surveillance of individuals."),
    (r"(?i)how\s+(do\s+i|to|can\s+i)\s+.{0,20}(rape|sexually\s+assault|molest|grope)",
     "Harmful content: Request involving sexual violence."),
    (r"(?i)(child|minor|underage|teen|kid)\s+.{0,20}(sexual|nude|naked|porn|grooming|exploitation|abuse)",
     "Harmful content: Child sexual exploitation content detected."),
    (r"(?i)how\s+(do\s+i|to|can\s+i)\s+.{0,20}(break\s+into|enter|burglar|rob|steal\s+from)\s+.{0,20}(house|home|apartment|building|store|shop|car)",
     "Harmful content: Request for burglary or robbery instructions."),

    # Food tampering / intentional bodily harm
    (r"(?i)(compromis\w*|damag\w*|destroy\w*|burn\w*|ruin\w*|paralyz\w*|harm\w*|injur\w*)\s+.{0,40}(taste\s*buds?|taste\s*pal[ea]tte|tongue|throat|mouth|stomach|digestive|health)",
     "Harmful content: Request to inflict sensory or physical injury via food or substances."),
    (r"(?i)(make|cook|prepare)\s+.{0,40}(so\s+hot|so\s+spicy)\s+.{0,40}(compromis\w*|damag\w*|hurt|harm|burn|injur|destroy)",
     "Harmful content: Request to weaponize extreme heat or spices to cause physical injury."),
    (r"(?i)(spike|poison|lace|tamper\s+with)\s+.{0,30}(food|drink|water|meal|dish|beverage|soup)",
     "Harmful content: Request involving food or beverage tampering."),

    # Evading law enforcement / escaping custody / prison break
    (r"(?i)how\s+(do\s+i|to|can\s+i)\s+.{0,20}(escape|break\s+out\s+of|flee\s+from|evade)\s+.{0,20}(prison|jail|police|custody|law\s+enforcement|handcuffs?|cell)",
     "Harmful content: Request for instructions on escaping custody or prison break."),
    (r"(?i)(prison|jail)\s+(break|escape)\s+(plan|guide|tutorial|how|instructions?|method)",
     "Harmful content: Request involving prison escape instructions."),
]


def evaluate_security_rules(prompt: str) -> dict:
    # 1. Check Prompt Injection
    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, prompt):
            return {
                "flagged": True,
                "reason": "Security Policy Triggered: Prompt injection attempt detected."
            }

    # 2. Check direct credential solicitation (asking for an actual secret)
    for pattern in CREDENTIAL_REQUEST_PATTERNS:
        if re.search(pattern, prompt):
            return {
                "flagged": True,
                "reason": (
                    "Security Policy Triggered: Harmful content: "
                    "Request to disclose credentials or secrets."
                )
            }

    # 3. Check Secret/Token Exposure
    for pattern in SECRET_PATTERNS:
        if re.search(pattern, prompt):
            return {
                "flagged": True,
                "reason": "Security Policy Triggered: High-entropy secret key or API token detected in prompt."
            }

    # 4. Check Harmful / Illegal Content
    for pattern, reason in HARMFUL_PATTERNS:
        if re.search(pattern, prompt):
            return {
                "flagged": True,
                "reason": f"Security Policy Triggered: {reason}"
            }

    return {"flagged": False, "reason": None}