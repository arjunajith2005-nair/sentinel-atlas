import re

INJECTION_PATTERNS = [
    r"(?i)ignore\s+(all\s+)?previous\s+instructions",
    r"(?i)disregard\s+(all\s+)?prior\s+prompts",
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

    # 2. Check Secret/Token Exposure
    for pattern in SECRET_PATTERNS:
        if re.search(pattern, prompt):
            return {
                "flagged": True,
                "reason": "Security Policy Triggered: High-entropy secret key or API token detected in prompt."
            }

    # 3. Check Harmful / Illegal Content
    for pattern, reason in HARMFUL_PATTERNS:
        if re.search(pattern, prompt):
            return {
                "flagged": True,
                "reason": f"Security Policy Triggered: {reason}"
            }

    return {"flagged": False, "reason": None}