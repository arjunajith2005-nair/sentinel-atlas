# Sentinel ATLAS — Simple Build Guide for a 4-Person Team

**The idea in one sentence:** you're building a "security guard" that sits between a user and an AI chatbot, watches whether the conversation is drifting away from what the user originally asked for, and raises alarms if it looks like an attack.

Difficulty ratings on every task: 🟢 Easy · 🟡 Medium · 🔴 Hard — so you know where to expect trouble and can put your strongest person there.

---

## Step 1: Split into 4 Roles

Think of the system as a pipeline. A message flows through 4 stages, and each person owns one stage:

```
User message
   ↓
[A] Gateway — receives it, stores it
   ↓
[B] Detection — checks if it's drifting from the original intent
   ↓
[C] Intelligence — matches it to known attacks, scores the risk
   ↓
[D] Dashboard — shows a human what's happening, reacts if needed
```

| Person | Nickname | What they own |
|---|---|---|
| **A** | "The Front Door" | The proxy that forwards messages, and the database that stores conversations |
| **B** | "The Detector" | Turning messages into numbers (embeddings), measuring drift, running a second AI as a checker |
| **C** | "The Analyst" | Matching flagged messages to known attack patterns, calculating a final risk score |
| **D** | "The Screen" | The dashboard a human watches, plus testing the whole system with fake attacks |

---

## Step 0: Everyone Does This First (Day 1) — 🟢 Easy

Before splitting up:
- Install Python 3.10+, set up a virtual environment.
- Install: `fastapi`, `uvicorn`, `sentence-transformers`, `chromadb`, `ollama`, `streamlit`, `numpy`, `scipy`.
- Install Ollama (a free local AI app) and download a small model like `llama3.2`.
- **As a group**, agree on one simple thing: what columns go in the database table that stores every message. Suggestion:
  `session_id | turn_number | message_text | embedding | drift_score | timestamp`

This one step matters more than it looks — if everyone agrees on this table upfront, the 4 people can work separately without stepping on each other.

---

## Person A: The Front Door

*Job in plain English: be the mail carrier. Take the message, pass it to the AI, save a copy, hand back the reply.*

| Task | What it means | Difficulty |
|---|---|---|
| Build a `/chat` endpoint | A single web address that receives a message and forwards it to a real AI | 🟢 Easy |
| Add failover | If something breaks, still try to reach the AI directly so the user isn't stuck | 🟢 Easy |
| Generate session IDs | Give each conversation a unique code (like a ticket number) | 🟢 Easy |
| Build the database layer | Save every message + its data into SQLite | 🟡 Medium |
| Build the "playbooks" (sanitize/reset/revoke) | Write the code that actually reacts once a risk score is high — strip the message down, wipe the session, or block it entirely | 🟡 Medium |
| Wire everything together | Make sure the gateway actually calls Person C's risk score after every message | 🔴 Hard — this is the glue that holds the whole pipeline together, so bugs here break everything downstream |

---

## Person B: The Detector

*Job in plain English: figure out if the conversation is wandering away from what the user first asked for — and double-check the AI's answers with a second, independent AI.*

| Task | What it means | Difficulty |
|---|---|---|
| Turn text into embeddings | Use a pre-built model (`all-MiniLM-L6-v2`) to convert each message into a list of numbers representing its meaning | 🟢 Easy — it's mostly calling a library, not building math yourself |
| Set the "anchor" | Decide what the very first message(s) were "really about," to compare everything else against | 🟡 Medium — the tricky part is handling short first messages (wait for message 2 and blend them) |
| Calculate drift | Measure how far each new message has moved from the anchor, using cosine similarity | 🟡 Medium |
| Rolling average of drift | Instead of one score, average the last 4 turns so a single weird message doesn't trigger a false alarm | 🟡 Medium |
| Build the second AI checker ("Auditor") | Send the anchor + the AI's proposed answer to a local model and ask "does this still match what the user wanted?" | 🔴 Hard — requires running this in the background (async) so it doesn't slow down the user's actual response |
| IAA score | A numeric version of the same alignment check, using embeddings instead of asking an AI | 🟡 Medium |

---

## Person C: The Analyst

*Job in plain English: once something looks suspicious, figure out what kind of attack it resembles, and boil everything down into one risk number.*

| Task | What it means | Difficulty |
|---|---|---|
| Download MITRE ATLAS technique list | A public list of known AI attack types, with descriptions | 🟢 Easy |
| Build the ATLAS search index | Convert each technique description into an embedding and store it in ChromaDB (a small vector database) | 🟡 Medium |
| Match flagged messages to techniques | When something is flagged, search the index for the closest-matching attack type | 🟡 Medium |
| Assign "sensitivity" values | Decide, by hand, which attack types are more dangerous (e.g. data theft ranks higher than harmless role-play) | 🟢 Easy — mostly judgment calls, not code |
| Build the risk formula | Combine attack-match confidence, sensitivity, past flags, and drift into one score | 🔴 Hard — this depends on everyone else's outputs being correct first, and the weights need real tuning to feel right |
| Tune the weights | After testing, adjust how much each factor counts | 🟡 Medium — needs real test data from Person D to do properly |

---

## Person D: The Screen

*Job in plain English: build the control-room screen a human watches, and write the fake attacks that prove the whole system actually works.*

| Task | What it means | Difficulty |
|---|---|---|
| Basic dashboard | A Streamlit page showing a table of active conversations | 🟢 Easy |
| Risk score chart | A line chart of one conversation's risk score over time | 🟢 Easy |
| Attack-type heatmap | A chart showing which attack types get flagged most often | 🟡 Medium |
| "Mark as False Positive" button | Lets a human override a false alarm and unblock a session | 🟡 Medium |
| Write ~10-15 fake attack conversations | Some genuinely adversarial, some innocent but topic-shifting, to test both real detection and false alarms | 🟡 Medium — writing genuinely convincing test cases takes real thought, not just typing random messages |
| Run the full evaluation | Send every test conversation through the whole system and record what got caught, missed, or wrongly flagged | 🔴 Hard — this only works once all 3 other people's pieces are done and correctly connected, so it's the highest-pressure, most failure-prone step |

---

## Suggested Order (so nobody's blocked waiting on someone else)

**Week 1 — build the easy, independent pieces first**
- A builds the basic proxy + database
- B builds embeddings + drift (doesn't need anyone else's code yet)
- C downloads ATLAS list + builds the search index (also independent)
- D builds a bare dashboard reading straight from A's database

**Week 2 — build the pieces that depend on each other**
- B adds the second-AI checker (needs A's proxy working)
- C builds the risk formula (needs B's drift score)
- A builds the reaction playbooks (needs C's risk score)
- D wires the dashboard to real scores + writes test conversations

**Week 3 — put it all together**
- Everyone runs the full pipeline together, fixes bugs
- D leads the evaluation run
- C tunes the risk weights based on results

---

## Where Things Are Likely to Go Wrong (🔴 Hard tasks, ranked)

1. **A's "wire everything together" step** — one broken connection here and nothing downstream works. Test this early and often, even with fake/random scores.
2. **B's async Auditor** — running a second AI call without slowing down the user's chat is the trickiest bit of engineering in the whole project.
3. **C's risk formula** — it's only as good as B and A's outputs, so don't start tuning it until those are stable.
4. **D's full evaluation** — needs everything else finished first; leave real time buffer for this at the end, don't squeeze it into the last day.

If you're short on time, it's fine to keep C's weights as a flat starting point (equal weighting) and only tune them if there's time left after Step 8's testing.
