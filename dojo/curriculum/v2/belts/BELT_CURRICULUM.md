# Belt Curriculum: Learning Through Meaningful Challenges

> Each belt level presents increasingly complex meaningful challenges that develop
> Critical Thinking, Creativity, Collaboration, and Communication through authentic problem-solving.

## Curriculum Design Principles

1. **No Lectures**: Every concept is taught through challenges, not exposition
2. **Authentic Stakes**: Challenges mirror real-world security problems
3. **4C Integration**: Each challenge develops multiple competencies
4. **Progressive Complexity**: Belts build on each other
5. **Meaningful Failure**: Wrong approaches teach transferable lessons

---

## White Belt: Foundations Through Discovery

**Theme**: "Question Everything You're Told"

### Competency Focus
- **Critical Thinking**: Primary - Learn to verify claims
- **Communication**: Secondary - Document what you find

### Meaningful Challenges

#### WB-01: "The Secure App" (Critical Thinking)
```yaml
scenario: |
  A developer claims their app is "completely secure" because:
  - Passwords are "encrypted"
  - Data is stored "safely"
  - Network traffic is "protected"

  You have the APK. Verify or refute each claim.

authentic_stakes: |
  Developers make these claims constantly. Your job is to verify, not trust.

discovery_required: |
  - What does "encrypted" actually mean in this implementation?
  - Where is data actually stored?
  - How is traffic actually protected?

multiple_approaches:
  - Static analysis of decompiled code
  - Runtime observation with Frida
  - Network traffic analysis
  - File system inspection

failure_teaches:
  - Accepting claims at face value leads to missed vulnerabilities
  - "Secure" is meaningless without specific, verifiable properties

4c_development:
  critical_thinking: "Verify claims against evidence"
  communication: "Document findings with proof"
```

#### WB-02: "The Documentation Says..." (Critical Thinking)
```yaml
scenario: |
  Official documentation claims an API endpoint requires authentication.
  Test this claim against the actual implementation.

authentic_stakes: |
  Documentation lies. Code is truth. Security depends on verifying.

discovery_required: |
  Does the server actually enforce what docs claim?

transfer_principle: |
  Never trust documentation. Test actual behavior.
```

#### WB-03: "Explain Like I'm New" (Communication)
```yaml
scenario: |
  You've found that an app stores sensitive data in plaintext SharedPreferences.
  Explain this to:
  1. A developer who needs to fix it
  2. A manager who needs to prioritize it
  3. A new security learner who needs to understand why it matters

authentic_stakes: |
  Findings are worthless if you can't communicate them effectively.

assessment: |
  - Can the developer fix it from your explanation?
  - Can the manager make the right priority decision?
  - Can the learner apply this knowledge elsewhere?
```

---

## Yellow Belt: Patterns and Transfer

**Theme**: "See the Pattern, Apply It Elsewhere"

### Competency Focus
- **Critical Thinking**: Recognize patterns across different contexts
- **Creativity**: Apply known patterns to new situations

### Meaningful Challenges

#### YB-01: "The Pattern Hunt" (Critical Thinking + Transfer)
```yaml
scenario: |
  You've learned that hardcoded credentials are bad.
  Now find ALL forms this pattern takes:
  - API keys in strings.xml
  - Database passwords in code
  - Encryption keys in assets
  - OAuth secrets in BuildConfig

  Different surface, same root cause.

discovery_required: |
  What is the UNDERLYING principle that makes all of these vulnerable?

transfer_principle: |
  "Any secret embedded in client-distributed code is not secret."

creativity_space: |
  What other places might secrets be hidden that weren't listed?
```

#### YB-02: "The Novel Target" (Creativity)
```yaml
scenario: |
  You know how to bypass root detection using Frida hooks.
  This app has root detection, but your standard scripts don't work.

  The detection uses a method you haven't seen before.
  Figure out how to bypass it anyway.

authentic_stakes: |
  Real-world bypasses require adaptation, not just script execution.

creativity_required: |
  - What is this detection actually checking?
  - How can I modify my approach for this specific implementation?

failure_teaches: |
  Memorized scripts without understanding are brittle.
  Understanding principles enables adaptation.
```

#### YB-03: "Teach the Pattern" (Communication + Critical Thinking)
```yaml
scenario: |
  Create a teaching module that explains WHY client-side security checks fail.

  Requirements:
  - Must be understandable to someone who hasn't done mobile security
  - Must include concrete examples
  - Must explain the fundamental principle
  - Must enable the learner to recognize this pattern in new contexts

assessment: |
  Test your module on an actual learner. Did they:
  - Understand the principle?
  - Successfully apply it to a new example?
  - Ask good clarifying questions?
```

---

## Orange Belt: Integration and Complexity

**Theme**: "Real Problems Are Messy"

### Competency Focus
- **Creativity**: Handle complexity and ambiguity
- **Critical Thinking**: Navigate conflicting information

### Meaningful Challenges

#### OB-01: "The Real App" (Integration)
```yaml
scenario: |
  Here's an APK from a real (anonymized) application.
  No hints. No guidance. Find what's wrong.

  The app has:
  - Multiple activities
  - Network communication
  - Local storage
  - Third-party libraries
  - Some security measures (not all effective)

authentic_stakes: |
  This is what real security work looks like. Messy. Ambiguous. Complex.

discovery_required: |
  - Where do you even start?
  - How do you prioritize what to investigate?
  - How do you know when you've found something significant?

integration_required:
  - Static analysis
  - Dynamic analysis
  - Network analysis
  - Code review
  - Documentation of findings

failure_teaches: |
  - Starting without a methodology wastes time
  - Missing context leads to false positives/negatives
  - Isolated skills must combine for real analysis
```

#### OB-02: "Conflicting Evidence" (Critical Thinking)
```yaml
scenario: |
  Your static analysis says the app is vulnerable to SQL injection.
  Your dynamic testing can't trigger it.
  The vendor says they've patched it.
  A CVE says it's still vulnerable.

  What is the truth?

authentic_stakes: |
  Tools disagree. Vendors lie. CVEs are often wrong. How do you find truth?

critical_thinking_required: |
  - What does each source actually claim?
  - What evidence supports each claim?
  - What would you need to see to be certain?

resolution: |
  Must produce a justified conclusion with explicit reasoning.
```

#### OB-03: "The Time-Boxed Assessment" (All 4Cs)
```yaml
scenario: |
  You have 4 hours to assess this app.
  At the end, you must deliver:
  - Executive summary (5 sentences max)
  - Technical findings (reproducible)
  - Risk prioritization (with justification)
  - Remediation guidance (actionable)

authentic_stakes: |
  Real assessments have time limits. Perfection is impossible.
  Good judgment about what matters is essential.

competencies_required:
  critical_thinking: "What matters most in limited time?"
  creativity: "How to get maximum coverage efficiently?"
  communication: "How to convey findings clearly under pressure?"
```

---

## Green Belt: Adversarial Thinking

**Theme**: "Think Like the Attacker"

### Competency Focus
- **Creativity**: Novel attack development
- **Critical Thinking**: Anticipate defenses and countermeasures

### Meaningful Challenges

#### GB-01: "Break Your Own Defense" (Creativity + Critical Thinking)
```yaml
scenario: |
  You implemented certificate pinning in an app.
  Now break it.

  Then improve your implementation.
  Then break it again.

authentic_stakes: |
  You can't build secure systems without understanding how they fail.

creativity_required: |
  - What assumptions does your implementation make?
  - How can those assumptions be violated?

iterative_learning: |
  Build → Break → Improve → Break → Improve → ...
```

#### GB-02: "The Defended Target" (Creativity)
```yaml
scenario: |
  This app has:
  - Root detection (3 different methods)
  - SSL pinning (with backup pins)
  - Integrity verification
  - Frida detection
  - Debug detection

  Extract the flag anyway.

authentic_stakes: |
  Defense-in-depth is common. Attackers must be creative.

creativity_required: |
  Standard approaches are blocked. What else is possible?
  - Timing attacks?
  - Race conditions?
  - Overlooked entry points?
  - Novel bypass techniques?

success_metric: |
  Flag extracted. Bonus: method that challenge designer didn't anticipate.
```

#### GB-03: "Red Team Report" (Communication + All 4Cs)
```yaml
scenario: |
  You've compromised an application ecosystem.
  Write the red team report that:
  - Executives will read and act on
  - Developers will use to fix issues
  - Security team will use to improve detection
  - Future red teamers can learn from

authentic_stakes: |
  A penetration test without a good report is worthless.

assessment:
  - Would an executive fund remediation based on this?
  - Could a developer fix the issues without asking questions?
  - Does this advance the organization's security maturity?
```

---

## Blue Belt: Systems Thinking

**Theme**: "Everything Is Connected"

### Competency Focus
- **Collaboration**: Work across boundaries
- **Critical Thinking**: Understand systemic risks

### Meaningful Challenges

#### BB-01: "The Ecosystem Attack" (Collaboration)
```yaml
scenario: |
  Target: A banking ecosystem with 5 apps
  - Main banking app
  - Authentication app
  - Payment app
  - Customer support app
  - Internal admin app

  Each team member analyzes one app.
  The full attack chain requires findings from multiple apps.

authentic_stakes: |
  Real compromises often chain vulnerabilities across systems.

collaboration_required: |
  - Share findings in standardized format
  - Identify cross-app attack paths
  - Coordinate exploitation timing

success_metric: |
  Demonstrate attack chain that requires ≥3 apps.
```

#### BB-02: "Build the Playbook" (Collaboration + Communication)
```yaml
scenario: |
  Create a shared methodology document that:
  - Any team member can follow
  - Produces consistent results
  - Captures collective knowledge
  - Improves over time

  Test it: Give the playbook to someone new. Can they succeed?

authentic_stakes: |
  Scalable security requires shared knowledge, not heroic individuals.
```

---

## Purple Belt: Creation and Teaching

**Theme**: "Those Who Can, Teach"

### Competency Focus
- **Communication**: Teach others effectively
- **Creativity**: Design new challenges

### Meaningful Challenges

#### PB-01: "Design a Meaningful Challenge" (All 4Cs)
```yaml
scenario: |
  Create a challenge for yellow belt students that:
  - Has authentic stakes
  - Requires genuine discovery
  - Allows multiple approaches
  - Enables transfer to new situations
  - Makes failure informative
  - Develops at least 2 competencies

  Then watch someone attempt it. Did it work as designed?

meta_learning: |
  Designing challenges deepens understanding of the domain.
```

#### PB-02: "Mentor Through a Challenge" (Communication + Collaboration)
```yaml
scenario: |
  Guide a green belt through a challenge without giving answers.

  You may:
  - Ask questions
  - Suggest directions to explore
  - Help them recover from failures

  You may not:
  - Give direct answers
  - Do the work for them

assessment: |
  Did the mentee:
  - Succeed?
  - Learn transferable skills?
  - Develop their own problem-solving approach?
```

---

## Brown Belt: Research and Innovation

**Theme**: "Advance the Field"

### Competency Focus
- **Creativity**: Original research
- **Communication**: Publish and share

### Meaningful Challenges

#### BrB-01: "The Novel Technique" (Creativity)
```yaml
scenario: |
  Develop a new technique, tool, or approach that:
  - Solves a problem not well-addressed by existing methods
  - Is documented well enough for others to use
  - Advances the state of the practice

authentic_stakes: |
  The field advances through practitioner innovation.

success_metric: |
  Would this be accepted at a security conference?
  Would other practitioners adopt this?
```

---

## Black Belt: Mastery and Leadership

**Theme**: "Shape the Future"

### Competency Focus
- All 4Cs at mastery level
- Ability to develop others

### Meaningful Challenges

#### BlB-01: "Build the Next Generation" (All 4Cs)
```yaml
scenario: |
  Take responsibility for developing 3 practitioners from white to green belt.

  Design their learning path.
  Create or select their challenges.
  Mentor them through difficulties.
  Assess their readiness for advancement.

success_metric: |
  Did your students develop:
  - Critical thinking habits?
  - Creative problem-solving ability?
  - Collaborative skills?
  - Clear communication?

  Can they solve problems you didn't explicitly teach?
```

---

## Assessment: How Do We Know Learning Happened?

### Not This:
- Quiz scores
- Checkbox completion
- Time spent
- Certificates earned

### But This:
- Can solve novel problems using learned principles
- Can explain reasoning to others who then succeed
- Can identify when approaches won't work and adjust
- Can create challenges that teach others
- Can collaborate to achieve more than individual capability

### The Ultimate Test:
Give the learner a problem they've never seen, in a domain slightly outside their training.

Do they:
1. **Question claims** rather than accept them?
2. **Try creative approaches** when standard ones fail?
3. **Collaborate effectively** when the problem requires it?
4. **Communicate clearly** about what they find?

If yes → Learning happened.
If no → More meaningful challenges needed.
