# Why agent security is an OS problem

A launch essay stub. Founder voice. Draft.

## The short version

An AI agent is a new kind of privileged process. We gave it credentials, a shell,
a browser, and the ability to act on its own. Then we forgot fifty years of work on
how to contain a privileged process. Agent security is not a model-alignment
problem. It is an operating-systems problem. We should treat it like one.

## The agent is a process, and we un-contained it

For fifty years we built containment for programs that act on our behalf. Unix
users and permissions. chroot. Capabilities. Namespaces and cgroups. seccomp.
Landlock. The whole point was blast-radius control. A process should be able to do
its job and nothing else, and when it is compromised the damage should stop at the
edge of what we granted it.

Then agents arrived and we handed them the keys with none of the locks. An agent
runs code, calls tools, reads files, hits APIs, and moves money. It decides what to
do next from text it read a moment ago. And it runs with the full authority of
whatever credentials we handed it. That is a setuid binary that takes instructions
from strangers.

## Prompt injection is privilege escalation

The security community keeps framing prompt injection as a model problem, something
we will filter our way out of. That framing is wrong in a way that matters.

Prompt injection is not the vulnerability. It is the delivery mechanism. The
vulnerability is that a compromised agent can do anything its credentials allow.
The injected text is just the attacker's input. What turns that input into a breach
is the absence of containment around the agent's actions.

Think about it the way we think about a web server. We assume the request is
hostile. We do not try to make the parser perfect. We drop privileges, we sandbox,
we limit what the process can touch, so that a bad request cannot become a bad day.
Agents deserve the same assumption. The prompt is hostile. Plan for it at the action
layer, not the token layer.

## Guardrails judge text. Containment limits action

Content filters and injection classifiers work on what the model says. They are a
probabilistic layer on an input that the attacker fully controls. Useful, maybe,
as one layer. But they do not contain anything. A guardrail that is 99 percent
effective is a lock that opens one time in a hundred, and the attacker gets to knock
as many times as they like.

Containment is different in kind. It does not care what the model said or why. It
enforces, deterministically, that the tool cannot read the file, cannot open the
socket, cannot delete the directory, because the policy did not grant it. A hijacked
agent under a least-privilege policy can only do what the policy allows. The exploit
still fires. The blast radius is a rounding error.

This is the difference between trying to predict the attack and refusing to be
harmed by it.

## What least privilege looks like for an agent

Take the primitives we already trust for processes and put them around the agent's
tool calls.

- **An allowlist of tools.** The agent calls the tools it needs. Everything else is
  denied by default.
- **A filesystem allowlist.** The agent reads its workspace and writes its output
  directory. It cannot read your SSH key or your environment secrets, because those
  are not on the list. On Linux this is Landlock, enforced by the kernel, not a
  string check.
- **Network deny by default.** No socket unless the policy says so. Exfiltration
  needs a channel. Take the channel away.
- **Resource limits.** CPU, memory, process count, file size. A runaway or malicious
  command hits a wall.
- **A complete audit trail.** Every action, every decision, the rule that fired.
  When something goes wrong you can see exactly what the agent did and what it was
  stopped from doing.

None of this is novel. That is the point. The operating system has offered these
controls for years. The work is to wire them to the place where an agent actually
acts, which is the tool-execution boundary, and to make that wiring take five
minutes for a developer to adopt.

## Enforce first. Learn later

There is a tempting version of this product that watches the agent, learns what
normal looks like, and flags anomalies. That is a research project, and it is a
research project that fails open. While the model learns, the agent is exposed.

Asphallea does the boring, deterministic thing first. You declare a least-privilege
policy. It enforces that policy on every action, allow or deny, with a full log. No
learning, no scoring, no probability. Enforce mode is the foundation. Everything
smarter is built on top of a floor that already holds.

## Be honest about where it holds

Real containment is not free and it is not uniform. Landlock needs a recent Linux
kernel. seccomp is Linux. Network namespaces need specific support. On macOS and
Windows the policy tier still enforces the tool allowlist, the path allowlist, the
rate and spend limits, and the timeouts, but the OS-level containment of spawned
processes is not there.

So we say so. Asphallea detects what the running kernel can actually enforce and
tells you. When it cannot contain, it refuses to pretend, and by default it fails
closed rather than run a dangerous command exposed. An honest "degraded on this
platform" is worth more than a green checkmark you cannot back up. Credibility is
the product too.

## Where this goes

v0 is enforce mode: a least-privilege policy and an audit trail around agent
tool-execution, with real OS containment on Linux for the tools that can do the most
damage. That is the floor. It is useful on its own, and it is the honest foundation
for everything after it.

The thesis underneath does not change. The agent is a privileged process. We already
know how to contain privileged processes. Point that knowledge at the new problem
and most of the fear about autonomous agents becomes an engineering detail with a
known answer.
