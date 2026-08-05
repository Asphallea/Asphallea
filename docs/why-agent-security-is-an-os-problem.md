# Why agent security is an OS problem

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

## We are not the first people to notice this

We would rather name the prior art than have you find it. Two projects are doing
serious work adjacent to this, and if you are evaluating Asphallea you should
evaluate them too.

**Anthropic's sandbox runtime** (`srt`) enforces filesystem and network
restrictions on arbitrary processes at the OS level with no container, using
`sandbox-exec` on macOS and `bubblewrap` on Linux plus a filtering proxy for the
network. It is the cleanest expression of the OS-primitives argument this essay
makes, it is open source, and it comes from the team that ships the most widely
used coding agent. If what you need is to wrap one process, or to jail a local MCP
server so it cannot read outside your project, use it. It is good, and the fact
that it exists is the strongest evidence we have that this framing is right.

**agentjail** puts a policy check in front of the tool calls of three specific
coding agents, Claude Code, Codex, and Cursor, with Landlock and Seatbelt behind it
and cost budgets on top. If you want a guardrail around a coding CLI you already
use, install it, and you are done in a minute.

Here is the seam neither of them covers, and it is the one we build for.

Both tools secure an agent that somebody else built. `srt` wraps a process: it
knows a command was run and which files that command touched, but it does not know
what a *tool call* is, so it cannot allow `filesystem.read` and deny
`filesystem.delete` when both are the same server. agentjail knows what a tool call
is, but it knows it for three named CLIs.

Asphallea is for the agent *you* are building. It is a library you put at your own
tool-execution boundary, so the decision happens before the call leaves your
process, on the call's own terms: this tool, these arguments, this argument is a
read path and that one is a write path, denied because of this rule. The same
decision point governs an MCP session and a LangChain tool, and the same JSONL line
records both. Then, for the tool calls that spawn shells or execute code, the OS
containment closes underneath.

Policy at the tool-call boundary, containment underneath it, one audit trail across
both. That is the layer we did not find, so we wrote it.

## Be honest about where it holds

Real containment is not free and it is not uniform. Each operating system has its
own engine, they do not cover the same ground, and pretending otherwise would make
this whole essay worthless.

The policy tier is identical everywhere. Tool allowlist, path allowlists, rate
limits, spend caps, timeouts, and the audit trail behave the same on Linux, macOS,
and Windows, because they are our code and they are deterministic.

The containment tier is where the platform matters. Linux contains with Landlock
for the filesystem allowlist, seccomp-bpf for syscall and network-family filtering,
network namespaces, and setrlimit, applied to the process and everything it spawns.
Windows contains with an AppContainer for the filesystem allowlist and network deny,
inside a Job Object that bounds memory, CPU, and process count and guarantees the
whole process tree dies. macOS contains with a Seatbelt profile that allowlists the
filesystem and denies the network; resource limits there are still to come.

So the coverage is real on all three, and it is not equal. Syscall filtering is
Linux only. Resource limits are not on macOS yet. We report what the running system
can actually enforce, per dimension, and when a policy asks for something the local
backend cannot deliver, the run fails closed instead of proceeding half contained.

An honest "degraded on this platform" is worth more than a green checkmark you
cannot back up. Credibility is the product too.

## Enforce first. Learn later

There is a tempting version of this product that watches the agent, learns what
normal looks like, and flags anomalies. That is a research project, and it is a
research project that fails open. While the model learns, the agent is exposed.

Asphallea does the boring, deterministic thing first. You declare a least-privilege
policy. It enforces that policy on every action, allow or deny, with a full log. No
learning, no scoring, no probability. Enforce mode is the foundation. Everything
smarter is built on top of a floor that already holds.

## Where this goes

v0 is enforce mode: a least-privilege policy and an audit trail around agent
tool-execution, with OS containment underneath the tools that can do the most
damage. That is the floor. It is useful on its own, and it is the honest foundation
for everything after it.

The thesis underneath does not change. The agent is a privileged process. We already
know how to contain privileged processes. Point that knowledge at the new problem
and most of the fear about autonomous agents becomes an engineering detail with a
known answer.
