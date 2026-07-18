"""Framework adapters over the framework-neutral :func:`asphallea.guard` core.

The generic callable wrapper in :mod:`asphallea.guard` is the foundation. These
adapters are thin shims that map a specific framework's tool object onto it.

Every adapter funnels into the one decision choke point,
:meth:`asphallea.intercept.Interceptor.decide`, so a tool-call is decided and
recorded by the same code no matter which surface it arrives on.

Available now:

* :mod:`asphallea.integrations.mcp` for MCP tool-calls, client or server side.
* :mod:`asphallea.integrations.langchain` for LangChain and LangGraph tools.

Fast-follow (not built in v0): OpenAI and Anthropic tool-calling adapters.
"""
