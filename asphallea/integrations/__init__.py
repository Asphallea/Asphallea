"""Framework adapters over the framework-neutral :func:`asphallea.guard` core.

The generic callable wrapper in :mod:`asphallea.guard` is the foundation. These
adapters are thin shims that map a specific framework's tool object onto it.

Available now:

* :mod:`asphallea.integrations.langchain` for LangChain and LangGraph tools.

Fast-follow (not built in v0): OpenAI and Anthropic tool-calling adapters.
"""
