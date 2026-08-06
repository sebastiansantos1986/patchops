# ADR 0001: Begin with a modular monolith

Status: Accepted

PatchOps will start with one web console, one modular control-plane service, one worker boundary, and a shared Go agent with platform adapters. A small team needs transactional clarity and fast product iteration more than independently deployed services. Modules will expose stable contracts so the job scheduler, catalog, or reporting service can be separated later when security or scale justifies it.
